// Copyright 2022 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package processing

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/google/gopacket"

	"github.com/scionproto/scion/heliagate/storage"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/app/path"
)

type dataPacket struct {
	pktArrivalTime time.Time
	scionLayer     *slayers.SCION
	scionPath      *scion.Raw
	fingerprint    storage.RawPathFingerprint
	rawPacket      []byte
}

// Parse takes a raw packet and parses its scion layer and calculates the raw path fingerprint
func Parse(rawPacket []byte) (*dataPacket, error) {
	proc := dataPacket{
		rawPacket:  make([]byte, len(rawPacket)),
		scionLayer: &slayers.SCION{},
	}
	copy(proc.rawPacket, rawPacket)
	if err := proc.scionLayer.DecodeFromBytes(
		proc.rawPacket, gopacket.NilDecodeFeedback,
	); err != nil {
		return nil, err
	}
	var ok bool
	proc.scionPath, ok = proc.scionLayer.Path.(*scion.Raw)
	if !ok {
		return nil, serrors.New("Getting scion path failed")
	}
	proc.fingerprint = storage.CalculateRawPathFingerprint(proc.scionPath)
	return &proc, nil
}

// getHopsFromPacket parses the interfaces of the packet and requests a matching path from the
// scion daemon. It then returns a list of AS hops from this path
func getHopsFromPacket(
	d *dataPacket, sd daemon.Connector, ctx context.Context,
) (snet.Path, []storage.Hop, error) {
	decoded, err := d.scionPath.ToDecoded()
	if err != nil {
		return nil, nil, err
	}
	sequence, n := ifsSequenceFromDecoded(decoded)

	opts := []path.Option{
		path.WithSequence(sequence),
	}
	path, err := path.Choose(ctx, sd, d.scionLayer.DstIA, opts...)
	if err != nil {
		log.Error("Path not found", "error", err)
		return nil, nil, err
	}
	hops := make([]storage.Hop, n)
	ifs := path.Metadata().Interfaces
	// The first and last hop only have one interface in the list
	hops[0] = storage.Hop{
		IA:      ifs[0].IA,
		Ingress: 0,
		Egress:  uint16(ifs[0].ID),
	}
	for i := 1; i < n-1; i++ {
		hops[i] = storage.Hop{
			IA:      ifs[i*2-1].IA,
			Ingress: uint16(ifs[i*2-1].ID),
			Egress:  uint16(ifs[i*2].ID),
		}
	}
	hops[n-1] = storage.Hop{
		IA:      ifs[(n-1)*2-1].IA,
		Ingress: uint16(ifs[(n-1)*2-1].ID),
		Egress:  0,
	}
	log.Debug("Heliagate: Reconstructed ASes from path", "hops", hops)
	return path, hops, nil
}

// ifsSequenceFromDecoded looks up the hop and info fields in a decoded SCION path and constructs
// a sequence of ingress and egress interfaces, while taking into account switchovers. The output
// string can directly be used to query the SCION daemon for compatible paths.
func ifsSequenceFromDecoded(decoded *scion.Decoded) (string, int) {
	sequence := ""
	n := 0
	currSeg := 0
	lastHopInSeg := int(decoded.PathMeta.SegLen[currSeg]) - 1
	consDir := decoded.InfoFields[currSeg].ConsDir
	for i := 0; i < decoded.NumHops; i++ {
		hf := decoded.HopFields[i]
		inIF := hf.ConsIngress
		outIF := hf.ConsEgress
		if !consDir {
			inIF, outIF = outIF, inIF
		}
		// process switchover when reaching end of segment, if this is not the last segment
		if i == lastHopInSeg && currSeg < 2 {
			nNextSeg := int(decoded.PathMeta.SegLen[currSeg+1])

			if nNextSeg > 0 {
				// if the next segment is not empty, take lookup the egress interface in the next HF
				currSeg++
				lastHopInSeg += nNextSeg
				consDir = decoded.InfoFields[currSeg].ConsDir

				i++
				hf := decoded.HopFields[i]
				if consDir {
					outIF = hf.ConsEgress
				} else {
					outIF = hf.ConsIngress
				}
			}
		}
		n++
		sequence += fmt.Sprintf("0-0#%d,%d ", inIF, outIF)
	}
	return sequence, n
}

// packTrafficPacket take a reservation traffic option and serializes it into a HBH extension.
// This extension is then inserted into the raw packet between the SCION header and the payload.
func packTrafficPacket(
	trafficOpt slayers.PacketReservTrafficOption, reservFields []slayers.ReservationField,
	d *dataPacket,
) error {

	// Prepare HBH extension and serialize it to a buffer
	hbh := &slayers.HopByHopExtn{}
	hbh.NextHdr = d.scionLayer.NextHdr
	hbh.Options = []*slayers.HopByHopOption{trafficOpt.HopByHopOption}
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: false,
		FixLengths:       true,
	}
	if err := hbh.SerializeTo(buffer, options); err != nil {
		return err
	}

	// Change scionLayer NextHdr to HBH extension
	d.rawPacket[4] = uint8(slayers.HopByHopClass)
	// Lookup length of serialized extension and previous payload length
	extLen := uint8(len(buffer.Bytes()))
	pktLen := d.scionLayer.PayloadLen
	// Update payloadLen to include length of new extension
	binary.BigEndian.PutUint16(d.rawPacket[6:8], pktLen+uint16(extLen))
	// Calculate scion header length, and insert the HBH buffer at that offset
	offset := d.scionLayer.HdrLen * 4
	// Extend packet buffer by temporarily appending the extension buffer
	d.rawPacket = append(d.rawPacket, buffer.Bytes()...)
	// Shift payload to end of packet buffer
	d.rawPacket = append(
		d.rawPacket[:offset+extLen], d.rawPacket[offset:uint16(offset)+pktLen]...,
	)
	// Insert HBH extension between header and payload
	copy(d.rawPacket[offset:offset+extLen], buffer.Bytes())
	return nil
}
