// Copyright 2020 Anapaya Systems
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

package helia

import (
	"encoding/binary"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
	"time"
)

// Size computes the full SCION packet size for an address pair with a given
// payload size.
func Size(local, remote *snet.UDPAddr, pldSize int) (int, error) {
	pkt, err := pack(local, remote, snet.SCMPEchoRequest{Payload: make([]byte, pldSize)})
	if err != nil {
		return 0, err
	}
	if err := pkt.Serialize(); err != nil {
		return 0, err
	}
	return len(pkt.Bytes), nil
}

func pack(local, remote *snet.UDPAddr, req snet.SCMPEchoRequest) (*snet.Packet, error) {
	_, isEmpty := remote.Path.(path.Empty)
	if isEmpty && !local.IA.Equal(remote.IA) {
		return nil, serrors.New("no path for remote ISD-AS", "local", local.IA, "remote", remote.IA)
	}
	target, _ := addr.ParseIA("2-ff00:0:210")
	heliaSetupOpt := createSetupRequest(target, false)
	pkt := &snet.Packet{
		PacketInfo: snet.PacketInfo{
			Destination: snet.SCIONAddress{
				IA:   remote.IA,
				Host: addr.HostFromIP(remote.Host.IP),
			},
			Source: snet.SCIONAddress{
				IA:   local.IA,
				Host: addr.HostFromIP(local.Host.IP),
			},
			Path:           remote.Path,
			Payload:        req,
			HopByHopOption: heliaSetupOpt,
		},
	}
	return pkt, nil
}

func createSetupRequest(target addr.IA, isBackwardReq bool) *slayers.HopByHopOption {
	counter := slayers.PktCounterFromCore(1, 1, 2)
	auth := [16]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	var tsReq [6]byte
	binary.BigEndian.PutUint32(tsReq[:], uint32(time.Now().UnixMilli()))
	optSetup, err := slayers.NewPacketReservReqForwardOption(
		slayers.PacketReservReqParams{
			TargetAS:  target,
			Timestamp: tsReq,
			Counter:   counter,
			Auth:      auth,
		})
	if err != nil {
		return nil
	}
	return optSetup.HopByHopOption
}
