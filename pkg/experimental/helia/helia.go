// Copyright 2023 ETH Zurich
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
	"crypto/subtle"
	"encoding/binary"
	"hash"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
)

const (
	MACBufferSize = 16
	// ReservationBandwidth is a fixed bandwidth, only during testing
	ReservationBandwidth = 1000
	// ReservationDuration is the fixed duration for reservations
	ReservationDuration = 10 * time.Second
)

func TESTING_KEY() []byte {
	return []byte("dabbadoodabbadoo")
}

type ReservationRequest struct {
	Target    addr.IA
	Counter   uint32
	IngressIF uint16
	EgressIF  uint16
	Timestamp uint64
	Backward  bool
}

type ReservationResponse struct {
	ReservAS      addr.IA
	Authenticator []byte
	Bandwidth     uint32
	TsExp         uint64
	IngressIF     uint16
	EgressIF      uint16
}

func CreateSetupRequest(
	h hash.Hash, reservReq *ReservationRequest, buffer []byte,
) *slayers.HopByHopOption {
	var auth [16]byte
	reqParams := slayers.PacketReservReqParams{
		TargetAS:  reservReq.Target,
		Timestamp: reservReq.Timestamp,
		Counter:   reservReq.Counter,
		Auth:      auth,
	}

	mac := CalcRequestMAC(h, reservReq, buffer)
	copy(reqParams.Auth[:], mac[:16])
	if !reservReq.Backward {
		optSetup, err := slayers.NewPacketReservReqForwardOption(reqParams)
		if err != nil {
			return nil
		}
		return optSetup.HopByHopOption
	} else {
		optSetup, err := slayers.NewPacketReservReqBackwardOption(reqParams)
		if err != nil {
			return nil
		}
		return optSetup.HopByHopOption
	}
}

func CreateSetupResponse(
	h hash.Hash, reservResp *ReservationResponse, buffer []byte,
) (*slayers.HopByHopOption, error) {
	// TODO: Protect with AEAD

	params := slayers.PacketReservResponseParams{
		ReservAS:  reservResp.ReservAS,
		Bandwidth: reservResp.Bandwidth,
		TsExp:     reservResp.TsExp,
		IngressIF: reservResp.IngressIF,
		EgressIF:  reservResp.EgressIF,
	}
	setupResp, err := slayers.NewPacketReservResponseOption(params)
	if err != nil {
		return nil, err
	}
	return setupResp.HopByHopOption, nil
}

// CalcRequestMAC derives the EPIC MAC (PHVF/LHVF) given the full 16 bytes of the SCION path type
// MAC (auth), the EPIC packet ID (pktID), the timestamp in the Info Field (timestamp),
// and the SCION common/address header (s).
// If the same buffer is provided in subsequent calls to this function, the previously returned
// EPIC MAC may get overwritten. Only the most recently returned EPIC MAC is guaranteed to be
// valid.
func CalcRequestMAC(
	h hash.Hash, reservReq *ReservationRequest, buffer []byte,
) []byte {
	if len(buffer) < MACBufferSize {
		buffer = make([]byte, MACBufferSize)
	}

	var optType slayers.OptionType
	if !reservReq.Backward {
		optType = slayers.OptTypeReservReqForward
	} else {
		optType = slayers.OptTypeReservReqBackward
	}

	// Prepare the input for the MAC function
	requestMACInput(
		reservReq.Counter, reservReq.IngressIF, reservReq.EgressIF, reservReq.Timestamp,
		uint8(optType), buffer,
	)
	h.Reset()
	if _, err := h.Write(buffer); err != nil {
		panic(err)
	}
	return h.Sum(buffer)[:16]

}

// VerifyRequestMAC verifies the correctness of the request packets MAC field by recomputing and
// comparing it. The verification was successful if and only if VerifyRequestMAC returns nil
func VerifyRequestMAC(h hash.Hash, reservReq *ReservationRequest, mac []byte, buffer []byte) error {
	if len(buffer) < MACBufferSize {
		buffer = make([]byte, MACBufferSize)
	}
	recomputedMac := CalcRequestMAC(h, reservReq, buffer)
	if subtle.ConstantTimeCompare(recomputedMac, mac) == 0 {
		return serrors.New(
			"Request MAC authentication failed",
			"MAC in packet", mac, "calculated MAC", recomputedMac,
		)
	}
	return nil
}

// PktCounterFromCore creates a counter for the packet identifier
// based on the client ID, core ID and the core counter.
func PktCounterFromCore(clientID uint8, coreID uint8, coreCounter uint16) uint32 {
	return uint32(clientID)<<24 | uint32(coreID)<<16 | uint32(coreCounter)
}

// CoreFromPktCounter reads the client ID, core ID and the core counter
// from a counter belonging to a packet identifier.
func CoreFromPktCounter(counter uint32) (uint8, uint8, uint16) {
	clientID := uint8(counter >> 24)
	coreID := uint8(counter >> 16)
	coreCounter := uint16(counter)
	return clientID, coreID, coreCounter
}

// requestMACInput returns the MAC input data block with the following layout:
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                          counter (4B)                         |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|          ingressIF (2B)       |         egressIF (2B)         |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                         timestamp (6B)                        |
//	+                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                               | OptType (1B)  |       0       |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func requestMACInput(
	counter uint32, ingressIF uint16, egressIF uint16, timestamp uint64,
	optType uint8, buffer []byte,
) {

	// Fill input
	offset := 0
	binary.BigEndian.PutUint32(buffer[offset:], counter)
	offset += 4
	binary.BigEndian.PutUint16(buffer[offset:], ingressIF)
	offset += 2
	binary.BigEndian.PutUint16(buffer[offset:], egressIF)
	offset += 2
	binary.BigEndian.PutUint16(buffer[offset:], uint16(timestamp>>32))
	binary.BigEndian.PutUint32(buffer[offset+2:], uint32(timestamp))
	offset += 6
	buffer[offset] = optType
	offset += 1
	buffer[offset] = 0
}
