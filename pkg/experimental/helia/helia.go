// Copyright 2020 ETH Zurich
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
	"hash"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
)

const (
	// AuthLen denotes the size of the authenticator in bytes
	AuthLen = 16
	// MaxPacketLifetime denotes the maximal lifetime of a packet
	MaxPacketLifetime time.Duration = 2 * time.Second
	// MaxClockSkew denotes the maximal clock skew
	MaxClockSkew time.Duration = time.Second
	// TimestampResolution denotes the resolution of the epic timestamp
	TimestampResolution = 21 * time.Microsecond
	// MACBufferSize denotes the buffer size of the CBC input and output.
	MACBufferSize = 16
)

type ReservationRequest struct {
	Target    addr.IA
	IngressIF uint16
	EgressIF  uint16
	Backward  bool
	Timestamp uint64
	Counter   uint32
}

var zeroInitVector [16]byte

func CreateSetupRequest(mac hash.Hash, reservReq *ReservationRequest) *slayers.HopByHopOption {
	var auth [16]byte
	reqParams := slayers.PacketReservReqParams{
		TargetAS:  reservReq.Target,
		Timestamp: reservReq.Timestamp,
		Counter:   reservReq.Counter,
		Auth:      auth,
	}
	var optType slayers.OptionType
	if !reservReq.Backward {
		optType = slayers.OptTypeReservReqForward
	} else {
		optType = slayers.OptTypeReservReqBackward
	}
	CalcMac(mac, reqParams, reservReq.IngressIF, reservReq.EgressIF, uint8(optType))
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

// CreateTimestamp returns the epic timestamp, which encodes the current time (now) relative to the
// input timestamp. The input timestamp must not be in the future (compared to the current time),
// otherwise an error is returned. An error is also returned if the current time is more than 1 day
// and 63 minutes after the input timestamp.
func CreateTimestamp(input time.Time, now time.Time) (uint32, error) {
	if input.After(now) {
		return 0, serrors.New("provided input timestamp is in the future",
			"input", input, "now", now)
	}
	epicTS := now.Sub(input)/TimestampResolution - 1
	if epicTS < 0 {
		epicTS = 0
	}
	if epicTS >= (1 << 32) {
		return 0, serrors.New("diff between input and now >1d63min", "epicTS", epicTS)
	}
	return uint32(epicTS), nil
}

// VerifyTimestamp checks whether an EPIC packet is fresh. This means that the time the packet
// was sent from the source host, which is encoded by the timestamp and the epicTimestamp,
// does not date back more than the maximal packet lifetime of two seconds. The function also takes
// a possible clock drift between the packet source and the verifier of up to one second into
// account.
func VerifyTimestamp(timestamp time.Time, epicTS uint32, now time.Time) error {
	diff := (time.Duration(epicTS) + 1) * TimestampResolution
	tsSender := timestamp.Add(diff)

	if tsSender.After(now.Add(MaxClockSkew)) {
		delta := tsSender.Sub(now.Add(MaxClockSkew))
		return serrors.New("epic timestamp is in the future",
			"delta", delta)
	}
	if now.After(tsSender.Add(MaxPacketLifetime).Add(MaxClockSkew)) {
		delta := now.Sub(tsSender.Add(MaxPacketLifetime).Add(MaxClockSkew))
		return serrors.New("epic timestamp expired",
			"delta", delta)
	}
	return nil
}

// CalcMac derives the EPIC MAC (PHVF/LHVF) given the full 16 bytes of the SCION path type
// MAC (auth), the EPIC packet ID (pktID), the timestamp in the Info Field (timestamp),
// and the SCION common/address header (s).
// If the same buffer is provided in subsequent calls to this function, the previously returned
// EPIC MAC may get overwritten. Only the most recently returned EPIC MAC is guaranteed to be
// valid.
func CalcMac(h hash.Hash,
	reqParams slayers.PacketReservReqParams, ingressIF uint16, egressIF uint16, optType uint8,
) ([]byte, error) {

	// Prepare the input for the MAC function
	prepareMacInput(
		reqParams.Counter, ingressIF, egressIF, reqParams.Timestamp, optType, reqParams.Auth,
	)
	if _, err := h.Write(reqParams.Auth[:]); err != nil {
		return nil, err
	}
	return h.Sum(reqParams.Auth[:0])[:16], nil

}

// VerifyHVF verifies the correctness of the HVF (PHVF or the LHVF) field in the EPIC packet by
// recalculating and comparing it. If the EPIC authenticator (auth), which denotes the full 16
// bytes of the SCION path type MAC, has invalid length, or if the MAC calculation gives an error,
// also VerifyHVF returns an error. The verification was successful if and only if VerifyHVF
// returns nil.
//func VerifyHVF(auth []byte, pktID epic.PktID, s *slayers.SCION,
//	timestamp uint32, hvf []byte, buffer []byte) error {
//
//	if s == nil || len(auth) != AuthLen {
//		return serrors.New("invalid input")
//	}
//
//	mac, err := CalcMac(auth, pktID, s, timestamp, buffer)
//	if err != nil {
//		return err
//	}
//
//	if subtle.ConstantTimeCompare(hvf, mac) == 0 {
//		return serrors.New("epic hop validation field verification failed",
//			"hvf in packet", hvf, "calculated mac", mac, "auth", auth)
//	}
//	return nil
//}

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

// prepareMacInput returns the MAC input data block with the following layout:
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
func prepareMacInput(counter uint32, ingressIF uint16, egressIF uint16, timestamp uint64,
	optType uint8, inputBuffer [16]byte) {

	// Fill input
	offset := 0
	binary.BigEndian.PutUint32(inputBuffer[offset:], counter)
	offset += 4
	binary.BigEndian.PutUint16(inputBuffer[offset:], ingressIF)
	offset += 2
	binary.BigEndian.PutUint16(inputBuffer[offset:], egressIF)
	offset += 2
	binary.BigEndian.PutUint16(inputBuffer[offset:], uint16(timestamp>>32))
	binary.BigEndian.PutUint32(inputBuffer[offset+2:], uint32(timestamp))
	offset += 6
	inputBuffer[offset] = optType
	offset += 1
	inputBuffer[offset] = 0
}
