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

// This file includes the SPAO header implementation as specified
// in https://scion.docs.anapaya.net/en/latest/protocols/authenticator-option.html

// The Authenticator option format is as follows
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  NextHdr=200  |    ExtLen=6   |  OptType=3/4  | OptDataLen=24 |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                Target AS Identifier: targetIA                 +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                       Timestamp: tsReq                        +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           Counter: cnt        |                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
// |                     MAC(tsReq,cnt): auth                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+:

package slayers

import (
	"encoding/binary"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"time"
)

// MinPacketAuthDataLen is the minimum size of the SPAO OptData.
// The SPAO header contains the following fixed-length fields:
// SPI (4 Bytes), Algorithm (1 Byte), Timestamp (3 Bytes),

// PacketCounter is used for duplicate suppression and consists of a Core id and a PerCoreCount
type PacketCounter uint16

// PktCounterFromCore creates a counter for the packet identifier
// based on the core ID and the core counter.
func PktCounterFromCore(coreID uint8, coreCounter uint8) PacketCounter {
	return PacketCounter(uint16(coreID)<<8 | uint16(coreCounter))
}

// CoreFromPktCounter reads the core ID and the core counter
// from a counter belonging to a packet identifier.
func CoreFromPktCounter(counter PacketCounter) (uint8, uint8) {
	coreID := uint8(counter >> 8)
	coreCounter := uint8(counter & 0x00FF)
	return coreID, coreCounter
}

type PacketReservReqParams struct {
	Target    addr.IA
	Timestamp int64
	Counter   PacketCounter
	Auth      []byte
}

type PacketReservResponseParams struct {
	ReservAS  addr.IA
	AuthEnc   []byte
	bandwidth uint32
	TsExp     int64
	IngressIF uint16
	EgressIF  uint16
	Tag       []byte
}

// PacketReservReqForwardOption wraps a HopByHopOption of OptTypeReservReqForward.
// This can be used to serialize and parse the internal structure of the reservation request forward
// option.
type PacketReservReqForwardOption struct {
	*HopByHopOption
}

type PacketReservReqBackwardOption struct {
	*HopByHopOption
}

// NewPacketReservReqForwardOption creates a new HopByHopOption of
// OptTypeReservReqForward, initialized with the given PacketReservReqParams.
func NewPacketReservReqForwardOption(
	p PacketReservReqParams,
) (PacketReservReqForwardOption, error) {

	o := PacketReservReqForwardOption{HopByHopOption: new(HopByHopOption)}
	err := o.Reset(p)
	return o, err
}

// ParsePacketReservReqForwardOption parses o as a packet reservation request forward option.
func ParsePacketReservReqForwardOption(o *HopByHopOption) (PacketReservReqForwardOption, error) {
	if o.OptType != OptTypeReservReqForward {
		return PacketReservReqForwardOption{},
			serrors.New("wrong option type", "expected", OptTypeReservReqForward, "actual", o.OptType)
	}
	return PacketReservReqForwardOption{o}, nil
}

// Reset reinitializes the underlying HopByHopOption with the give PacketReservReqParams.
func (o PacketReservReqForwardOption) Reset(
	p PacketReservReqParams,
) error {

	o.OptType = OptTypeReservReqForward

	binary.BigEndian.PutUint64(o.OptData[:8], uint64(p.Target))
	binary.BigEndian.PutUint64(o.OptData[8:16], uint64(p.Timestamp))
	binary.BigEndian.PutUint16(o.OptData[16:18], uint16(p.Counter))
	copy(o.OptData[18:], p.Auth)

	o.OptAlign = [2]uint8{4, 2}
	// reset unused/implicit fields
	o.OptDataLen = 0
	o.ActualLength = 0
	return nil
}

// Target returns the IA address value set in the extension
func (o PacketReservReqForwardOption) Target() addr.IA {
	return addr.IA(binary.BigEndian.Uint64(o.OptData[:8]))
}

func (o PacketReservReqForwardOption) Timestamp() uint64 {
	return binary.BigEndian.Uint64(o.OptData[8:16])
}

func (o PacketReservReqForwardOption) PacketCounter() PacketCounter {
	return PacketCounter(binary.BigEndian.Uint64(o.OptData[16:18]))
}

// Auth returns slice of the underlying auth buffer.
// Changes to this slice will be reflected on the wire when
// the extension is serialized.
func (o PacketReservReqForwardOption) Auth() []byte {
	return o.OptData[18:]
}

func CreateSetupRequest(target addr.IA, isBackwardReq bool) *HopByHopOption {
	tsReq := time.Now().UnixNano()
	counter := PktCounterFromCore(1, 2)
	auth := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	optSetup, err := NewPacketReservReqForwardOption(
		PacketReservReqParams{
			Target:    target,
			Timestamp: tsReq,
			Counter:   counter,
			Auth:      auth,
		})
	if err != nil {
		return nil
	}
	return optSetup.HopByHopOption
}
