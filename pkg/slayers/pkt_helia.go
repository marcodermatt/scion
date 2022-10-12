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

// This file includes the Helia header implementation

// Reservation request options format:
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  NextHdr=200  |    ExtLen=9   |  OptType=3/4  | OptDataLen=34 |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                Target AS Identifier: targetIA                 +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Counter: cnt                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                                                               +
// |                                                               |
// +                             MAC                               +
// |                                                               |
// +                                                               +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +          Timestamp: tsReq     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
// |                               |   OptType=1   |       0       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//
// Reservation response options format
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  NextHdr=200  |   ExtLen=14   |   OptType=5   | OptDataLen=56 |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                AS Identifier: reservationIA                   +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                                                               +
// |                                                               |
// +              Encrypted Authenticator: authEnc                 +
// |                                                               |
// +                                                               +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Bandwidth: b                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                  Expiration Timestamp: tsExp                  +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Ingress Interface: ingressIF  |  Egress Interface: egressIF   |                                                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                                                               +
// |                                                               |
// +                         AEAD Tag: tag                         +
// |                                                               |
// +                                                               +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

package slayers

import (
	"encoding/binary"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
)

// PacketSetupReqDataLen is the fixed size of the Helia request OptData.
const PacketSetupReqDataLen = 34
const PacketSetupResponseDataLen = 56

// PacketCounter is used for duplicate suppression and consists of a Core id and a PerCoreCount
type PacketCounter uint32

// PktCounterFromCore creates a counter for the packet identifier
// based on the client ID, core ID and the core counter.
func PktCounterFromCore(clientID uint8, coreID uint8, coreCounter uint16) PacketCounter {
	return PacketCounter(uint32(clientID)<<24 | uint32(coreID)<<16 | uint32(coreCounter))
}

// CoreFromPktCounter reads the client ID, core ID and the core counter
// from a counter belonging to a packet identifier.
func CoreFromPktCounter(counter PacketCounter) (uint8, uint8, uint16) {
	clientID := uint8(counter >> 24)
	coreID := uint8(counter >> 16)
	coreCounter := uint16(counter)
	return clientID, coreID, coreCounter
}

type PacketReservReqParams struct {
	TargetAS  addr.IA
	Counter   PacketCounter
	Auth      [16]byte
	Timestamp [6]byte
}

type PacketReservResponseParams struct {
	ReservAS  addr.IA
	AuthEnc   [16]byte
	Bandwidth uint32
	TsExp     uint64
	IngressIF uint16
	EgressIF  uint16
	Tag       [16]byte
}

// PacketReservReqOptions and PacketReservRespOption wrap a HopByHopOption of OptTypeReservReqForward.
// This can be used to serialize and parse the internal structure of the reservation option.
type PacketReservReqForwardOption struct {
	*HopByHopOption
}

type PacketReservReqBackwardOption struct {
	*HopByHopOption
}

type PacketReservResponseOption struct {
	*HopByHopOption
}

// NewPacketReservOptions creates a new HopByHopOption of
// the specified type, initialized with the given PacketParams.
func NewPacketReservReqForwardOption(
	p PacketReservReqParams,
) (PacketReservReqForwardOption, error) {

	o := PacketReservReqForwardOption{HopByHopOption: new(HopByHopOption)}
	err := o.Reset(p)
	return o, err
}

func NewPacketReservReqBackwardOption(
	p PacketReservReqParams,
) (PacketReservReqBackwardOption, error) {

	o := PacketReservReqBackwardOption{HopByHopOption: new(HopByHopOption)}
	err := o.Reset(p)
	return o, err
}

func NewPacketReservResponseOption(
	p PacketReservResponseParams,
) (PacketReservResponseOption, error) {

	o := PacketReservResponseOption{HopByHopOption: new(HopByHopOption)}
	err := o.Reset(p)
	return o, err
}

// ParsePacketReservOption parses o as the specified option.
func ParsePacketReservReqForwardOption(o *HopByHopOption) (PacketReservReqForwardOption, error) {
	if o.OptType != OptTypeReservReqForward {
		return PacketReservReqForwardOption{},
			serrors.New("wrong option type", "expected", OptTypeReservReqForward, "actual", o.OptType)
	}
	return PacketReservReqForwardOption{o}, nil
}

func ParsePacketReservReqBackwardOption(o *HopByHopOption) (PacketReservReqBackwardOption, error) {
	if o.OptType != OptTypeReservReqBackward {
		return PacketReservReqBackwardOption{},
			serrors.New("wrong option type", "expected", OptTypeReservReqBackward, "actual", o.OptType)
	}
	return PacketReservReqBackwardOption{o}, nil
}

func ParsePacketReservResponseOption(o *HopByHopOption) (PacketReservResponseOption, error) {
	if o.OptType != OptTypeReservResponse {
		return PacketReservResponseOption{},
			serrors.New("wrong option type", "expected", OptTypeReservResponse, "actual", o.OptType)
	}
	return PacketReservResponseOption{o}, nil
}

// Reset reinitializes the underlying HopByHopOption with the give PacketParams.
func (o PacketReservReqForwardOption) Reset(
	p PacketReservReqParams,
) error {

	o.OptType = OptTypeReservReqForward

	if PacketSetupReqDataLen <= cap(o.OptData) {
		o.OptData = o.OptData[:PacketSetupReqDataLen]
	} else {
		o.OptData = make([]byte, PacketSetupReqDataLen)
	}
	binary.BigEndian.PutUint64(o.OptData[:8], uint64(p.TargetAS))
	binary.BigEndian.PutUint32(o.OptData[8:12], uint32(p.Counter))
	copy(o.OptData[12:28], p.Auth[:])
	copy(o.OptData[28:34], p.Timestamp[:])

	o.OptAlign = [2]uint8{4, 2}
	// reset unused/implicit fields
	o.OptDataLen = 0
	o.ActualLength = 0
	return nil
}

func (o PacketReservReqBackwardOption) Reset(
	p PacketReservReqParams,
) error {

	o.OptType = OptTypeReservReqBackward

	if PacketSetupReqDataLen <= cap(o.OptData) {
		o.OptData = o.OptData[:PacketSetupReqDataLen]
	} else {
		o.OptData = make([]byte, PacketSetupReqDataLen)
	}
	binary.BigEndian.PutUint64(o.OptData[:8], uint64(p.TargetAS))
	binary.BigEndian.PutUint32(o.OptData[8:12], uint32(p.Counter))
	copy(o.OptData[12:28], p.Auth[:])
	copy(o.OptData[28:34], p.Timestamp[:])

	o.OptAlign = [2]uint8{4, 2}
	// reset unused/implicit fields
	o.OptDataLen = 0
	o.ActualLength = 0
	return nil
}

func (o PacketReservResponseOption) Reset(
	p PacketReservResponseParams,
) error {

	o.OptType = OptTypeReservResponse

	if PacketSetupResponseDataLen <= cap(o.OptData) {
		o.OptData = o.OptData[:PacketSetupResponseDataLen]
	} else {
		o.OptData = make([]byte, PacketSetupResponseDataLen)
	}
	binary.BigEndian.PutUint64(o.OptData[:8], uint64(p.ReservAS))
	copy(o.OptData[8:24], p.AuthEnc[:])
	binary.BigEndian.PutUint32(o.OptData[24:28], p.Bandwidth)
	binary.BigEndian.PutUint64(o.OptData[28:36], p.TsExp)
	binary.BigEndian.PutUint16(o.OptData[36:38], p.IngressIF)
	binary.BigEndian.PutUint16(o.OptData[38:40], p.EgressIF)
	copy(o.OptData[40:56], p.Tag[:])

	o.OptAlign = [2]uint8{4, 2}
	// reset unused/implicit fields
	o.OptDataLen = 0
	o.ActualLength = 0
	return nil
}

// RequestOption field accessors

// TargetAS returns the IA address value set in the option
func (o PacketReservReqForwardOption) TargetAS() addr.IA {
	return addr.IA(binary.BigEndian.Uint64(o.OptData[:8]))
}

func (o PacketReservReqBackwardOption) TargetAS() addr.IA {
	return addr.IA(binary.BigEndian.Uint64(o.OptData[:8]))
}

// PacketCounter returns the packet counter value set in the option
func (o PacketReservReqForwardOption) PacketCounter() PacketCounter {
	return PacketCounter(binary.BigEndian.Uint64(o.OptData[8:12]))
}

func (o PacketReservReqBackwardOption) PacketCounter() PacketCounter {
	return PacketCounter(binary.BigEndian.Uint64(o.OptData[8:12]))
}

// Auth returns slice of the underlying auth buffer.
// Changes to this slice will be reflected on the wire when
// the extension is serialized.
func (o PacketReservReqForwardOption) Auth() []byte {
	return o.OptData[12:28]
}

func (o PacketReservReqBackwardOption) Auth() []byte {
	return o.OptData[12:28]
}

// Timestamp returns the timestamp value set in the option
func (o PacketReservReqForwardOption) Timestamp() uint64 {
	return binary.BigEndian.Uint64(o.OptData[28:34])
}

func (o PacketReservReqBackwardOption) Timestamp() uint64 {
	return binary.BigEndian.Uint64(o.OptData[28:34])
}

// ResponseOption field accessors

// ReservAS returns the reservation AS set in the option
func (o PacketReservResponseOption) ReservAS() addr.IA {
	return addr.IA(binary.BigEndian.Uint64(o.OptData[:8]))
}

// AuthEnc returns the encrypted authenticator set in the option
func (o PacketReservResponseOption) AuthEnc() []byte {
	return o.OptData[8:24]
}

// Bandwidth returns the bandwidth value set in the option
func (o PacketReservResponseOption) Bandwidth() uint32 {
	return binary.BigEndian.Uint32(o.OptData[24:28])
}

// TsExp returns the expiration timestamp set in the option
func (o PacketReservResponseOption) TsExp() uint64 {
	return binary.BigEndian.Uint64(o.OptData[28:36])
}

// IngressIF returns the ingress interface set in the option
func (o PacketReservResponseOption) IngressIF() uint16 {
	return binary.BigEndian.Uint16(o.OptData[36:38])
}

// EgressIF returns the egress interface set in the option
func (o PacketReservResponseOption) EgressIF() uint16 {
	return binary.BigEndian.Uint16(o.OptData[38:40])
}

// Tag returns the AEAD tag set in the option
func (o PacketReservResponseOption) Tag() []byte {
	return o.OptData[40:56]
}
