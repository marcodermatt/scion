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

// This file includes the hop-by-hop extension header options for the Helia implementation

// Reservation request options format:
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   NextHdr=L4  |    ExtLen=9   |  OptType=3/4  | OptDataLen=34 |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                     Target AS Identifier                      +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Packet Counter                         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                                                               +
// |                                                               |
// +                        16-octet MAC data                      +
// |                                                               |
// +                                                               +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +           Timestamp	       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                               |   OptType=1   |       0       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// Reservation response options format:
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   NextHdr=L4  |   ExtLen=14   |   OptType=5   | OptDataLen=56 |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                   Reservation AS Identifier                   +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                                                               +
// |                                                               |
// +                    Encrypted Authenticator                    +
// |                                                               |
// +                                                               +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                           Bandwidth                           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                     Expiration Timestamp                      +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |       Ingress Interface       |        Egress Interface       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                                                               +
// |                                                               |
// +                       16-octet AEAD data                      +
// |                                                               |
// +                                                               +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// Reservation traffic options format:
// With `N` reservation fields, ExtLen=3+N and OptDataLen=12+4*N
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  NextHdr=L4   |     ExtLen    |   OptType=6   |  OptDataLen   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Direction   |     CurrRF    |        Backward length        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                       Packet Timestamp                        +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   AS_0 hash   |                    RVF_0                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//								...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   AS_i hash   |                    RVF_i                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//								...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  AS_N-1 hash  |                   RVF_N-1                     |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

package slayers

import (
	"encoding/binary"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
)

const (
	// PacketSetupReqDataLen is the fixed size of the Helia request OptData.
	PacketSetupReqDataLen = 34
	// PacketSetupResponseDataLen is the fixed size of the Helia response OptData.
	PacketSetupResponseDataLen = 56
	// MinPacketTrafficDataLen is the minimum size of the Helia traffic OptData.
	MinPacketTrafficDataLen = 12
)

type PacketReservReqParams struct {
	TargetAS  addr.IA
	Counter   uint32
	Timestamp uint64
	Auth      [16]byte
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

type PacketReservTrafficParams struct {
	Direction       uint8
	CurrRF          uint8
	MaxBackwardLen  uint16
	TsPkt           uint64
	ReservHopFields []ReservationField
}

type ReservationField struct {
	ASHash uint8
	RVF    [3]byte
}

// PacketReservReqForwardOption wraps an HopByHopOption of OptTypeReservReqForward.
// This can be used to serialize and parse the internal structure of the reservation request option.
type PacketReservReqForwardOption struct {
	*HopByHopOption
}

// PacketReservReqBackwardOption wraps an HopByHopOption of OptTypeReservReqBackward.
// This can be used to serialize and parse the internal structure of the reservation request option.
type PacketReservReqBackwardOption struct {
	*HopByHopOption
}

// PacketReservResponseOption wraps an HopByHopOption of OptTypeReservResponse.
// This can be used to serialize and parse the internal structure of the reservation response
// option.
type PacketReservResponseOption struct {
	*HopByHopOption
}

// PacketReservTrafficOption wraps an HopByHopOption of OptTypeReservTraffic.
// This can be used to serialize and parse the internal structure of the reservation traffic option.
type PacketReservTrafficOption struct {
	*HopByHopOption
}

// NewPacketReservReqForwardOption creates a new HopByHopOption of
// OptTypeReservReqForward, initialized with the given PacketParams.
func NewPacketReservReqForwardOption(
	p PacketReservReqParams,
) (PacketReservReqForwardOption, error) {

	o := PacketReservReqForwardOption{HopByHopOption: new(HopByHopOption)}
	err := o.Reset(p)
	return o, err
}

// NewPacketReservReqBackwardOption creates a new HopByHopOption of
// OptTypeReservReqBackward, initialized with the given PacketParams.
func NewPacketReservReqBackwardOption(
	p PacketReservReqParams,
) (PacketReservReqBackwardOption, error) {

	o := PacketReservReqBackwardOption{HopByHopOption: new(HopByHopOption)}
	err := o.Reset(p)
	return o, err
}

// NewPacketReservResponseOption creates a new HopByHopOption of
// OptTypeReservResponse, initialized with the given PacketParams.
func NewPacketReservResponseOption(
	p PacketReservResponseParams,
) (PacketReservResponseOption, error) {

	o := PacketReservResponseOption{HopByHopOption: new(HopByHopOption)}
	err := o.Reset(p)
	return o, err
}

// NewPacketReservTrafficOption creates a new HopByHopOption of
// OptTypeReservTraffic, initialized with the given PacketParams.
func NewPacketReservTrafficOption(
	p PacketReservTrafficParams,
) (PacketReservTrafficOption, error) {

	o := PacketReservTrafficOption{HopByHopOption: new(HopByHopOption)}
	err := o.Reset(p)
	return o, err
}

// ParsePacketReservReqForwardOption parses o as a PacketReservReqForwardOption.
func ParsePacketReservReqForwardOption(o *HopByHopOption) (PacketReservReqForwardOption, error) {
	if o.OptType != OptTypeReservReqForward {
		return PacketReservReqForwardOption{},
			serrors.New(
				"wrong option type", "expected", OptTypeReservReqForward, "actual", o.OptType,
			)
	}
	if len(o.OptData) != PacketSetupReqDataLen {
		return PacketReservReqForwardOption{},
			serrors.New(
				"buffer has wrong size", "expected", PacketSetupReqDataLen, "actual",
				len(o.OptData),
			)
	}
	return PacketReservReqForwardOption{o}, nil
}

// ParsePacketReservReqBackwardOption parses o as a PacketReservReqBackwardOption.
func ParsePacketReservReqBackwardOption(o *HopByHopOption) (PacketReservReqBackwardOption, error) {
	if o.OptType != OptTypeReservReqBackward {
		return PacketReservReqBackwardOption{},
			serrors.New(
				"wrong option type", "expected", OptTypeReservReqBackward, "actual", o.OptType,
			)
	}
	if len(o.OptData) != PacketSetupReqDataLen {
		return PacketReservReqBackwardOption{},
			serrors.New(
				"buffer has wrong size", "expected", PacketSetupReqDataLen, "actual",
				len(o.OptData),
			)
	}
	return PacketReservReqBackwardOption{o}, nil
}

// ParsePacketReservResponseOption parses o as a PacketReservResponseOption.
func ParsePacketReservResponseOption(o *HopByHopOption) (PacketReservResponseOption, error) {
	if o.OptType != OptTypeReservResponse {
		return PacketReservResponseOption{},
			serrors.New("wrong option type", "expected", OptTypeReservResponse, "actual", o.OptType)
	}
	if len(o.OptData) != PacketSetupResponseDataLen {
		return PacketReservResponseOption{},
			serrors.New(
				"buffer has wrong size", "expected", PacketSetupResponseDataLen, "actual",
				len(o.OptData),
			)
	}
	return PacketReservResponseOption{o}, nil
}

// ParsePacketReservTrafficOption parses o as a PacketReservTrafficOption.
func ParsePacketReservTrafficOption(o *HopByHopOption) (PacketReservTrafficOption, error) {
	if o.OptType != OptTypeReservTraffic {
		return PacketReservTrafficOption{},
			serrors.New("wrong option type", "expected", OptTypeReservTraffic, "actual", o.OptType)
	}
	if len(o.OptData) < MinPacketTrafficDataLen {
		return PacketReservTrafficOption{},
			serrors.New(
				"buffer too short", "expected at least", MinPacketTrafficDataLen, "actual",
				len(o.OptData),
			)
	}
	return PacketReservTrafficOption{o}, nil
}

// Reset reinitializes the underlying HopByHopOption with the give PacketParams.
// Reuses the OptData buffer if it is of sufficient capacity.
func (o PacketReservReqForwardOption) Reset(
	p PacketReservReqParams,
) error {

	if p.Timestamp >= (1 << 48) {
		return serrors.New("Timestamp value should be smaller than 2^48")
	}

	o.OptType = OptTypeReservReqForward

	if PacketSetupReqDataLen <= cap(o.OptData) {
		o.OptData = o.OptData[:PacketSetupReqDataLen]
	} else {
		o.OptData = make([]byte, PacketSetupReqDataLen)
	}
	binary.BigEndian.PutUint64(o.OptData[:8], uint64(p.TargetAS))
	binary.BigEndian.PutUint32(o.OptData[8:12], p.Counter)
	copy(o.OptData[12:28], p.Auth[:])
	binary.BigEndian.PutUint16(o.OptData[28:30], uint16(p.Timestamp>>32))
	binary.BigEndian.PutUint32(o.OptData[30:34], uint32(p.Timestamp))

	o.OptAlign = [2]uint8{4, 2}
	// reset unused/implicit fields
	o.OptDataLen = 0
	o.ActualLength = 0
	return nil
}

// Reset reinitializes the underlying HopByHopOption with the give PacketParams.
// Reuses the OptData buffer if it is of sufficient capacity.
func (o PacketReservReqBackwardOption) Reset(
	p PacketReservReqParams,
) error {

	if p.Timestamp >= (1 << 48) {
		return serrors.New("Timestamp value should be smaller than 2^48")
	}

	o.OptType = OptTypeReservReqBackward

	if PacketSetupReqDataLen <= cap(o.OptData) {
		o.OptData = o.OptData[:PacketSetupReqDataLen]
	} else {
		o.OptData = make([]byte, PacketSetupReqDataLen)
	}
	binary.BigEndian.PutUint64(o.OptData[:8], uint64(p.TargetAS))
	binary.BigEndian.PutUint32(o.OptData[8:12], p.Counter)
	copy(o.OptData[12:28], p.Auth[:])
	binary.BigEndian.PutUint16(o.OptData[28:30], uint16(p.Timestamp>>32))
	binary.BigEndian.PutUint32(o.OptData[30:34], uint32(p.Timestamp))

	o.OptAlign = [2]uint8{4, 2}
	// reset unused/implicit fields
	o.OptDataLen = 0
	o.ActualLength = 0
	return nil
}

// Reset reinitializes the underlying HopByHopOption with the give PacketParams.
// Reuses the OptData buffer if it is of sufficient capacity.
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

// Reset reinitializes the underlying HopByHopOption with the give PacketParams.
// Reuses the OptData buffer if it is of sufficient capacity.
func (o PacketReservTrafficOption) Reset(
	p PacketReservTrafficParams,
) error {

	o.OptType = OptTypeReservTraffic

	n := MinPacketTrafficDataLen + 4*len(p.ReservHopFields)
	if n <= cap(o.OptData) {
		o.OptData = o.OptData[:n]
	} else {
		o.OptData = make([]byte, n)
	}
	o.OptData[0] = p.Direction
	o.OptData[1] = p.CurrRF
	binary.BigEndian.PutUint16(o.OptData[2:4], p.MaxBackwardLen)
	binary.BigEndian.PutUint64(o.OptData[4:12], p.TsPkt)

	for i, reservHop := range p.ReservHopFields {
		offset := 12 + 4*i
		o.OptData[offset] = reservHop.ASHash
		copy(o.OptData[offset+1:offset+4], reservHop.RVF[:])
	}

	o.OptAlign = [2]uint8{4, 2}
	// reset unused/implicit fields
	o.OptDataLen = 0
	o.ActualLength = 0
	return nil
}

// PacketReservReqOption field accessors

// TargetAS returns the target AS address value set in the option
func (o PacketReservReqForwardOption) TargetAS() addr.IA {
	return addr.IA(binary.BigEndian.Uint64(o.OptData[:8]))
}

// TargetAS returns the target AS address value set in the option
func (o PacketReservReqBackwardOption) TargetAS() addr.IA {
	return addr.IA(binary.BigEndian.Uint64(o.OptData[:8]))
}

// RawHeliaTargetAS returns the target AS address value set in the unparsed option
func RawHeliaTargetAS(option *HopByHopOption) addr.IA {
	return addr.IA(binary.BigEndian.Uint64(option.OptData[:8]))
}

// PacketCounter returns the packet counter value set in the option
func (o PacketReservReqForwardOption) PacketCounter() uint32 {
	return binary.BigEndian.Uint32(o.OptData[8:12])
}

// PacketCounter returns the packet counter value set in the option
func (o PacketReservReqBackwardOption) PacketCounter() uint32 {
	return binary.BigEndian.Uint32(o.OptData[8:12])
}

// Timestamp returns the request timestamp value set in the option
func (o PacketReservReqForwardOption) Timestamp() uint64 {
	return uint64(binary.BigEndian.Uint16(o.OptData[28:30]))<<32 +
		uint64(binary.BigEndian.Uint32(o.OptData[30:34]))
}

// Timestamp returns the request timestamp value set in the option
func (o PacketReservReqBackwardOption) Timestamp() uint64 {
	return uint64(binary.BigEndian.Uint16(o.OptData[28:30]))<<32 +
		uint64(binary.BigEndian.Uint32(o.OptData[30:34]))
}

// Auth returns slice of the underlying auth buffer.
// Changes to this slice will be reflected on the wire when
// the extension is serialized.
func (o PacketReservReqForwardOption) Auth() []byte {
	return o.OptData[12:28]
}

// Auth returns slice of the underlying auth buffer.
// Changes to this slice will be reflected on the wire when
// the extension is serialized.
func (o PacketReservReqBackwardOption) Auth() []byte {
	return o.OptData[12:28]
}

// PacketReservResponseOption field accessors

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

// TrafficOption field accessors

// Direction returns the direction flag set in the option
func (o PacketReservTrafficOption) Direction() uint8 {
	return o.OptData[0]
}

// CurrRF returns the current reservation field pointer in the option
func (o PacketReservTrafficOption) CurrRF() uint8 {
	return o.OptData[1]
}

// MaxBackwardLen returns the backwards length in the option
func (o PacketReservTrafficOption) MaxBackwardLen() uint16 {
	return binary.BigEndian.Uint16(o.OptData[2:4])
}

// TsPkt returns the packet timestamp in the option
func (o PacketReservTrafficOption) TsPkt() uint64 {
	return binary.BigEndian.Uint64(o.OptData[4:12])
}

// NumRF returns the number of reservation fields in the option
func (o PacketReservTrafficOption) NumRF() uint8 {
	return uint8((len(o.OptData) - 12) / 4)
}

// GetRF returns the reservation field at index i in the option
func (o PacketReservTrafficOption) GetRF(i uint8) (ReservationField, error) {
	if i >= o.NumRF() {
		return ReservationField{}, serrors.New("Index out of range", "actual length", o.NumRF())
	}
	offset := 12 + 4*i
	rf := ReservationField{ASHash: o.OptData[offset]}
	copy(rf.RVF[:], o.OptData[offset+1:offset+4])
	return rf, nil
}

// RawHeliaRFHash returns the AS hash of the current RF set in the unparsed option
func RawHeliaRFHash(option *HopByHopOption) uint8 {
	// Retrieve currRF for calculating RF offset
	offset := 12 + 4*option.OptData[1]
	return option.OptData[offset]
}
