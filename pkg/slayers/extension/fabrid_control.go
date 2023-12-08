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

// The FABRID control option format is as follows:
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   NextHdr     |     ExtLen    |  OptType = 5  |    OptLen     |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |    Type   |              Timestamp                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          Packet ID                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                           E2E Mac                             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                             ...                               |
// |                          [Content]                            |
// |                             ...                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

package extension

import (
	"encoding/binary"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	"time"
)

const baseFabridControlLen int = 12

//const FabridMetadataLen int = 4
//const MaxSupportedFabridHops = 62

type FabridControlOptionType uint8

// Definition of FABRID control option type constants.
const (
	ValidationConfig FabridControlOptionType = iota
	ValidationResponse
	StatisticsRequest
	StatisticsResponse
)

type FabridControlOption struct {
	// Type of the control message
	ControlOptionType FabridControlOptionType
	// Timestamp with 1 ms precision
	Timestamp time.Time
	// The packet ID
	PacketID uint32
	// The base timestamp. Usually the timestamp of the first info field.
	BaseTimestamp uint32
	Auth          [4]byte
	Data          []byte
}

type FabridControlStatistics struct {
	ValidPackets   uint32
	InvalidPackets uint32
}

// Validates the length of FabridControlOption. Requires ControlOptionType to be set
func (fc *FabridControlOption) validate(b []byte) error {
	if fc == nil {
		return serrors.New("Fabrid control option must not be nil")
	}
	if fc.ControlOptionType > StatisticsResponse {
		return serrors.New("Invalid fabrid control option type")
	}
	if len(b) < FabridControlOptionLen(fc.ControlOptionType) {
		return serrors.New("Raw Fabrid control option too short", "is", len(b),
			"expected", FabridControlOptionLen(fc.ControlOptionType))
	}
	return nil
}

func (fc *FabridControlOption) GetRelativeTimestamp() uint32 {
	return uint32(fc.Timestamp.UnixMilli()-int64(fc.BaseTimestamp)*1000) & 0x7FFFFFF
}

func (fc *FabridControlOption) decodeTimestampFromBytes(b []byte) {
	relativeTimestamp := binary.BigEndian.Uint32(b) & 0x7FFFFFF // take only the right 27bit
	ts := uint64(relativeTimestamp) + 1000*uint64(fc.BaseTimestamp)
	fc.Timestamp = time.Unix(0, int64(time.Millisecond)*int64(ts))
}

func (fc *FabridControlOption) serializeTimestampTo(b []byte) {
	binary.BigEndian.PutUint32(b, fc.GetRelativeTimestamp())
}
func (fc *FabridControlOption) Decode(b []byte) error {
	fc.ControlOptionType = FabridControlOptionType(b[0] >> 3)
	if err := fc.validate(b); err != nil {
		return err
	}
	fc.decodeTimestampFromBytes(b[0:4])
	fc.PacketID = binary.BigEndian.Uint32(b[4:8])
	copy(fc.Auth[:], b[8:12])
	switch fc.ControlOptionType {
	case ValidationConfig:
		fc.Data = make([]byte, 1)
		copy(fc.Data[:], b[12:13])
	case ValidationResponse:
		fc.Data = make([]byte, 4)
		copy(fc.Data[:], b[12:16])
	case StatisticsResponse:
		fc.Data = make([]byte, 8)
		copy(fc.Data[:], b[12:20])
	}
	return nil
}

func (fc *FabridControlOption) SerializeTo(b []byte) error {
	if fc == nil {
		return serrors.New("Fabrid control option must not be nil")
	}
	if len(b) < FabridControlOptionLen(fc.ControlOptionType) {
		return serrors.New("Buffer too short", "is", len(b),
			"expected", FabridControlOptionLen(fc.ControlOptionType))
	}
	// Set timestamp before type, so it is not overwritten
	fc.serializeTimestampTo(b[0:4])
	b[0] &= 0x7 // clear the first 5 (left) bits
	b[0] |= uint8(fc.ControlOptionType) << 3
	binary.BigEndian.PutUint32(b[4:8], fc.PacketID)
	copy(b[8:12], fc.Auth[:])
	if len(fc.Data) < fabridControlOptionDataLen(fc.ControlOptionType) {
		return serrors.New("Data too short", "is", len(fc.Data),
			"expected", fabridControlOptionDataLen(fc.ControlOptionType))
	}
	switch fc.ControlOptionType {
	case ValidationConfig:
		copy(b[12:], fc.Data[:1])
	case ValidationResponse:
		copy(b[12:16], fc.Data[0:4])
	case StatisticsResponse:
		copy(b[12:20], fc.Data[0:8])
	}
	return nil
}

func FabridControlOptionLen(controlOptionType FabridControlOptionType) int {
	return baseFabridControlLen + fabridControlOptionDataLen(controlOptionType)
}

func fabridControlOptionDataLen(controlOptionType FabridControlOptionType) int {
	switch controlOptionType {
	case ValidationConfig:
		return 1
	case ValidationResponse:
		return 4
	case StatisticsRequest:
		return 0
	case StatisticsResponse:
		return 8
	default:
		return 0
	}
}

func ParseFabridControlOptionFullExtension(o *slayers.EndToEndOption, baseTimestamp uint32) (*FabridControlOption, error) {
	if o.OptType != slayers.OptTypeFabridControl {
		return nil,
			serrors.New("Wrong option type", "expected", slayers.OptTypeFabridControl, "actual", o.OptType)
	}
	fc := &FabridControlOption{
		BaseTimestamp: baseTimestamp,
	}
	if err := fc.Decode(o.OptData); err != nil {
		return nil, err
	}
	return fc, nil
}
