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

package extension_test

import (
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/extension"
	"github.com/stretchr/testify/assert"
)

func TestFabridControlDecode(t *testing.T) {
	type test struct {
		name          string
		o             *slayers.EndToEndOption
		baseTimestamp uint32
		validate      func(*extension.FabridControlOption, error, *testing.T)
	}
	unixNow := uint32(time.Now().Unix())
	tests := []test{
		{
			name: "Wrong option type",
			o: &slayers.EndToEndOption{
				OptType: slayers.OptTypeIdentifier,
				OptData: make([]byte, 8),
			},
			baseTimestamp: unixNow,
			validate: func(fco *extension.FabridControlOption, err error, t *testing.T) {
				assert.Error(t, err)
			},
		},
		{
			name: "Wrong fabrid control option type",
			o: &slayers.EndToEndOption{
				OptType: slayers.OptTypeFabridControl,
				OptData: []byte{0x20},
			},
			baseTimestamp: unixNow,
			validate: func(fco *extension.FabridControlOption, err error, t *testing.T) {
				assert.Error(t, err)
			},
		},
		{
			name: "Raw fabrid too short",
			o: &slayers.EndToEndOption{
				OptType: slayers.OptTypeFabridControl,
				OptData: make([]byte, 12),
			},
			baseTimestamp: unixNow,
			validate: func(fco *extension.FabridControlOption, err error, t *testing.T) {
				assert.Error(t, err)
			},
		},
		{
			name: "Raw fabrid parses with correct length",
			o: &slayers.EndToEndOption{
				OptType: slayers.OptTypeFabridControl,
				OptData: make([]byte, 13),
			},
			baseTimestamp: unixNow,
			validate: func(fco *extension.FabridControlOption, err error, t *testing.T) {
				assert.NoError(t, err)
			},
		},
		{
			name: "Parses fabrid validation config correctly",
			o: &slayers.EndToEndOption{
				OptType: slayers.OptTypeFabridControl,
				OptData: []byte{
					0x07, 0x00, 0x00, 0x01,
					0x01, 0x02, 0x03, 0x04,
					0x11, 0x22, 0x33, 0x44,
					0xaa,
				},
			},
			baseTimestamp: unixNow,
			validate: func(fco *extension.FabridControlOption, err error, t *testing.T) {
				assert.NoError(t, err)
				assert.Equal(t, extension.ValidationConfig, fco.ControlOptionType)
				expectedTime := int64(unixNow)*1000 + 0x7000001
				assert.Equal(t, expectedTime, fco.Timestamp.UnixMilli())
				assert.Equal(t, uint32(0x01020304), fco.PacketID)
				assert.Equal(t, []byte{0xaa}, fco.Data)
			},
		},
		{
			name: "Parses fabrid validation response correctly",
			o: &slayers.EndToEndOption{
				OptType: slayers.OptTypeFabridControl,
				OptData: []byte{
					0x0f, 0x00, 0x00, 0x01,
					0x01, 0x02, 0x03, 0x04,
					0x11, 0x22, 0x33, 0x44,
					0xaa, 0xbb, 0xcc, 0xdd,
				},
			},
			baseTimestamp: unixNow,
			validate: func(fco *extension.FabridControlOption, err error, t *testing.T) {
				assert.NoError(t, err)
				assert.Equal(t, extension.ValidationResponse, fco.ControlOptionType)
				expectedTime := int64(unixNow)*1000 + 0x7000001
				assert.Equal(t, expectedTime, fco.Timestamp.UnixMilli())
				assert.Equal(t, uint32(0x01020304), fco.PacketID)
				assert.Equal(t, []byte{0xaa, 0xbb, 0xcc, 0xdd}, fco.Data)
			},
		},
		{
			name: "Parses fabrid statistics request correctly",
			o: &slayers.EndToEndOption{
				OptType: slayers.OptTypeFabridControl,
				OptData: []byte{
					0x17, 0x00, 0x00, 0x01,
					0x01, 0x02, 0x03, 0x04,
					0x11, 0x22, 0x33, 0x44,
				},
			},
			baseTimestamp: unixNow,
			validate: func(fco *extension.FabridControlOption, err error, t *testing.T) {
				assert.NoError(t, err)
				assert.Equal(t, extension.StatisticsRequest, fco.ControlOptionType)
				expectedTime := int64(unixNow)*1000 + 0x7000001
				assert.Equal(t, expectedTime, fco.Timestamp.UnixMilli())
				assert.Equal(t, uint32(0x01020304), fco.PacketID)
			},
		},
		{
			name: "Parses fabrid statistics response correctly",
			o: &slayers.EndToEndOption{
				OptType: slayers.OptTypeFabridControl,
				OptData: []byte{
					0x1f, 0x00, 0x00, 0x01,
					0x01, 0x02, 0x03, 0x04,
					0x11, 0x22, 0x33, 0x44,
					0xaa, 0xbb, 0xcc, 0xdd,
					0x0a, 0x0b, 0x0c, 0x0d,
				},
			},
			baseTimestamp: unixNow,
			validate: func(fco *extension.FabridControlOption, err error, t *testing.T) {
				assert.NoError(t, err)
				assert.Equal(t, extension.StatisticsResponse, fco.ControlOptionType)
				expectedTime := int64(unixNow)*1000 + 0x7000001
				assert.Equal(t, expectedTime, fco.Timestamp.UnixMilli())
				assert.Equal(t, uint32(0x01020304), fco.PacketID)
				assert.Equal(t, []byte{
					0xaa, 0xbb, 0xcc, 0xdd,
					0x0a, 0x0b, 0x0c, 0x0d,
				}, fco.Data)
			},
		},
	}

	for _, tc := range tests {
		func(tc test) {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				fc, err := extension.ParseFabridControlOptionFullExtension(tc.o, tc.baseTimestamp)
				tc.validate(fc, err, t)
			})
		}(tc)
	}
}

func TestFabridControlSerialize(t *testing.T) {
	type test struct {
		name     string
		fc       *extension.FabridControlOption
		buffer   []byte
		validate func([]byte, error, *testing.T)
	}

	unixNow := uint32(time.Now().Unix())
	tests := []test{
		{
			name: "Fabrid control option is nil",
			fc:   nil,
			validate: func(b []byte, err error, t *testing.T) {
				assert.Error(t, err)
			},
		},
		{
			name: "Buffer too small",
			fc: &extension.FabridControlOption{
				ControlOptionType: extension.ValidationConfig,
				Data:              make([]byte, 1),
			},
			buffer: make([]byte, 12),
			validate: func(b []byte, err error, t *testing.T) {
				assert.Error(t, err)
			},
		},
		{
			name: "Data buffer too small",
			fc: &extension.FabridControlOption{
				ControlOptionType: extension.ValidationConfig,
			},
			buffer: make([]byte, 13),
			validate: func(b []byte, err error, t *testing.T) {
				assert.Error(t, err)
			},
		},
		{
			name: "Fabrid validation config serializes correctly",
			fc: &extension.FabridControlOption{
				ControlOptionType: extension.ValidationConfig,
				Timestamp:         time.Unix(int64(unixNow), 0x7000001*int64(time.Millisecond)),
				BaseTimestamp:     unixNow,
				PacketID:          0xaabbccdd,
				Auth:              [4]byte{0xa1, 0xb2, 0xc3, 0xd4},
				Data:              []byte{0x99},
			},
			buffer: make([]byte, 13),
			validate: func(b []byte, err error, t *testing.T) {
				assert.NoError(t, err)
				assert.Equal(t, []byte{0x07, 0x00, 0x00, 0x01}, b[0:4], "Wrong type or Timestamp")
				assert.Equal(t, []byte{0xaa, 0xbb, 0xcc, 0xdd}, b[4:8], "Wrong PacketID")
				assert.Equal(t, []byte{0xa1, 0xb2, 0xc3, 0xd4}, b[8:12], "Wrong Auth")
				assert.Equal(t, []byte{0x99}, b[12:13], "Wrong Data")
			},
		},
		{
			name: "Fabrid validation response serializes correctly",
			fc: &extension.FabridControlOption{
				ControlOptionType: extension.ValidationResponse,
				Timestamp:         time.Unix(int64(unixNow), 0x7000001*int64(time.Millisecond)),
				BaseTimestamp:     unixNow,
				PacketID:          0xaabbccdd,
				Auth:              [4]byte{0xa1, 0xb2, 0xc3, 0xd4},
				Data:              []byte{0x99, 0x88, 0x77, 0x66},
			},
			buffer: make([]byte, 16),
			validate: func(b []byte, err error, t *testing.T) {
				assert.NoError(t, err)
				assert.Equal(t, []byte{0x0f, 0x00, 0x00, 0x01}, b[0:4], "Wrong type or Timestamp")
				assert.Equal(t, []byte{0xaa, 0xbb, 0xcc, 0xdd}, b[4:8], "Wrong PacketID")
				assert.Equal(t, []byte{0xa1, 0xb2, 0xc3, 0xd4}, b[8:12], "Wrong Auth")
				assert.Equal(t, []byte{0x99, 0x88, 0x77, 0x66}, b[12:16], "Wrong Data")
			},
		},
		{
			name: "Fabrid statistics request serializes correctly",
			fc: &extension.FabridControlOption{
				ControlOptionType: extension.StatisticsRequest,
				Timestamp:         time.Unix(int64(unixNow), 0x7000001*int64(time.Millisecond)),
				BaseTimestamp:     unixNow,
				PacketID:          0xaabbccdd,
				Auth:              [4]byte{0xa1, 0xb2, 0xc3, 0xd4},
			},
			buffer: make([]byte, 12),
			validate: func(b []byte, err error, t *testing.T) {
				assert.NoError(t, err)
				assert.Equal(t, []byte{0x17, 0x00, 0x00, 0x01}, b[0:4], "Wrong type or Timestamp")
				assert.Equal(t, []byte{0xaa, 0xbb, 0xcc, 0xdd}, b[4:8], "Wrong PacketID")
				assert.Equal(t, []byte{0xa1, 0xb2, 0xc3, 0xd4}, b[8:12], "Wrong Auth")
			},
		},
		{
			name: "Fabrid statistics response serializes correctly",
			fc: &extension.FabridControlOption{
				ControlOptionType: extension.StatisticsResponse,
				Timestamp:         time.Unix(int64(unixNow), 0x7000001*int64(time.Millisecond)),
				BaseTimestamp:     unixNow,
				PacketID:          0xaabbccdd,
				Auth:              [4]byte{0xa1, 0xb2, 0xc3, 0xd4},
				Data:              []byte{0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22},
			},
			buffer: make([]byte, 20),
			validate: func(b []byte, err error, t *testing.T) {
				assert.NoError(t, err)
				assert.Equal(t, []byte{0x1f, 0x00, 0x00, 0x01}, b[0:4], "Wrong type or Timestamp")
				assert.Equal(t, []byte{0xaa, 0xbb, 0xcc, 0xdd}, b[4:8], "Wrong PacketID")
				assert.Equal(t, []byte{0xa1, 0xb2, 0xc3, 0xd4}, b[8:12], "Wrong Auth")
				assert.Equal(t, []byte{0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22}, b[12:20], "Wrong Data")
			},
		},
	}

	for _, tc := range tests {
		func(tc test) {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				err := tc.fc.SerializeTo(tc.buffer)
				tc.validate(tc.buffer, err, t)
			})
		}(tc)
	}
}
