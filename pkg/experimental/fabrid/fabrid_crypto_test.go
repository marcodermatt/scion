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

package fabrid_test

import (
	crand "crypto/rand"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/experimental/fabrid"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/extension"
	"github.com/stretchr/testify/assert"
)

func TestEncryptPolicyID(t *testing.T) {
	unixNow := uint32(time.Now().Unix())

	id := &extension.IdentifierOption{
		Timestamp:     time.Unix(int64(unixNow), 10*int64(time.Millisecond)),
		PacketID:      0xaa,
		BaseTimestamp: unixNow,
	}
	// test with 64 different randomly chosen keys and policyIDs
	for i := 0; i < 64; i++ {
		idNumber := uint8(rand.Uint32())
		policyID := fabrid.FabridPolicyID{
			ID: idNumber,
		}
		key := generateRandomBytes(16)
		encPolicyID, err := fabrid.EncryptPolicyID(&policyID, id, key)
		assert.NoError(t, err)
		meta := &extension.FabridHopfieldMetadata{
			EncryptedPolicyID:  encPolicyID,
			HopValidationField: [3]byte{},
		}
		computedPolicyID, err := fabrid.ComputePolicyID(meta, id, key)
		assert.NoError(t, err)
		assert.Equal(t, policyID, computedPolicyID)
	}
}

func generateRandomBytes(len int) []byte {
	b := make([]byte, len)
	crand.Read(b)
	return b
}

func TestFailedValidation(t *testing.T) {
	//TODO: implement
}

func TestSuccessfullValidators(t *testing.T) {
	type test struct {
		name       string
		rawSrcAddr []byte
		srcIA      addr.IA
	}
	unixNow := uint32(time.Now().Unix())

	tmpBuffer := make([]byte, (extension.MaxSupportedFabridHops*3+15)&^15+16)
	tests := []test{
		{
			name:       "random 16 byte src addr",
			rawSrcAddr: generateRandomBytes(16),
			srcIA:      addr.IA(rand.Uint64()),
		},
		{
			name:       "random 12 byte src addr",
			rawSrcAddr: generateRandomBytes(12),
			srcIA:      addr.IA(rand.Uint64()),
		},
		{
			name:       "random 8 byte src addr",
			rawSrcAddr: generateRandomBytes(8),
			srcIA:      addr.IA(rand.Uint64()),
		},
		{
			name:       "random 4 byte src addr",
			rawSrcAddr: generateRandomBytes(4),
			srcIA:      addr.IA(rand.Uint64()),
		},
	}

	for _, tc := range tests {
		func(tc test) {
			t.Run(tc.name, func(t *testing.T) {
				id := &extension.IdentifierOption{
					Timestamp:     time.Unix(int64(unixNow), 10*int64(time.Millisecond)),
					PacketID:      rand.Uint32(),
					BaseTimestamp: unixNow,
				}
				s := &slayers.SCION{
					RawSrcAddr: tc.rawSrcAddr,
					SrcIA:      tc.srcIA,
				}
				f := &extension.FabridOption{}
				for j := uint8(1); j <= extension.MaxSupportedFabridHops; j++ {
					f.HopfieldMetadata = append(f.HopfieldMetadata, &extension.FabridHopfieldMetadata{
						EncryptedPolicyID: uint8(rand.Uint32()),
						FabridEnabled:     rand.Intn(2) == 0,
						ASLevelKey:        rand.Intn(2) == 0,
					})
					ases := []addr.IA{}
					pathKey := generateRandomBytes(16)
					asHostKeys := make(map[addr.IA]drkey.ASHostKey)
					asAsKeys := make(map[addr.IA]drkey.Level1Key)
					ingresses := []uint16{}
					egresses := []uint16{}

					for i := 0; i < len(f.HopfieldMetadata); i++ {
						ingresses = append(ingresses, uint16(rand.Int()))
						egresses = append(egresses, uint16(rand.Int()))
						var ia addr.IA
						if i == 0 {
							ia = tc.srcIA

						} else {
							ia = addr.IA(rand.Int())
						}
						ases = append(ases, ia)
						keyBytes := drkey.Key{}
						copy(keyBytes[:], generateRandomBytes(16))
						if f.HopfieldMetadata[i].ASLevelKey {
							asAsKeys[ia] = drkey.Level1Key{Key: drkey.Key(keyBytes)}
						} else {
							asHostKeys[ia] = drkey.ASHostKey{Key: drkey.Key(keyBytes)}
						}
					}

					srcValidationNumber, srcValidationReply, err := fabrid.InitValidators(f, id, s, tmpBuffer, pathKey, asHostKeys, asAsKeys, ases, ingresses, egresses)
					assert.NoError(t, err)

					for i, meta := range f.HopfieldMetadata {
						if meta.FabridEnabled {

							if meta.ASLevelKey {
								key := asAsKeys[ases[i]]
								err = fabrid.VerifyAndUpdate(meta, id, s, tmpBuffer, key.Key[:], ingresses[i], egresses[i])
							} else {
								key := asHostKeys[ases[i]]
								err = fabrid.VerifyAndUpdate(meta, id, s, tmpBuffer, key.Key[:], ingresses[i], egresses[i])
							}

							assert.NoError(t, err)
						}
					}
					dstValidationNumber, dstValidationReply, err := fabrid.VerifyPathValidator(f, tmpBuffer, pathKey)
					assert.NoError(t, err)

					assert.Equal(t, srcValidationNumber, dstValidationNumber)
					assert.Equal(t, srcValidationReply, dstValidationReply)
				}
			})
		}(tc)
	}
}

func TestControlOptionValidation(t *testing.T) {
	type test struct {
		name string
		fc   *extension.FabridControlOption
	}

	tests := []test{
		{
			name: "Success shortest control option",
			fc: &extension.FabridControlOption{
				Type:      extension.StatisticsRequest,
				Auth:      [4]byte{},
				Timestamp: uint32(0x07bbccdd),
				PacketID:  uint32(0xeeffaabb),
				Data:      []byte{},
			},
		},
		{
			name: "Success longest control option",
			fc: &extension.FabridControlOption{
				Type:      extension.StatisticsResponse,
				Auth:      [4]byte{},
				Timestamp: uint32(0x07bbccdd),
				PacketID:  uint32(0xeeffaabb),
				Data: []byte{
					0x07, 0xbb, 0xcc, 0xdd,
					0xee, 0xff, 0xaa, 0xbb,
					0x99, 0x88, 0x77, 0x66,
					0x55, 0x44, 0x33, 0x22,
				},
			},
		},
	}

	for _, tc := range tests {
		func(tc test) {
			t.Run(tc.name, func(t *testing.T) {
				pathKey := generateRandomBytes(16)
				err := fabrid.InitFabridControlValidator(tc.fc, pathKey)
				assert.NoError(t, err)

				err = fabrid.VerifyFabridControlValidator(tc.fc, pathKey)
				assert.NoError(t, err)

			})
		}(tc)
	}
}

func TestFailedControlOptionValidation(t *testing.T) {
	type test struct {
		name string
		fc   *extension.FabridControlOption
	}

	tests := []test{
		{
			name: "Failure shortest control option",
			fc: &extension.FabridControlOption{
				Type:      extension.StatisticsRequest,
				Auth:      [4]byte{},
				Timestamp: uint32(0x07bbccdd),
				PacketID:  uint32(0xeeffaabb),
				Data:      []byte{},
			},
		},
		{
			name: "Failure longest control option",
			fc: &extension.FabridControlOption{
				Type:      extension.StatisticsResponse,
				Auth:      [4]byte{},
				Timestamp: uint32(0x07bbccdd),
				PacketID:  uint32(0xeeffaabb),
				Data: []byte{
					0x07, 0xbb, 0xcc, 0xdd,
					0xee, 0xff, 0xaa, 0xbb,
					0x99, 0x88, 0x77, 0x66,
					0x55, 0x44, 0x33, 0x22,
				},
			},
		},
	}

	for _, tc := range tests {
		func(tc test) {
			t.Run(tc.name, func(t *testing.T) {
				pathKey := generateRandomBytes(16)
				err := fabrid.InitFabridControlValidator(tc.fc, pathKey)
				assert.NoError(t, err)
				randomShift := 4 + rand.Intn(28)
				byteIdx := randomShift / 8
				bitIdx := randomShift % 8
				fmt.Println(randomShift, byteIdx, bitIdx)
				tc.fc.Auth[byteIdx] ^= 1 << bitIdx

				err = fabrid.VerifyFabridControlValidator(tc.fc, pathKey)
				assert.Error(t, err)

			})
		}(tc)
	}
}
