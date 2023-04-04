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

package slayers_test

import (
	"encoding/binary"
	"testing"

	"github.com/google/gopacket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/slayers"
)

var (
	heliaAS      = xtest.MustParseIA("1-ff00:0:110")
	counter      = uint32(0x04030201)
	timestamp    = uint64(0x0A0908070605)
	reservReqMAC = []byte("16byte_mac_foooo")
)

var rawHBHReservReqForward = append(
	[]byte{
		0x11, 0x9, 0x3, 0x22,
		0x0, 0x1, 0xff, 0x0,
		0x0, 0x0, 0x1, 0x10,
		0x4, 0x3, 0x2, 0x1,
	}, append(reservReqMAC,
		0xA, 0x9, 0x8, 0x7,
		0x6, 0x5, 0x1, 0x0)...)

func TestReservReqForwardSerialize(t *testing.T) {
	cases := []struct {
		name      string
		heliaAS   addr.IA
		counter   uint32
		timestamp uint64
		auth      []byte
		errorFunc assert.ErrorAssertionFunc
	}{
		{
			name:      "correct",
			heliaAS:   heliaAS,
			counter:   counter,
			timestamp: timestamp,
			auth:      reservReqMAC,
			errorFunc: assert.NoError,
		},
		{
			name:      "bad_ts",
			heliaAS:   heliaAS,
			counter:   counter,
			timestamp: binary.LittleEndian.Uint64([]byte{0, 0, 0, 0, 0, 0, 1, 0}),
			auth:      reservReqMAC,
			errorFunc: assert.Error,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {

			reservOpt, err := slayers.NewPacketReservReqForwardOption(slayers.PacketReservReqParams{
				TargetAS:  heliaAS,
				Counter:   counter,
				Timestamp: c.timestamp,
				Auth:      *(*[16]byte)(c.auth),
			})
			c.errorFunc(t, err)
			if err != nil {
				return
			}

			hbh := slayers.HopByHopExtn{}
			hbh.NextHdr = slayers.L4UDP
			hbh.Options = []*slayers.HopByHopOption{reservOpt.HopByHopOption}

			b := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{FixLengths: true}
			assert.NoError(t, hbh.SerializeTo(b, opts), "SerializeTo")
			assert.Equal(t, rawHBHReservReqForward, b.Bytes(), "Raw Buffer")
		})
	}
}

func TestReservReqForwardDeserialize(t *testing.T) {
	hbh := slayers.HopByHopExtn{}

	_, err := hbh.FindOption(slayers.OptTypeReservReqForward)
	assert.Error(t, err)

	assert.NoError(t, hbh.DecodeFromBytes(rawHBHReservReqForward, gopacket.NilDecodeFeedback))
	assert.Equal(t, slayers.L4UDP, hbh.NextHdr, "NextHeader")
	reservOpt, err := hbh.FindOption(slayers.OptTypeReservReqForward)
	require.NoError(t, err, "FindOption")
	reserv, err := slayers.ParsePacketReservReqForwardOption(reservOpt)
	require.NoError(t, err, "ParsePacketRservReqForwardOption")
	assert.Equal(t, heliaAS, reserv.TargetAS(), "Target AS")
	assert.Equal(t, counter, reserv.PacketCounter(), "Counter")
	assert.Equal(t, timestamp, reserv.Timestamp(), "Timestamp")
	assert.Equal(t, optAuthMAC, reserv.Auth(), "Authenticator data (MAC)")
}

func TestReservReqForwardDeserializeCorrupt(t *testing.T) {
	optReservCorrupt := slayers.HopByHopOption{
		OptType: slayers.OptTypeReservReqForward,
		OptData: []byte{},
	}
	hbh := slayers.HopByHopExtn{}
	hbh.NextHdr = slayers.L4UDP
	hbh.Options = []*slayers.HopByHopOption{&optReservCorrupt}

	b := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	assert.NoError(t, hbh.SerializeTo(b, opts), "SerializeTo")

	assert.NoError(t, hbh.DecodeFromBytes(b.Bytes(), gopacket.NilDecodeFeedback))
	optAuth, err := hbh.FindOption(slayers.OptTypeReservReqForward)
	require.NoError(t, err, "FindOption")
	_, err = slayers.ParsePacketReservReqForwardOption(optAuth)
	require.Error(t, err, "ParsePacketReservReqForwardOption should fail")
}
