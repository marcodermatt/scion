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

package fabrid

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"

	"github.com/scionproto/scion/pkg/segment/extensions/fabrid"
)

type PolicyIPRange struct {
	MPLSLabel uint32
	IP        []byte
	Prefix    uint32
}

type MplsMaps struct {
	IPPoliciesMap        map[uint32][]PolicyIPRange
	InterfacePoliciesMap map[uint64]uint32
	CurrentHash          []byte
}

func NewMplsMaps() *MplsMaps {
	return &MplsMaps{
		IPPoliciesMap:        make(map[uint32][]PolicyIPRange),
		InterfacePoliciesMap: make(map[uint64]uint32),
		CurrentHash:          []byte{},
	}
}

func (m *MplsMaps) AddConnectionPoint(ie fabrid.ConnectionPair, mplsLabel uint32, policyIdx uint8) {
	if mplsLabel == 0 {
		return
	}
	if ie.Egress.Type == fabrid.Interface {
		// Wildcard ingress interface:
		key := 1<<63 + uint64(ie.Egress.InterfaceId)<<8 + uint64(policyIdx)
		if ie.Ingress.Type == fabrid.Interface { // Specified ingress interface
			key = uint64(ie.Ingress.InterfaceId)<<24 + uint64(ie.Egress.
				InterfaceId)<<8 + uint64(policyIdx)
		}
		m.InterfacePoliciesMap[key] = mplsLabel
	} else if ie.Egress.Type == fabrid.IPv4Range { // Egress is IP network:
		key := 1<<31 + uint32(policyIdx)         // Wildcard ingress interface
		if ie.Ingress.Type == fabrid.Interface { // Specified ingress interface
			key = uint32(ie.Ingress.InterfaceId)<<8 + uint32(policyIdx)
		}
		m.IPPoliciesMap[key] = append(m.IPPoliciesMap[key], PolicyIPRange{
			IP:        ie.Egress.IPNetwork().IP,
			Prefix:    ie.Egress.Prefix,
			MPLSLabel: mplsLabel})
	}
}

func (m *MplsMaps) sortedIpPoliciesKeys() []uint32 {
	// TODO(jvanbommel): Q At this point we should just use an orderedmap library
	orderedKeys := make([]uint32, 0, len(m.IPPoliciesMap))
	for k := range m.IPPoliciesMap {
		orderedKeys = append(orderedKeys, k)
	}
	sort.Slice(orderedKeys, func(i int, j int) bool {
		return orderedKeys[i] < orderedKeys[j]
	})
	return orderedKeys
}

func (m *MplsMaps) sortedInterfacePoliciesKeys() []uint64 {
	orderedKeys := make([]uint64, 0, len(m.InterfacePoliciesMap))
	for k := range m.InterfacePoliciesMap {
		orderedKeys = append(orderedKeys, k)
	}
	sort.Slice(orderedKeys, func(i int, j int) bool {
		return orderedKeys[i] < orderedKeys[j]
	})
	return orderedKeys
}

//when scion is on go1.18 make it generic
//func sortedKeys[K comparable, V any](m map[K]V) []K {
//	keys := make([]K, 0, len(m))
//	for k := range m {
//		keys = append(keys, k)
//	}
//
//	sort.Slice(keys, func(i, j int) bool {
//		return keys[i] < keys[j]
//	})
//
//	return keys
//}

// This method is to be called after all inserts and removes from the internal map
// TODO(jvanbommel): this feels too expensive for what a relatively simple synchronization need.
// Revise?
func (m *MplsMaps) UpdateHash() {
	h := sha256.New()
	for _, polIdx := range m.sortedIpPoliciesKeys() {
		_ = binary.Write(h, binary.BigEndian, polIdx)
		for _, ipRange := range m.IPPoliciesMap[polIdx] {
			_ = binary.Write(h, binary.BigEndian, ipRange.MPLSLabel)
			h.Write(ipRange.IP)
			_ = binary.Write(h, binary.BigEndian, ipRange.Prefix)
		}
	}
	for _, polIdx := range m.sortedInterfacePoliciesKeys() {
		_ = binary.Write(h, binary.BigEndian, polIdx)
		_ = binary.Write(h, binary.BigEndian, m.InterfacePoliciesMap[polIdx])
	}
	m.CurrentHash = h.Sum(nil)
}
