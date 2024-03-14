// Copyright 2023 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fabrid

import (
	"github.com/scionproto/scion/control/config"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/segment/extensions/fabrid"
	"gopkg.in/yaml.v2"
	"os"
	"path/filepath"
	"time"
)

const MaxFabridPolicies = 255

// TODO(jvanbommel): Can probably combine this with PolicyIdentifier
type RemotePolicyIdentifier struct {
	ISDAS      uint64
	Identifier uint32
}

type RemotePolicyDescription struct {
	Description string
	Expires     time.Time
}

type FabridManager struct {
	autoIncrIndex            int
	PoliciesPath             string
	SupportedIndicesMap      fabrid.SupportedIndicesMap
	IndexIdentifierMap       fabrid.IndexIdentifierMap
	IdentifierDescriptionMap map[uint32]string
	MPLSMap                  *MplsMaps
	RemotePolicyCache        map[RemotePolicyIdentifier]RemotePolicyDescription
}

func NewFabridManager(policyPath string) (*FabridManager, error) {
	fb := &FabridManager{
		PoliciesPath:             policyPath,
		SupportedIndicesMap:      map[fabrid.ConnectionPair][]uint8{},
		IndexIdentifierMap:       map[uint8]*fabrid.PolicyIdentifier{},
		IdentifierDescriptionMap: map[uint32]string{},
		MPLSMap:                  NewMplsMaps(),
		RemotePolicyCache:        map[RemotePolicyIdentifier]RemotePolicyDescription{},
		autoIncrIndex:            1,
	}
	return fb, fb.Load()
}

func (f *FabridManager) Reload() error {
	f.IndexIdentifierMap = make(map[uint8]*fabrid.PolicyIdentifier)
	f.SupportedIndicesMap = make(map[fabrid.ConnectionPair][]uint8)
	f.MPLSMap = NewMplsMaps()
	f.autoIncrIndex = 1
	return f.Load()
}

func (f *FabridManager) Load() error {
	if err := filepath.Walk(f.PoliciesPath, f.parseAndAdd); err != nil {
		return serrors.WrapStr("Unable to read the fabrid policies in folder", err, "path", f.PoliciesPath)
	}
	f.MPLSMap.UpdateHash()
	return nil
}

func (f *FabridManager) Active() bool {
	//return len(f.SupportedIndicesMap) > 0
	return true
}

func (f *FabridManager) parseAndAdd(path string, fi os.FileInfo, err error) error {
	if !fi.Mode().IsRegular() {
		return nil
	}

	if f.autoIncrIndex > MaxFabridPolicies {
		return serrors.New("Amount of FABRID policies exceeds limit.")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return serrors.WrapStr("Unable to read the fabrid policy in file", err, "path", path)
	}
	pol, err := parseFABRIDYAMLPolicy(b)
	if err != nil {
		return err
	}

	policyIdx := uint8(f.autoIncrIndex)
	f.autoIncrIndex++

	if pol.IsLocalPolicy {
		f.IndexIdentifierMap[policyIdx] = &fabrid.PolicyIdentifier{
			Type:       fabrid.LocalPolicy,
			Identifier: pol.LocalIdentifier,
		}
		f.IdentifierDescriptionMap[pol.LocalIdentifier] = pol.LocalDescription
	} else {
		f.IndexIdentifierMap[policyIdx] = &fabrid.PolicyIdentifier{
			Type:       fabrid.GlobalPolicy,
			Identifier: pol.GlobalIdentifier,
		}
	}

	for _, connection := range pol.SupportedBy {
		ie := fabrid.ConnectionPair{
			Ingress: createConnectionPoint(connection.Ingress),
			Egress:  createConnectionPoint(connection.Egress),
		}
		f.MPLSMap.AddConnectionPoint(ie, connection.MPLSLabel, policyIdx)
		f.SupportedIndicesMap[ie] = append(f.SupportedIndicesMap[ie], policyIdx)
	}

	log.Debug("Loaded FABRID policy", "pol", pol)
	return nil
}

func parseFABRIDYAMLPolicy(b []byte) (*config.FABRIDPolicy, error) {
	p := &config.FABRIDPolicy{}
	if err := yaml.UnmarshalStrict(b, p); err != nil {
		return nil, serrors.WrapStr("Unable to parse policy", err)
	}
	return p, nil
}

func createConnectionPoint(connection config.FABRIDConnectionPoint) fabrid.ConnectionPoint {
	if connection.Type == fabrid.Interface {
		return fabrid.ConnectionPoint{
			Type:        fabrid.Interface,
			InterfaceId: connection.Interface,
		}
	} else if connection.Type == fabrid.IPv4Range || connection.Type == fabrid.IPv6Range {
		return fabrid.IPConnectionPointFromString(connection.IPAddress, uint32(connection.Prefix), connection.Type)
	} else if connection.Type == fabrid.Wildcard { //TODO(jvanbommel): explicit wildcard or intf 0 = wildcard?
		return fabrid.ConnectionPoint{
			Type: fabrid.Wildcard,
		}
	}
	return fabrid.ConnectionPoint{}
}
