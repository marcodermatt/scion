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

package grpc

import (
	"bytes"
	"context"
	"time"

	"github.com/scionproto/scion/control/fabrid"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/proto/control_plane/experimental"
	fabridext "github.com/scionproto/scion/pkg/segment/extensions/fabrid"
)

type Server struct {
	FabridManager *fabrid.FabridManager
	Fetcher       PolicyFetcher
}

func (s Server) mplsIPMapToPB() map[uint32]*experimental.MPLSIPArray {
	mplsIpMap := make(map[uint32]*experimental.MPLSIPArray)
	for i, entry := range s.FabridManager.MPLSMap.IPPoliciesMap {
		if _, exists := mplsIpMap[i]; !exists {
			mplsIpMap[i] = &experimental.MPLSIPArray{Entry: make([]*experimental.MPLSIP, 0,
				len(entry))}
		}
		for _, iprange := range entry {
			mplsIpMap[i].Entry = append(mplsIpMap[i].Entry, &experimental.MPLSIP{
				MplsLabel: iprange.MPLSLabel,
				Ip:        iprange.IP,
				Prefix:    iprange.Prefix,
			})
		}
	}
	return mplsIpMap
}

func (s Server) MPLSMap(ctx context.Context, request *experimental.MPLSMapRequest) (*experimental.
	MPLSMapResponse, error) {
	if bytes.Equal(request.Hash, s.FabridManager.MPLSMap.CurrentHash) {
		return &experimental.MPLSMapResponse{Update: false}, nil
	}
	// Create the map of mpls labelks for
	return &experimental.MPLSMapResponse{
		Update:                   true,
		Hash:                     s.FabridManager.MPLSMap.CurrentHash,
		MplsInterfacePoliciesMap: s.FabridManager.MPLSMap.InterfacePoliciesMap,
		MplsIpMap:                s.mplsIPMapToPB(),
	}, nil
}

func (s Server) RemotePolicyDescription(ctx context.Context,
	request *experimental.RemotePolicyDescriptionRequest) (
	*experimental.RemotePolicyDescriptionResponse, error) {
	//TODO(jvanbommel): signature / hash?
	identifier := fabrid.RemotePolicyIdentifier{
		ISDAS:      request.IsdAs,
		Identifier: request.PolicyIdentifier,
	}
	if val, ok := s.FabridManager.RemotePolicyCache[identifier]; ok && val.Expires.After(
		time.Now()) {
		return &experimental.RemotePolicyDescriptionResponse{Description: val.Description}, nil
	}

	policy, err := s.Fetcher.GetRemotePolicy(ctx, addr.IA(request.IsdAs), request.PolicyIdentifier)
	if err != nil {
		return &experimental.RemotePolicyDescriptionResponse{}, err
	}

	s.FabridManager.RemotePolicyCache[identifier] = fabrid.RemotePolicyDescription{
		Description: policy.Description,
		Expires:     time.Now().Add(s.FabridManager.RemoteCacheValidity),
	}

	return &experimental.RemotePolicyDescriptionResponse{Description: policy.Description}, nil
}

func (s Server) SupportedIndicesMap(_ context.Context,
	_ *experimental.SupportedIndicesMapRequest) (*experimental.SupportedIndicesMapResponse, error) {
	return &experimental.SupportedIndicesMapResponse{
		SupportedIndicesMap: fabridext.SupportedIndicesMapToPB(s.FabridManager.SupportedIndicesMap),
	}, nil
}

func (s Server) IndexIdentifierMap(_ context.Context, _ *experimental.IndexIdentifierMapRequest) (
	*experimental.IndexIdentifierMapResponse, error) {

	return &experimental.IndexIdentifierMapResponse{
		IndexIdentifierMap: fabridext.IndexIdentifierMapToPB(s.FabridManager.IndexIdentifierMap),
	}, nil
}

func (s Server) LocalPolicyDescription(_ context.Context,
	request *experimental.LocalPolicyDescriptionRequest) (
	*experimental.LocalPolicyDescriptionResponse, error) {

	if descr, ok := s.FabridManager.IdentifierDescriptionMap[request.PolicyIdentifier]; ok {
		return &experimental.LocalPolicyDescriptionResponse{
			Description: descr}, nil
	}
	return &experimental.LocalPolicyDescriptionResponse{}, errNotFound
}
