// Copyright 2021 ETH Zurich
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
	"context"
	"fmt"
	"github.com/scionproto/scion/pkg/addr"
	drhelper "github.com/scionproto/scion/pkg/daemon/helper"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/drkey/specific"
	drpb "github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/extension"
	"github.com/scionproto/scion/pkg/snet"
	"google.golang.org/grpc"
	"time"
)

const maxValidationRatio uint8 = 128

type SimpleFabridConfig struct {
	DestinationIA   addr.IA
	DestinationAddr string
	ValidationRatio uint8
	Policy          snet.FabridPolicyIdentifier
}

type Statistics struct {
	TotalPackets   uint32
	InvalidPackets uint32
}

type ServerState struct {
	Source              snet.UDPAddr
	ValidationRatio     uint8
	Stats               Statistics
	fabridControlBuffer []byte
	tmpBuffer           []byte
	pathKey             drkey.Key
}

func NewFabridServerState(remote snet.UDPAddr, key drkey.Key) *ServerState {
	state := &ServerState{
		Source:              remote,
		pathKey:             key,
		ValidationRatio:     255,
		Stats:               Statistics{},
		fabridControlBuffer: make([]byte, 20),
		tmpBuffer:           make([]byte, 192),
	}
	return state
}

func FetchHostASKey(local snet.UDPAddr, t time.Time, dstIA addr.IA, grpcConn *grpc.ClientConn) (drkey.HostASKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	drkeyClient := drpb.NewDRKeyIntraServiceClient(grpcConn)
	meta := drkey.HostASMeta{
		Validity: t,
		SrcIA:    local.IA,
		SrcHost:  local.Host.IP.String(),
		DstIA:    dstIA,
		ProtoId:  drkey.FABRID,
	}
	rep, err := drkeyClient.DRKeyHostAS(ctx, drhelper.HostASMetaToProtoRequest(meta))
	if err != nil {
		return drkey.HostASKey{}, err
	}
	key, err := drhelper.GetHostASKeyFromReply(rep, meta)
	if err != nil {
		return drkey.HostASKey{}, err
	}
	return key, nil
}

func DeriveHostHostKey(dstHost string, hostAsKey drkey.HostASKey) (drkey.Key, error) {
	d := specific.Deriver{}
	hostHostKey, err := d.DeriveHostHost(dstHost, hostAsKey.Key)
	if err != nil {
		return drkey.Key{}, err
	}
	return hostHostKey, nil
}

func HandleFabridOption(fabridOption *extension.FabridOption, identifierOption *extension.IdentifierOption, state *ServerState) (*slayers.EndToEndExtn, error) {
	state.Stats.TotalPackets++
	validationNumber, _, err := VerifyPathValidator(fabridOption, state.tmpBuffer, state.pathKey[:])
	if err != nil {
		fmt.Println(err)
	}
	if validationNumber < state.ValidationRatio {
		fmt.Println("Should send validation response")
	}
	return nil, nil
}
