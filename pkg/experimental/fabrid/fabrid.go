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
	"github.com/scionproto/scion/pkg/private/serrors"
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

type ClientConnection struct {
	Source              snet.UDPAddr
	ValidationRatio     uint8
	Stats               Statistics
	fabridControlBuffer []byte
	tmpBuffer           []byte
	pathKey             drkey.Key
}

type Server struct {
	Local       snet.UDPAddr
	grpcConn    *grpc.ClientConn
	Connections map[snet.UDPAddr]*ClientConnection
	ASKeyCache  map[addr.IA]drkey.HostASKey
}

type Client struct {
	Destination         snet.UDPAddr
	ValidationRatio     uint8
	fabridControlBuffer []byte
	pathKey             drkey.Key
	Paths               map[snet.PathFingerprint]*PathState
	Config              SimpleFabridConfig
}

type validationIdentifier struct {
	timestamp uint32
	packetId  uint32
}

type PathState struct {
	ValidationRatio      uint8
	expectedValResponses map[validationIdentifier]uint32
}

func NewFabridClient(remote snet.UDPAddr, key drkey.Key, config SimpleFabridConfig) *Client {
	state := &Client{
		Destination:         remote,
		ValidationRatio:     config.ValidationRatio,
		fabridControlBuffer: make([]byte, 20),
		pathKey:             key,
		Paths:               make(map[snet.PathFingerprint]*PathState),
		Config:              config,
	}
	return state
}

func (c *Client) NewFabridPathState(fingerprint snet.PathFingerprint) *PathState {
	state := &PathState{
		ValidationRatio:      c.ValidationRatio,
		expectedValResponses: make(map[validationIdentifier]uint32),
	}
	c.Paths[fingerprint] = state

	return state
}

func NewFabridServer(local *snet.UDPAddr, grpcConn *grpc.ClientConn) *Server {
	server := &Server{
		Local:       *local,
		grpcConn:    grpcConn,
		Connections: make(map[snet.UDPAddr]*ClientConnection),
		ASKeyCache:  make(map[addr.IA]drkey.HostASKey),
	}
	return server
}

func (s *Server) fetchHostASKey(t time.Time, dstIA addr.IA) (drkey.HostASKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	drkeyClient := drpb.NewDRKeyIntraServiceClient(s.grpcConn)
	meta := drkey.HostASMeta{
		Validity: t,
		SrcIA:    s.Local.IA,
		SrcHost:  s.Local.Host.IP.String(),
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

func (s *Server) DeriveHostHostKey(dstHost snet.UDPAddr) (drkey.Key, error) {
	var err error
	hostAsKey, ok := s.ASKeyCache[dstHost.IA]
	if !ok {
		hostAsKey, err = s.fetchHostASKey(time.Now(), dstHost.IA)
		if err != nil {
			return drkey.Key{}, err
		}
		s.ASKeyCache[dstHost.IA] = hostAsKey
	}

	d := specific.Deriver{}
	hostHostKey, err := d.DeriveHostHost(dstHost.Host.IP.String(), hostAsKey.Key)
	if err != nil {
		return drkey.Key{}, err
	}
	return hostHostKey, nil
}

func (s *Server) HandleFabridPacket(remote snet.UDPAddr, fabridOption *extension.FabridOption, identifierOption *extension.IdentifierOption, controlOption *extension.FabridControlOption) (*slayers.EndToEndExtn, error) {
	client, found := s.Connections[remote]
	if !found {
		pathKey, err := s.DeriveHostHostKey(remote)
		if err != nil {
			return nil, err
		}
		client = &ClientConnection{
			Source:              remote,
			ValidationRatio:     255,
			Stats:               Statistics{},
			fabridControlBuffer: make([]byte, 20),
			tmpBuffer:           make([]byte, 192),
			pathKey:             pathKey,
		}
		s.Connections[remote] = client
	}

	client.Stats.TotalPackets++
	validationNumber, validationReply, err := VerifyPathValidator(fabridOption, client.tmpBuffer, client.pathKey[:])
	if err != nil {
		fmt.Println(err)
		client.Stats.InvalidPackets++
		// Don't abort on invalid packets
		// TODO: add callback function here
		return nil, nil
	}

	var replyOpts []*extension.FabridControlOption
	if controlOption != nil {
		controlReplyOpt := &extension.FabridControlOption{
			Timestamp: identifierOption.GetRelativeTimestamp(),
			PacketID:  identifierOption.PacketID,
		}
		replyOpts = append(replyOpts, controlReplyOpt)

		switch controlOption.Type {
		case extension.ValidationConfig:
			requestedRatio, err := controlOption.ValidationRatio()
			if err != nil {
				return nil, err
			}
			if requestedRatio > maxValidationRatio {
				fmt.Println("FABRID control: requested ratio too large", "requested", requestedRatio, "max", maxValidationRatio)
				requestedRatio = maxValidationRatio
			}
			fmt.Println("FABRID control: updated validation ratio", "new", requestedRatio, "old", client.ValidationRatio)
			client.ValidationRatio = requestedRatio

			// Prepare ACK
			controlReplyOpt.Type = extension.ValidationConfigAck
			controlReplyOpt.Data = make([]byte, 1)
			err = controlReplyOpt.SetValidationRatio(client.ValidationRatio)
			if err != nil {
				return nil, err
			}
		case extension.StatisticsRequest:
			fmt.Println("FABRID control: statistics request")
			// Prepare statistics reply
			controlReplyOpt.Type = extension.StatisticsResponse
			controlReplyOpt.Data = make([]byte, 8)
			err := controlReplyOpt.SetStatistics(client.Stats.TotalPackets, client.Stats.InvalidPackets)
			if err != nil {
				return nil, err
			}
		}
	}
	if validationNumber < client.ValidationRatio {
		fmt.Println("Send validation response")
		validationReplyOpt := &extension.FabridControlOption{
			Timestamp: identifierOption.GetRelativeTimestamp(),
			PacketID:  identifierOption.PacketID,
		}
		replyOpts = append(replyOpts, validationReplyOpt)
		validationReplyOpt.Type = extension.ValidationResponse
		validationReplyOpt.Data = make([]byte, 4)
		err = validationReplyOpt.SetPathValidatorReply(validationReply)
		if err != nil {
			return nil, err
		}
		err = InitFabridControlValidator(validationReplyOpt, client.pathKey[:])
		if err != nil {
			return nil, err
		}
		err = validationReplyOpt.SerializeTo(client.fabridControlBuffer)
		if err != nil {
			return nil, err
		}
	}

	if len(replyOpts) > 0 {
		e2eExt := &slayers.EndToEndExtn{}
		for _, replyOpt := range replyOpts {
			fabridReplyOptionLength := extension.BaseFabridControlLen + extension.FabridControlOptionDataLen(replyOpt.Type)
			e2eExt.Options = append(e2eExt.Options,
				&slayers.EndToEndOption{
					OptType:      slayers.OptTypeFabridControl,
					OptData:      client.fabridControlBuffer,
					OptDataLen:   uint8(fabridReplyOptionLength),
					ActualLength: fabridReplyOptionLength,
				})
		}
		return e2eExt, nil
	}
	return nil, nil
}

func (ps *PathState) HandleFabridControlOption(controlOption *extension.FabridControlOption) error {
	switch controlOption.Type {
	case extension.ValidationConfigAck:
		confirmedRatio, err := controlOption.ValidationRatio()
		if err != nil {
			return err
		}
		if confirmedRatio == ps.ValidationRatio {
			fmt.Println("FABRID control: validation ratio confirmed", "ratio", confirmedRatio)
		} else if confirmedRatio < ps.ValidationRatio {
			fmt.Println("FABRID control: validation ratio reduced by server", "requested", ps.ValidationRatio, "confirmed", confirmedRatio)
			ps.ValidationRatio = confirmedRatio
		}
	case extension.ValidationResponse:
		validatorReply, err := controlOption.PathValidatorReply()
		if err != nil {
			return err
		}
		err = ps.CheckValidationResponse(validatorReply, controlOption.Timestamp, controlOption.PacketID)
		if err != nil {
			return err
		}

	case extension.StatisticsResponse:
		totalPkts, invalidPkts, err := controlOption.Statistics()
		if err != nil {
			return err
		}
		fmt.Println("FABRID control: statistics response", "totalPackets", totalPkts, "invalidPackets", invalidPkts)
	}
	return nil
}

func (ps *PathState) StoreValidationResponse(validator uint32, timestamp uint32, packetID uint32) error {
	valIdent := validationIdentifier{
		timestamp: timestamp,
		packetId:  packetID,
	}
	_, found := ps.expectedValResponses[valIdent]
	if found {
		return serrors.New("Validation response already stored", "validationIdentifier", valIdent)
	}
	fmt.Println("Storing validation response for PacketID:", packetID)
	ps.expectedValResponses[valIdent] = validator
	return nil
}

func (ps *PathState) CheckValidationResponse(validatorReply uint32, timestamp uint32, packetID uint32) error {
	valIdent := validationIdentifier{
		timestamp: timestamp,
		packetId:  packetID,
	}
	validatorStored, found := ps.expectedValResponses[valIdent]
	fmt.Println("Checking validation response")
	if found {
		if validatorStored == validatorReply {
			fmt.Println("FABRID control: successful validation of packetID", packetID)
		} else {
			return serrors.New("FABRID control: failed validation", "packetID", packetID, "stored", validatorStored, "reply", validatorReply)
		}
	} else {
		return serrors.New("FABRID control: unexpected validation response", "packetID", packetID)
	}
	return nil
}

//if f.counter%5 == 0 || f.counter%5 == 3 {
//if p.E2eExtension == nil {
//p.E2eExtension = &slayers.EndToEndExtn{}
//}
//controlOption := &extension.FabridControlOption{
//Timestamp: identifierOption.GetRelativeTimestamp(),
//PacketID:  identifierOption.PacketID,
//}
//switch f.counter % 5 {
//case 0:
//controlOption.Type = extension.ValidationConfig
//controlOption.Data = []byte{0xaa}
////case 1:
////	controlOption.ControlOptionType = extension.ValidationConfigAck
////	controlOption.Data = []byte{0xa0}
////case 2:
////	controlOption.ControlOptionType = extension.ValidationResponse
////	controlOption.Data = []byte{0xaa, 0xbb, 0xcc, 0xdd}
//case 3:
//controlOption.Type = extension.StatisticsRequest
////case 4:
////	controlOption.ControlOptionType = extension.StatisticsResponse
////	controlOption.Data = []byte{0x1, 0x2, 0x3, 0x4, 0x11, 0x22, 0x33, 0x44}
//
//}
//
//err = controlOption.SerializeTo(f.fabridControlBuffer)
//if err != nil {
//return serrors.WrapStr("serializing fabrid control option", err)
//}
//fabridControlLength := extension.FabridControlOptionLen(controlOption.ControlOptionType)
//p.E2eExtension.Options = append(p.E2eExtension.Options,
//&slayers.EndToEndOption{
//OptType:      slayers.OptTypeFabridControl,
//OptData:      f.fabridControlBuffer,
//OptDataLen:   uint8(fabridControlLength),
//ActualLength: fabridControlLength,
//})
//
//}
