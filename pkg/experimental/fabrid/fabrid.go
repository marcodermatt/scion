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
	"github.com/scionproto/scion/pkg/addr"
	drhelper "github.com/scionproto/scion/pkg/daemon/helper"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/drkey/specific"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	drpb "github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/extension"
	"github.com/scionproto/scion/pkg/snet"
	"google.golang.org/grpc"
	"time"
)

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
	Local              snet.UDPAddr
	grpcConn           *grpc.ClientConn
	Connections        map[string]*ClientConnection
	ASKeyCache         map[addr.IA]drkey.HostASKey
	MaxValidationRatio uint8
}

type Client struct {
	Destination         snet.UDPAddr
	validationRatio     uint8
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
	UpdateValRatio       bool
	RequestStatistics    bool
	Stats                Statistics
	expectedValResponses map[validationIdentifier]uint32
}

func NewFabridClient(remote snet.UDPAddr, key drkey.Key, config SimpleFabridConfig) *Client {
	state := &Client{
		Destination:         remote,
		validationRatio:     config.ValidationRatio,
		fabridControlBuffer: make([]byte, 20*3),
		pathKey:             key,
		Paths:               make(map[snet.PathFingerprint]*PathState),
		Config:              config,
	}
	return state
}

func (c *Client) NewFabridPathState(fingerprint snet.PathFingerprint) *PathState {
	state := &PathState{
		ValidationRatio:      c.validationRatio,
		UpdateValRatio:       true,
		RequestStatistics:    false,
		expectedValResponses: make(map[validationIdentifier]uint32),
	}
	c.Paths[fingerprint] = state

	log.Debug("New FABRID PathState")
	return state
}

func (c *Client) GetFabridPathState(fingerprint snet.PathFingerprint) (*PathState, error) {
	state, found := c.Paths[fingerprint]
	if !found {
		return nil, serrors.New("No state found", "pathFingerprint", fingerprint)
	}
	return state, nil
}

func (c *Client) SetValidationRatio(newRatio uint8) {
	for _, pathState := range c.Paths {
		if pathState.ValidationRatio != newRatio {
			pathState.ValidationRatio = newRatio
			pathState.UpdateValRatio = true
		}
	}
	c.validationRatio = newRatio
}

func NewFabridServer(local *snet.UDPAddr, grpcConn *grpc.ClientConn, maxValidationRatio uint8) *Server {
	server := &Server{
		Local:              *local,
		grpcConn:           grpcConn,
		Connections:        make(map[string]*ClientConnection),
		ASKeyCache:         make(map[addr.IA]drkey.HostASKey),
		MaxValidationRatio: maxValidationRatio,
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

func (s *Server) HandleFabridPacket(remote snet.UDPAddr, fabridOption *extension.FabridOption, identifierOption *extension.IdentifierOption, controlOptions []*extension.FabridControlOption) (*slayers.EndToEndExtn, error) {
	client, found := s.Connections[remote.String()]
	if !found {
		log.Info("Opening new connection", "remote", remote.String())
		pathKey, err := s.DeriveHostHostKey(remote)
		if err != nil {
			return nil, err
		}
		client = &ClientConnection{
			Source:              remote,
			ValidationRatio:     0,
			Stats:               Statistics{},
			fabridControlBuffer: make([]byte, 28*3),
			tmpBuffer:           make([]byte, 192),
			pathKey:             pathKey,
		}
		s.Connections[remote.String()] = client
	}

	client.Stats.TotalPackets++
	validationNumber, validationReply, err := VerifyPathValidator(fabridOption, client.tmpBuffer, client.pathKey[:])
	if err != nil {
		log.Error("Path validation failed", "err", err)
		client.Stats.InvalidPackets++
		// Don't abort on invalid packets
		// TODO: add callback function here
		return nil, nil
	}

	var replyOpts []*extension.FabridControlOption
	for _, controlOption := range controlOptions {
		err := VerifyFabridControlValidator(controlOption, client.pathKey[:])
		if err != nil {
			return nil, err
		}
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
			if requestedRatio > s.MaxValidationRatio {
				log.Debug("FABRID control: requested ratio too large", "requested", requestedRatio, "max", s.MaxValidationRatio)
				requestedRatio = s.MaxValidationRatio
			}
			log.Debug("FABRID control: updated validation ratio", "new", requestedRatio, "old", client.ValidationRatio)
			client.ValidationRatio = requestedRatio

			// Prepare ACK
			controlReplyOpt.Type = extension.ValidationConfigAck
			controlReplyOpt.Data = make([]byte, 9)
			err = controlReplyOpt.SetValidationRatio(client.ValidationRatio)
			if err != nil {
				return nil, err
			}
		case extension.StatisticsRequest:
			log.Debug("FABRID control: statistics request")
			// Prepare statistics reply
			controlReplyOpt.Type = extension.StatisticsResponse
			controlReplyOpt.Data = make([]byte, 24)
			err := controlReplyOpt.SetStatistics(client.Stats.TotalPackets, client.Stats.InvalidPackets)
			if err != nil {
				return nil, err
			}
		}
	}
	if validationNumber < client.ValidationRatio {
		log.Debug("Send validation response for packetID", identifierOption.PacketID)
		validationReplyOpt := &extension.FabridControlOption{
			Timestamp: identifierOption.GetRelativeTimestamp(),
			PacketID:  identifierOption.PacketID,
		}
		replyOpts = append(replyOpts, validationReplyOpt)
		validationReplyOpt.Type = extension.ValidationResponse
		validationReplyOpt.Data = make([]byte, 20)
		err = validationReplyOpt.SetPathValidatorReply(validationReply)
		if err != nil {
			return nil, err
		}
	}

	if len(replyOpts) > 0 {
		e2eExt := &slayers.EndToEndExtn{}
		for i, replyOpt := range replyOpts {
			err = InitFabridControlValidator(replyOpt, client.pathKey[:])
			if err != nil {
				return nil, err
			}
			buffer := client.fabridControlBuffer[i*28 : (i+1)*28]
			err = replyOpt.SerializeTo(buffer)
			if err != nil {
				return nil, err
			}
			fabridReplyOptionLength := extension.BaseFabridControlLen + extension.FabridControlOptionDataLen(replyOpt.Type)
			e2eExt.Options = append(e2eExt.Options,
				&slayers.EndToEndOption{
					OptType:      slayers.OptTypeFabridControl,
					OptData:      buffer,
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
			log.Debug("FABRID control: validation ratio confirmed", "ratio", confirmedRatio)
		} else if confirmedRatio < ps.ValidationRatio {
			log.Debug("FABRID control: validation ratio reduced by server", "requested", ps.ValidationRatio, "confirmed", confirmedRatio)
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
		log.Debug("FABRID control: statistics response", "totalPackets", totalPkts, "invalidPackets", invalidPkts)
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
	log.Debug("Storing validation response", "packetID", packetID)
	ps.expectedValResponses[valIdent] = validator
	return nil
}

func (ps *PathState) CheckValidationResponse(validatorReply uint32, timestamp uint32, packetID uint32) error {
	valIdent := validationIdentifier{
		timestamp: timestamp,
		packetId:  packetID,
	}
	log.Debug("Checking validation response", "timestamp", timestamp, "packetID", packetID)
	validatorStored, found := ps.expectedValResponses[valIdent]
	if found {
		if validatorStored == validatorReply {
			log.Debug("FABRID control: successful validation", "packetID", packetID)
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
