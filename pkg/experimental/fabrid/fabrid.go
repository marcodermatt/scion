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
	crand "crypto/rand"
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

// Testing options for failing validation
const CLIENT_FLAKINESS = 0
const SERVER_FLAKINESS = 64

type SimpleFabridConfig struct {
	DestinationIA     addr.IA
	DestinationAddr   string
	LocalIA           addr.IA
	LocalAddr         string
	ValidationRatio   uint8
	Policy            snet.FabridPolicyIdentifier
	ValidationHandler func(*PathState, *extension.FabridControlOption, bool)
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
	ValidationHandler  func(*ClientConnection, *extension.IdentifierOption, bool)
}

type Client struct {
	Destination         snet.UDPAddr
	validationRatio     uint8
	fabridControlBuffer []byte
	PathKey             drkey.HostHostKey
	Paths               map[snet.PathFingerprint]*PathState
	Config              SimpleFabridConfig
	drkeyPathFn         func(context.Context, drkey.HostHostMeta) (drkey.HostHostKey, error)
	GrpcConn            *grpc.ClientConn
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

func NewFabridClient(remote snet.UDPAddr, config SimpleFabridConfig, grpcConn *grpc.ClientConn) *Client {
	state := &Client{
		Destination:         remote,
		validationRatio:     config.ValidationRatio,
		fabridControlBuffer: make([]byte, 20*3),
		Paths:               make(map[snet.PathFingerprint]*PathState),
		Config:              config,
		GrpcConn:            grpcConn,
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

func NewFabridServer(local *snet.UDPAddr, grpcConn *grpc.ClientConn) *Server {
	server := &Server{
		Local:       *local,
		grpcConn:    grpcConn,
		Connections: make(map[string]*ClientConnection),
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
	validationNumber, validationReply, success, err := VerifyPathValidator(fabridOption, client.tmpBuffer, client.pathKey[:])
	if err != nil {
		return nil, nil
	}
	s.ValidationHandler(client, identifierOption, success)

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
		log.Debug("Send validation response", "packetID", identifierOption.PacketID)
		validationReplyOpt := &extension.FabridControlOption{
			Timestamp: identifierOption.GetRelativeTimestamp(),
			PacketID:  identifierOption.PacketID,
		}
		replyOpts = append(replyOpts, validationReplyOpt)
		validationReplyOpt.Type = extension.ValidationResponse
		validationReplyOpt.Data = make([]byte, 20)
		// TODO: Removing testing code
		randInt := make([]byte, 1)
		crand.Read(randInt)
		if uint8(randInt[0]) < SERVER_FLAKINESS {
			validationReply ^= 0xFFFFFFFF
		}
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

func (c *Client) RenewPathKey(t time.Time) error {
	if c.PathKey.Epoch.NotAfter.Before(t) {
		// key is expired, renew it
		newKey, err := c.fetchHostHostKey(t)
		if err != nil {
			return err
		}
		c.PathKey = newKey
	}
	return nil
}

func (c *Client) fetchHostHostKey(t time.Time) (drkey.HostHostKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	drkeyClient := drpb.NewDRKeyIntraServiceClient(c.GrpcConn)
	meta := drkey.HostHostMeta{
		Validity: t,
		SrcIA:    c.Config.DestinationIA,
		SrcHost:  c.Config.DestinationAddr,
		DstIA:    c.Config.LocalIA,
		DstHost:  c.Config.LocalAddr,
		ProtoId:  drkey.FABRID,
	}
	rep, err := drkeyClient.DRKeyHostHost(ctx, drhelper.HostHostMetaToProtoRequest(meta))
	if err != nil {
		return drkey.HostHostKey{}, err
	}
	key, err := drhelper.GetHostHostKeyFromReply(rep, meta)
	if err != nil {
		return drkey.HostHostKey{}, err
	}
	return key, nil
}

func (c *Client) HandleFabridControlOption(fp snet.PathFingerprint, controlOption *extension.FabridControlOption) error {

	err := VerifyFabridControlValidator(controlOption, c.PathKey.Key[:])
	if err != nil {
		return err
	}
	ps, _ := c.Paths[fp]

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
		success := c.CheckValidationResponse(fp, validatorReply, controlOption.Timestamp, controlOption.PacketID)
		c.Config.ValidationHandler(ps, controlOption, success)
		//log.Debug("FABRID control: validation response", "packetID", controlOption.PacketID, "success", success)

	case extension.StatisticsResponse:
		totalPkts, invalidPkts, err := controlOption.Statistics()
		if err != nil {
			return err
		}
		log.Info("FABRID control: statistics response", "totalPackets", totalPkts, "invalidPackets", invalidPkts)
	}
	return nil
}

func (c *Client) StoreValidationResponse(fp snet.PathFingerprint, validator uint32, timestamp uint32, packetID uint32) error {
	ps, _ := c.Paths[fp]
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

func (c *Client) CheckValidationResponse(fp snet.PathFingerprint, validatorReply uint32, timestamp uint32, packetID uint32) bool {
	ps, _ := c.Paths[fp]
	valIdent := validationIdentifier{
		timestamp: timestamp,
		packetId:  packetID,
	}
	//log.Debug("Checking validation response", "timestamp", timestamp, "packetID", packetID)
	validatorStored, found := ps.expectedValResponses[valIdent]
	if found && validatorStored == validatorReply {
		return true
	}
	return false
}

func (c *Client) RequestStatistics() {
	for _, state := range c.Paths {
		state.RequestStatistics = true
	}
}
