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

package common

import (
	"context"
	crand "crypto/rand"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/experimental/fabrid"
	"github.com/scionproto/scion/pkg/experimental/fabrid/crypto"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/extension"
	"github.com/scionproto/scion/pkg/snet"
	"time"
)

// Testing options for failing validation
const CLIENT_FLAKINESS = 0
const SERVER_FLAKINESS = 0

type SimpleFabridConfig struct {
	DestinationIA     addr.IA
	DestinationAddr   string
	LocalIA           addr.IA
	LocalAddr         string
	ValidationRatio   uint8
	Policy            fabrid.Policy
	ValidationHandler func(*PathState, *extension.FabridControlOption, bool) error
}

type Statistics struct {
	TotalPackets   uint32
	InvalidPackets uint32
}

type ClientConnection struct {
	Source              snet.SCIONAddress
	ValidationRatio     uint8
	Stats               Statistics
	fabridControlBuffer []byte
	tmpBuffer           []byte
	pathKey             drkey.Key
}

type Server struct {
	Local              snet.UDPAddr
	sdConn             daemon.Connector
	Connections        map[string]*ClientConnection
	ASKeyCache         map[addr.IA]drkey.HostASKey
	MaxValidationRatio uint8
	ValidationHandler  func(*ClientConnection, *extension.IdentifierOption, bool) error
}

type Client struct {
	Destination         snet.UDPAddr
	validationRatio     uint8
	fabridControlBuffer []byte
	PathKey             drkey.HostHostKey
	Paths               map[snet.PathFingerprint]*PathState
	Config              SimpleFabridConfig
	drkeyPathFn         func(context.Context, drkey.HostHostMeta) (drkey.HostHostKey, error)
	SDConn              daemon.Connector
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

func NewFabridClient(remote snet.UDPAddr, config SimpleFabridConfig,
	sdConn daemon.Connector) *Client {
	state := &Client{
		Destination:         remote,
		validationRatio:     config.ValidationRatio,
		fabridControlBuffer: make([]byte, 20*3),
		Paths:               make(map[snet.PathFingerprint]*PathState),
		Config:              config,
		SDConn:              sdConn,
	}
	return state
}

func (c *Client) NewFabridPathState(fingerprint snet.PathFingerprint) *PathState {
	state := &PathState{
		ValidationRatio:      c.validationRatio,
		UpdateValRatio:       false,
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

func NewFabridServer(local *snet.UDPAddr, sdConn daemon.Connector) *Server {
	server := &Server{
		Local:       *local,
		sdConn:      sdConn,
		Connections: make(map[string]*ClientConnection),
		ASKeyCache:  make(map[addr.IA]drkey.HostASKey),
		ValidationHandler: func(_ *ClientConnection, _ *extension.IdentifierOption, _ bool) error {
			return nil
		},
	}
	return server
}

func (s *Server) FetchHostHostKey(dstHost snet.SCIONAddress, validity time.Time) (drkey.Key, error) {
	meta := drkey.HostHostMeta{
		Validity: validity,
		SrcIA:    s.Local.IA,
		SrcHost:  s.Local.Host.IP.String(),
		DstIA:    dstHost.IA,
		DstHost:  dstHost.Host.IP().String(),
		ProtoId:  drkey.FABRID,
	}
	hostHostKey, err := s.sdConn.DRKeyGetHostHostKey(context.Background(), meta)
	if err != nil {
		return drkey.Key{}, serrors.WrapStr("getting host key", err)
	}
	return hostHostKey.Key, nil
}

func (s *Server) HandleFabridPacket(remote snet.SCIONAddress, fabridOption *extension.FabridOption,
	identifierOption *extension.IdentifierOption,
	controlOptions []*extension.FabridControlOption) (*slayers.EndToEndExtn, error) {
	client, found := s.Connections[remote.String()]
	if !found {
		pathKey, err := s.FetchHostHostKey(remote, identifierOption.Timestamp)
		if err != nil {
			return nil, err
		}
		client = &ClientConnection{
			Source:              remote,
			ValidationRatio:     255,
			Stats:               Statistics{},
			fabridControlBuffer: make([]byte, 28*3),
			tmpBuffer:           make([]byte, 192),
			pathKey:             pathKey,
		}
		s.Connections[remote.String()] = client
		log.Info("Opened new connection", "remote", remote.String())
	}

	client.Stats.TotalPackets++
	validationNumber, validationReply, success, err := crypto.VerifyPathValidator(fabridOption,
		client.tmpBuffer, client.pathKey[:])
	if err != nil {
		return nil, err
	}
	err = s.ValidationHandler(client, identifierOption, success)
	if err != nil {
		return nil, err
	}

	var replyOpts []*extension.FabridControlOption
	for _, controlOption := range controlOptions {
		err = crypto.VerifyFabridControlValidator(controlOption, identifierOption,
			client.pathKey[:])
		if err != nil {
			return nil, err
		}
		controlReplyOpt := &extension.FabridControlOption{}
		ts, _ := controlOption.Timestamp()
		controlReplyOpt.SetTimestamp(ts)
		packetID, _ := controlOption.PacketID()
		controlReplyOpt.SetPacketID(packetID)
		replyOpts = append(replyOpts, controlReplyOpt)

		switch controlOption.Type {
		case extension.ValidationConfig:
			requestedRatio, err := controlOption.ValidationRatio()
			if err != nil {
				return nil, err
			}
			if requestedRatio > s.MaxValidationRatio {
				log.Debug("FABRID control: requested ratio too large", "requested", requestedRatio,
					"max", s.MaxValidationRatio)
				requestedRatio = s.MaxValidationRatio
			}
			log.Debug("FABRID control: updated validation ratio", "new", requestedRatio,
				"old", client.ValidationRatio)
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
			err := controlReplyOpt.SetStatistics(client.Stats.TotalPackets,
				client.Stats.InvalidPackets)
			if err != nil {
				return nil, err
			}
		}
	}
	if validationNumber < client.ValidationRatio {
		log.Debug("Send validation response", "packetID", identifierOption.PacketID)
		validationReplyOpt := &extension.FabridControlOption{}
		validationReplyOpt.SetTimestamp(identifierOption.GetRelativeTimestamp())
		validationReplyOpt.SetPacketID(identifierOption.PacketID)
		replyOpts = append(replyOpts, validationReplyOpt)
		validationReplyOpt.Type = extension.ValidationResponse
		validationReplyOpt.Data = make([]byte, 20)
		// TODO: Remove testing code
		randInt := make([]byte, 1)
		crand.Read(randInt)
		if randInt[0] < SERVER_FLAKINESS {
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
			err = crypto.InitFabridControlValidator(replyOpt, identifierOption, client.pathKey[:])
			if err != nil {
				return nil, err
			}
			buffer := client.fabridControlBuffer[i*28 : (i+1)*28]
			err = replyOpt.SerializeTo(buffer)
			if err != nil {
				return nil, err
			}
			fabridReplyOptionLength := extension.BaseFabridControlLen +
				extension.FabridControlOptionDataLen(replyOpt.Type)
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
		newKey, err := c.FetchHostHostKey(t)
		if err != nil {
			return err
		}
		c.PathKey = newKey
	}
	return nil
}

func (c *Client) FetchHostHostKey(validity time.Time) (drkey.HostHostKey, error) {
	meta := drkey.HostHostMeta{
		Validity: validity,
		SrcIA:    c.Config.DestinationIA,
		SrcHost:  c.Config.DestinationAddr,
		DstIA:    c.Config.LocalIA,
		DstHost:  c.Config.LocalAddr,
		ProtoId:  drkey.FABRID,
	}
	hostHostKey, err := c.SDConn.DRKeyGetHostHostKey(context.Background(), meta)
	if err != nil {
		return drkey.HostHostKey{}, serrors.WrapStr("getting host key", err)
	}
	return hostHostKey, nil
}

func (c *Client) HandleFabridControlOption(fp snet.PathFingerprint,
	controlOption *extension.FabridControlOption,
	identifierOption *extension.IdentifierOption) error {

	err := crypto.VerifyFabridControlValidator(controlOption, identifierOption, c.PathKey.Key[:])
	if err != nil {
		return err
	}
	ps := c.Paths[fp]

	switch controlOption.Type {
	case extension.ValidationConfigAck:
		confirmedRatio, err := controlOption.ValidationRatio()
		if err != nil {
			return err
		}
		if confirmedRatio == ps.ValidationRatio {
			log.Debug("FABRID control: validation ratio confirmed", "ratio", confirmedRatio)
		} else if confirmedRatio < ps.ValidationRatio {
			log.Info("FABRID control: validation ratio reduced by server",
				"requested", ps.ValidationRatio, "confirmed", confirmedRatio)
			ps.ValidationRatio = confirmedRatio
		}
	case extension.ValidationResponse:
		err = c.CheckValidationResponse(fp, controlOption)
		if err != nil {
			return err
		}
		err = c.Config.ValidationHandler(ps, controlOption, true)
		if err != nil {
			return err
		}
		//log.Debug("FABRID control: validation response",
		//"packetID", controlOption.PacketID, "success", success)

	case extension.StatisticsResponse:
		totalPkts, invalidPkts, err := controlOption.Statistics()
		if err != nil {
			return err
		}
		log.Info("FABRID control: statistics response", "totalPackets", totalPkts,
			"invalidPackets", invalidPkts)
	}
	return nil
}

func (c *Client) StoreValidationResponse(fp snet.PathFingerprint, validator uint32,
	timestamp uint32, packetID uint32) error {
	ps := c.Paths[fp]
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

func (c *Client) CheckValidationResponse(fp snet.PathFingerprint,
	fco *extension.FabridControlOption) error {
	timestamp, err := fco.Timestamp()
	if err != nil {
		return err
	}
	packetID, err := fco.PacketID()
	if err != nil {
		return err
	}
	validatorReply, err := fco.PathValidatorReply()
	if err != nil {
		return err
	}
	ps := c.Paths[fp]
	valIdent := validationIdentifier{
		timestamp: timestamp,
		packetId:  packetID,
	}
	//log.Debug("Checking validation response", "timestamp", timestamp, "packetID", packetID)
	validatorStored, found := ps.expectedValResponses[valIdent]
	if !found {
		return serrors.New("Unknown validation response", "validationIdentifier", valIdent)
	}
	if validatorStored != validatorReply {
		return serrors.New("Wrong path validation response", "validationIdentifier", valIdent,
			"expected", validatorStored, "actual", validatorReply)
	}
	return nil
}

func (c *Client) RequestStatistics() {
	for _, state := range c.Paths {
		state.RequestStatistics = true
	}
}
