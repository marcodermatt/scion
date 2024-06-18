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

package path

import (
	"context"
	crand "crypto/rand"
	"github.com/scionproto/scion/pkg/log"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/experimental/fabrid"
	"github.com/scionproto/scion/pkg/experimental/fabrid/crypto"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/extension"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet"
)

type FabridConfig struct {
	LocalIA         addr.IA
	LocalAddr       string
	DestinationIA   addr.IA
	DestinationAddr string
}

type FABRID struct {
	Raw              []byte
	keys             map[addr.IA]*drkey.FabridKey
	pathKey          drkey.FabridKey
	getFabridKeys    func(context.Context, drkey.FabridKeysMeta) (drkey.FabridKeysResponse, error)
	conf             *FabridConfig
	counter          uint32
	baseTimestamp    uint32
	tmpBuffer        []byte
	identifierBuffer []byte
	fabridBuffer     []byte
	e2eBuffer        []byte
	numHops          int
	hops             []snet.HopInterface
	policyIDs        []*fabrid.PolicyID
	client           *fabrid.Client
	fingerprint      snet.PathFingerprint
}

func NewFABRIDDataplanePath(p SCION, hops []snet.HopInterface, policyIDs []*fabrid.PolicyID,
	conf *FabridConfig, client *fabrid.Client, fingerprint snet.PathFingerprint) (*FABRID, error) {
	numHops := len(hops)
	var decoded scion.Decoded
	if err := decoded.DecodeFromBytes(p.Raw); err != nil {
		return nil, serrors.WrapStr("decoding path", err)
	}
	//TODO(jvanbommel) How was this remove hops introduced by crossovers even supposed to work?
	// Decreasing the numHops would still add the hops to ingresses and egresses of crossovers
	// in the middle of the path, and even cut out the end of the path. What did I miss?
	keys := make(map[addr.IA]*drkey.FabridKey)
	if len(policyIDs) == 0 { // If no policies are provided, use empty policy for all hops
		policyIDs = make([]*fabrid.PolicyID, numHops)
	} else if len(policyIDs) != numHops {
		return nil, serrors.New("Amount of policy ids does not match the amount of hops in " +
			"the path.")
	}
	f := &FABRID{
		hops:             hops,
		numHops:          numHops,
		conf:             conf,
		keys:             keys,
		tmpBuffer:        make([]byte, 64),
		identifierBuffer: make([]byte, 8),
		fabridBuffer:     make([]byte, 8+4*numHops),
		e2eBuffer:        make([]byte, 5*2),
		Raw:              append([]byte(nil), p.Raw...),
		policyIDs:        policyIDs,
		client:           client,
		fingerprint:      fingerprint,
	}

	// Get ingress/egress IFs and IAs from path interfaces
	for i, hop := range hops {
		if policyIDs[i] != nil {
			f.keys[hop.IA] = &drkey.FabridKey{}
		}
	}
	f.baseTimestamp = decoded.InfoFields[0].Timestamp
	return f, nil
}

func (f *FABRID) RegisterDRKeyFetcher(
	getFabridKeys func(context.Context, drkey.FabridKeysMeta) (drkey.FabridKeysResponse, error)) {

	f.getFabridKeys = getFabridKeys
}

func (f *FABRID) SetPath(s *slayers.SCION) error {
	var sp scion.Raw
	if err := sp.DecodeFromBytes(f.Raw); err != nil {
		return err
	}
	s.Path, s.PathType = &sp, sp.Type()
	return nil
}
func (f *FABRID) SetExtensions(s *slayers.SCION, p *snet.PacketInfo) error {
	if s == nil {
		return serrors.New("scion layer is nil")
	}
	if p == nil {
		return serrors.New("packet info is nil")
	}
	if f.getFabridKeys == nil {
		return serrors.New("drkey not correctly configured")
	}
	if p.HbhExtension == nil {
		p.HbhExtension = &slayers.HopByHopExtn{}
	}
	now := time.Now().Truncate(time.Millisecond)
	err := f.renewExpiredKeys(now)
	if err != nil {
		return serrors.WrapStr("While obtaining fabrid keys", err)
	}
	identifierOption := &extension.IdentifierOption{
		Timestamp:     now,
		BaseTimestamp: f.baseTimestamp,
		PacketID:      f.counter,
	}
	fabridOption := &extension.FabridOption{
		HopfieldMetadata: make([]*extension.FabridHopfieldMetadata, f.numHops),
	}
	for i := 0; i < f.numHops; i++ {
		meta := &extension.FabridHopfieldMetadata{}
		if f.policyIDs[i] != nil && f.keys[f.hops[i].IA] != nil {
			meta.FabridEnabled = true
			key := f.keys[f.hops[i].IA].Key
			encPolicyID, err := crypto.EncryptPolicyID(*f.policyIDs[i], identifierOption, key[:])
			if err != nil {
				return serrors.WrapStr("encrypting policy ID", err)
			}
			meta.EncryptedPolicyID = encPolicyID
		}
		fabridOption.HopfieldMetadata[i] = meta
	}
	valNumber, pathValReply, err := crypto.InitValidators(fabridOption, identifierOption, s, f.tmpBuffer, f.pathKey.Key[:],
		f.keys, nil, f.hops)
	if err != nil {
		return serrors.WrapStr("initializing validators failed", err)
	}
	// TODO: Removing testing code
	randInt := make([]byte, 1)
	crand.Read(randInt)
	if uint8(randInt[0]) < fabrid.CLIENT_FLAKINESS {
		for i, b := range fabridOption.PathValidator {
			fabridOption.PathValidator[i] = b ^ 0xFF
		}
	}
	err = identifierOption.Serialize(f.identifierBuffer)
	if err != nil {
		return serrors.WrapStr("serializing identifier", err)
	}
	err = fabridOption.SerializeTo(f.fabridBuffer)
	if err != nil {
		return serrors.WrapStr("serializing fabrid option", err)
	}
	fabridLength := 4 + 4*f.numHops
	p.HbhExtension.Options = append(p.HbhExtension.Options,
		&slayers.HopByHopOption{
			OptType:      slayers.OptTypeIdentifier,
			OptData:      f.identifierBuffer,
			OptDataLen:   8,
			ActualLength: 8,
		},
		&slayers.HopByHopOption{
			OptType:      slayers.OptTypeFabrid,
			OptData:      f.fabridBuffer[:fabridLength],
			OptDataLen:   uint8(fabridLength),
			ActualLength: fabridLength,
		})

	pathState, _ := f.client.GetFabridPathState(f.fingerprint)

	if valNumber < pathState.ValidationRatio {
		err = f.client.StoreValidationResponse(f.fingerprint, pathValReply, identifierOption.GetRelativeTimestamp(), f.counter)
		if err != nil {
			return err
		}
	}

	var e2eOpts []*extension.FabridControlOption
	if pathState.UpdateValRatio {
		valConfigOption := &extension.FabridControlOption{
			Type:      extension.ValidationConfig,
			Auth:      [4]byte{},
			Timestamp: identifierOption.GetRelativeTimestamp(),
			PacketID:  identifierOption.PacketID,
			Data:      make([]byte, 1),
		}
		err = valConfigOption.SetValidationRatio(pathState.ValidationRatio)
		if err != nil {
			return err
		}
		e2eOpts = append(e2eOpts, valConfigOption)
		pathState.UpdateValRatio = false
		log.Debug("FABRID control: outgoing validation config", "valRatio", pathState.ValidationRatio)
	}
	if pathState.RequestStatistics {
		statisticsRequestOption := &extension.FabridControlOption{
			Type:      extension.StatisticsRequest,
			Auth:      [4]byte{},
			Timestamp: identifierOption.GetRelativeTimestamp(),
			PacketID:  identifierOption.PacketID,
		}

		e2eOpts = append(e2eOpts, statisticsRequestOption)
		pathState.RequestStatistics = false
		log.Debug("FABRID control: sending statistics request")
	}
	if len(e2eOpts) > 0 {
		if p.E2eExtension == nil {
			p.E2eExtension = &slayers.EndToEndExtn{}
		}
		for i, replyOpt := range e2eOpts {
			err = crypto.InitFabridControlValidator(replyOpt, f.client.PathKey.Key[:])
			if err != nil {
				return err
			}
			buffer := f.e2eBuffer[i*5 : (i+1)*5]
			err = replyOpt.SerializeTo(buffer)
			if err != nil {
				return err
			}
			fabridReplyOptionLength := extension.BaseFabridControlLen + extension.FabridControlOptionDataLen(replyOpt.Type)
			p.E2eExtension.Options = append(p.E2eExtension.Options,
				&slayers.EndToEndOption{
					OptType:      slayers.OptTypeFabridControl,
					OptData:      buffer,
					OptDataLen:   uint8(fabridReplyOptionLength),
					ActualLength: fabridReplyOptionLength,
				})
		}
	}

	f.counter++
	pathState.Stats.TotalPackets++
	return nil
}

// This function iterates over all on-path ASes and checks whether the keys are still valid.
// If it finds expired keys it marks them as expired and renews all expired keys at once.
func (f *FABRID) renewExpiredKeys(t time.Time) error {
	var expiredAses []addr.IA = nil
	for ia, key := range f.keys {
		if key.Epoch.NotAfter.Before(t) {
			// key is expired, mark as expired
			if expiredAses == nil {
				expiredAses = make([]addr.IA, 0, len(f.keys))
			}
			expiredAses = append(expiredAses, ia)
		}
	}
	isPathKeyExpired := f.pathKey.Epoch.NotAfter.Before(t)
	if expiredAses != nil || isPathKeyExpired {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		meta := drkey.FabridKeysMeta{
			SrcAS:    f.conf.LocalIA,
			SrcHost:  f.conf.LocalAddr,
			PathASes: expiredAses,
			DstAS:    f.conf.DestinationIA,
		}
		if isPathKeyExpired {
			meta.DstHost = &f.conf.DestinationAddr
		}
		keys, err := f.getFabridKeys(ctx, meta)
		if err != nil {
			return err
		}
		if isPathKeyExpired {
			f.pathKey = keys.PathKey
		}
		for i := range keys.ASHostKeys {
			f.keys[keys.ASHostKeys[i].AS] = &keys.ASHostKeys[i]
		}
	}
	return nil
}
