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
	keys             map[addr.IA]drkey.ASHostKey
	ingresses        []uint16
	egresses         []uint16
	drkeyFn          func(context.Context, drkey.ASHostMeta) (drkey.ASHostKey, error)
	conf             *FabridConfig
	counter          uint32
	baseTimestamp    uint32
	tmpBuffer        []byte
	identifierBuffer []byte
	fabridBuffer     []byte
	e2eBuffer        []byte
	numHops          int
	policyIDs        []*fabrid.FabridPolicyID
	ias              []addr.IA
	support          map[addr.IA]bool
	client           *fabrid.Client
	fingerprint      snet.PathFingerprint
}

func NewFABRIDDataplanePath(p SCION, interfaces []snet.PathInterface, policyIDsPerHop []snet.FabridPolicyPerHop, conf *FabridConfig, client *fabrid.Client, fingerprint snet.PathFingerprint) (*FABRID, error) {

	var decoded scion.Decoded
	if err := decoded.DecodeFromBytes(p.Raw); err != nil {
		return nil, serrors.WrapStr("decoding path", err)
	}
	numSegs := len(decoded.InfoFields)
	var numHops int
	if isPeering(decoded) {
		numHops = len(decoded.HopFields)
	} else {
		numHops = len(decoded.HopFields) - numSegs + 1 // Remove hops introduced by crossovers
	}
	keys := make(map[addr.IA]drkey.ASHostKey, len(policyIDsPerHop))
	var policyIDs []*fabrid.FabridPolicyID
	var ias []addr.IA
	if len(policyIDsPerHop) > 0 {
		policyIDs, ias = policiesToHopFields(numHops, policyIDsPerHop, decoded, keys)
	} else {
		// If no policies are provided, use zero policy for all hops
		policyIDs = make([]*fabrid.FabridPolicyID, numHops)
		for i := 0; i < numHops; i++ {
			policyIDs[i] = &fabrid.FabridPolicyID{ID: 0}
		}
		ias = make([]addr.IA, numHops)

	}
	f := &FABRID{
		numHops:          numHops,
		conf:             conf,
		keys:             keys,
		ias:              ias,
		ingresses:        make([]uint16, numHops),
		egresses:         make([]uint16, numHops),
		tmpBuffer:        make([]byte, 64),
		identifierBuffer: make([]byte, 8),
		fabridBuffer:     make([]byte, 8+4*numHops),
		e2eBuffer:        make([]byte, 5*2),
		support:          make(map[addr.IA]bool),
		Raw:              append([]byte(nil), p.Raw...),
		policyIDs:        policyIDs,
		client:           client,
		fingerprint:      fingerprint,
	}

	// Get ingress/egress IFs and IAs from path interfaces
	f.ingresses[0] = 0
	f.egresses[0] = uint16(interfaces[0].ID)
	f.ias[0] = interfaces[0].IA
	f.keys[f.ias[0]] = drkey.ASHostKey{}
	for i := 1; i < numHops-1; i++ {
		f.ingresses[i] = uint16(interfaces[2*i-1].ID)
		f.egresses[i] = uint16(interfaces[2*i].ID)
		f.ias[i] = interfaces[2*i-1].IA
		f.keys[f.ias[i]] = drkey.ASHostKey{}
	}
	f.ingresses[numHops-1] = uint16(interfaces[(numHops-1)*2-1].ID)
	f.egresses[numHops-1] = 0
	f.ias[numHops-1] = interfaces[(numHops-1)*2-1].IA
	f.keys[f.ias[numHops-1]] = drkey.ASHostKey{}
	for _, ia := range ias {
		f.support[ia] = true
	}
	f.baseTimestamp = decoded.InfoFields[0].Timestamp
	return f, nil
}

func isPeering(path scion.Decoded) bool {
	// Explicit check for assumption that peering paths can only have 2 segments
	return path.NumINF == 2 && path.InfoFields[0].Peer && path.InfoFields[1].Peer
}

func hfEqual(consDir bool, consIngress, consEgress, compIngress, compEgress uint16) bool {
	return (consIngress == compIngress && consEgress == compEgress && consDir) ||
		(consIngress == compEgress && consEgress == compIngress && !consDir)
}

func policiesToHopFields(numHops int, policyIDs []snet.FabridPolicyPerHop, decoded scion.Decoded,
	keys map[addr.IA]drkey.ASHostKey) ([]*fabrid.FabridPolicyID, []addr.IA) {
	polIds := make([]*fabrid.FabridPolicyID, numHops)
	ias := make([]addr.IA, numHops)
	hfIdx := 0
	log.Debug("Policy conversion", "policyIDs", policyIDs)
	ifIdx := 0
	polIdx := 0

	for _, seglen := range decoded.PathMeta.SegLen {
		for seg := uint8(0); seg < seglen; seg++ {
			if polIdx >= len(policyIDs) {
				break
			}
			keys[policyIDs[polIdx].IA] = drkey.ASHostKey{}
			hfOneToOne := hfIdx < numHops && hfEqual(decoded.InfoFields[ifIdx].ConsDir,
				decoded.HopFields[hfIdx].ConsIngress,
				decoded.HopFields[hfIdx].ConsEgress,
				policyIDs[polIdx].Ingress,
				policyIDs[polIdx].Egress)

			log.Debug("HFPol", "hfIdx", hfIdx, "hhfOneToOne", hfOneToOne, "consDir", decoded.InfoFields[ifIdx].ConsDir, "hopField", decoded.HopFields[hfIdx], "policyIDs", policyIDs[polIdx])

			if hfOneToOne {
				if policyIDs[polIdx].Pol == nil {
					polIds[hfIdx] = nil
					log.Debug("HF not using a policy", "hfIdx", hfIdx)

				} else {
					polIds[hfIdx] = &fabrid.FabridPolicyID{
						ID: policyIDs[polIdx].Pol.Index,
					}
					log.Debug("HF uses a policy", "hfIdx", hfIdx, "policy index", policyIDs[polIdx].Pol.Index, "IA", policyIDs[polIdx].IA)

				}
				ias[hfIdx] = policyIDs[polIdx].IA
			} else {
				polIds[hfIdx] = nil
				ias[hfIdx] = policyIDs[polIdx].IA
				log.Debug("HF uses nil policy", "hfIdx", hfIdx)
			}
			hfIdx++
			polIdx++
		}
		ifIdx++
	}
	//for _, policy := range policyIDs {
	//
	//}
	return polIds, ias
}

func (f *FABRID) RegisterDRKeyFetcher(fn func(context.Context, drkey.ASHostMeta) (drkey.ASHostKey, error)) {
	f.drkeyFn = fn
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
	if p.HbhExtension == nil {
		p.HbhExtension = &slayers.HopByHopExtn{}
	}
	now := time.Now().Truncate(time.Millisecond)
	err := f.renewExpiredKeys(now)
	if err != nil {
		return serrors.WrapStr("While obtaining fabrid keys", err)
	}
	err = f.client.RenewPathKey(now)
	if err != nil {
		return err
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
		if f.policyIDs[i] == nil {
			fabridOption.HopfieldMetadata[i] = &extension.FabridHopfieldMetadata{}
			continue
		}
		meta := &extension.FabridHopfieldMetadata{}
		if f.support[f.ias[i]] {
			meta.FabridEnabled = true

			key := f.keys[f.ias[i]].Key
			encPolicyID, err := fabrid.EncryptPolicyID(f.policyIDs[i], identifierOption, key[:])
			if err != nil {
				return serrors.WrapStr("encrypting policy ID", err)
			}
			meta.EncryptedPolicyID = encPolicyID
		}
		fabridOption.HopfieldMetadata[i] = meta
	}
	valNumber, pathValReply, err := fabrid.InitValidators(fabridOption, identifierOption, s, f.tmpBuffer, f.client.PathKey.Key[:], f.keys, nil, f.ias, f.ingresses, f.egresses)
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

	if valNumber <= pathState.ValidationRatio {
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
			err = fabrid.InitFabridControlValidator(replyOpt, f.client.PathKey.Key[:])
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

func (f *FABRID) renewExpiredKeys(t time.Time) error {
	for ia, key := range f.keys {
		if f.support[ia] {
			if key.Epoch.NotAfter.Before(t) {
				// key is expired, renew it
				newKey, err := f.fetchKey(t, ia)
				if err != nil {
					f.support[ia] = false
					log.Error("Error while fetching drkey", "IA", ia)
					continue
				}
				log.Debug("Successfully fetched drkey", "IA", ia)
				f.keys[ia] = newKey
			}
		}
	}
	return nil
}
func (f *FABRID) fetchKey(t time.Time, ia addr.IA) (drkey.ASHostKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	key, err := f.drkeyFn(ctx, drkey.ASHostMeta{
		Validity: t,
		SrcIA:    ia,
		DstIA:    f.conf.LocalIA,
		DstHost:  f.conf.LocalAddr,
		ProtoId:  drkey.FABRID,
	})
	if err != nil {
		return drkey.ASHostKey{}, err
	}
	return key, nil
}
