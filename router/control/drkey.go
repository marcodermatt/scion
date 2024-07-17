// Copyright 2024 ETH Zurich
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

package control

import (
	"errors"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey/specific"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	pb "github.com/scionproto/scion/pkg/proto/drkey"
)

const pastValidity time.Duration = time.Second * 5

var errDRKeySecretInvalid = errors.New("no valid drkey secret for provided time period")
var errDRKeyNotInitialized = errors.New("drkey not initialized")

var nullByte = [16]byte{}

type DRKeyProvider struct {
	drKeySecrets [][2]*SecretValue
	// determines whether index 0 or index 1 should be overwritten next
	drKeySecretNextOverwrite []uint8
	mtx                      sync.Mutex
}

func (d *DRKeyProvider) Init() {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	log.Debug("Initialize DRKey provider")
	numDRKeyProtocols := len(pb.Protocol_value)
	d.drKeySecrets = make([][2]*SecretValue, numDRKeyProtocols)
	for i := 0; i < numDRKeyProtocols; i++ {
		d.drKeySecrets[i] = [2]*SecretValue{
			{},
			{},
		}
	}
	d.drKeySecretNextOverwrite = make([]uint8, numDRKeyProtocols)
}

func (d *DRKeyProvider) AddSecret(protocolID int32, sv SecretValue) error {
	if d == nil {
		return serrors.New("Error while adding new drkey. DRKeyProvider not initialized.")
	}
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.drKeySecrets == nil {
		return errDRKeyNotInitialized
	}
	if int(protocolID) > len(d.drKeySecrets) {
		return serrors.New("Error while adding a new drkey. ProtocolID too large",
			"protocolID", protocolID)
	}
	nextOverwrite := d.drKeySecretNextOverwrite[protocolID]
	d.drKeySecrets[protocolID][nextOverwrite] = &sv
	log.Debug("Registered new DRKey", "protocol", protocolID, "from", sv.EpochBegin,
		"to", sv.EpochEnd)
	// switch nextOverwrite from 0 to 1 or from 1 to 0
	d.drKeySecretNextOverwrite[protocolID] = 1 - nextOverwrite
	return nil
}

func (d *DRKeyProvider) getSecret(protocolID int32, t time.Time) (*SecretValue, error) {
	secrets := d.drKeySecrets[protocolID]
	since := time.Since(t)
	if since > pastValidity {
		return nil, serrors.New("time after validity window", "t", t, "since", since,
			"validityPeriod", pastValidity)
	}
	for _, sv := range secrets {
		if t.After(sv.EpochBegin) && sv.EpochEnd.After(t) {
			return sv, nil
		}
	}
	return nil, errDRKeySecretInvalid
}

func (d *DRKeyProvider) DeriveASASKey(protocolID int32, t time.Time, srcAS addr.IA) ([16]byte,
	error) {
	drv := specific.Deriver{}
	secret, err := d.getSecret(protocolID, t)
	if err != nil {
		return nullByte, err
	}
	asToAsKey, err := drv.DeriveLevel1(srcAS, secret.Key)
	if err != nil {
		return nullByte, err
	}
	return asToAsKey, nil
}

func (d *DRKeyProvider) DeriveASHostKey(protocolID int32, t time.Time, srcAS addr.IA, src string) (
	[16]byte, error) {

	drv := specific.Deriver{}
	asToAsKey, err := d.DeriveASASKey(protocolID, t, srcAS)
	if err != nil {
		return nullByte, err
	}
	asToHostKey, err := drv.DeriveASHost(src, asToAsKey)
	if err != nil {
		return nullByte, err
	}

	return asToHostKey, nil
}
