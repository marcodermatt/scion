// Copyright 2022 ETH Zurich
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

package processing

import (
	"time"

	"github.com/google/gopacket"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/experimental/heliagate/config"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
)

type Worker struct {
	CoreIdCounter  uint32
	NumCounterBits int

	LocalAS addr.AS
}

type dataPacket struct {
	pktArrivalTime time.Time
	scionLayer     *slayers.SCION
	scionPath      *scion.Raw
	rawPacket      []byte
}

func Parse(rawPacket []byte) (*dataPacket, error) {
	proc := dataPacket{
		rawPacket:  make([]byte, len(rawPacket)),
		scionLayer: &slayers.SCION{},
	}
	copy(proc.rawPacket, rawPacket)
	if err := proc.scionLayer.DecodeFromBytes(
		proc.rawPacket, gopacket.NilDecodeFeedback,
	); err != nil {
		return nil, err
	}
	var ok bool
	proc.scionPath, ok = proc.scionLayer.Path.(*scion.Raw)
	if !ok {
		return nil, serrors.New("Getting scion path failed")
	}
	return &proc, nil
}

// NewWorker initializes the worker with its id, tokenbuckets and reservations
func NewWorker(
	config *config.Heliagate, workerId uint32, gatewayId uint32, localAS addr.AS,
) *Worker {
	w := &Worker{
		CoreIdCounter:  (gatewayId << (32 - config.NumBitsForGatewayId)) | (workerId << (32 - config.NumBitsForGatewayId - config.NumBitsForWorkerId)),
		NumCounterBits: config.NumBitsForPerWorkerCounter,
		LocalAS:        localAS,
	}
	return w
}
