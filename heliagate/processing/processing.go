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

	"github.com/scionproto/scion/heliagate/config"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers"
	"golang.org/x/mod/sumdb/storage"
)

type Worker struct {
	CoreIdCounter  uint32
	NumCounterBits int

	Storage *storage.Storage
	LocalAS addr.AS
}

type dataPacket struct {
	pktArrivalTime time.Time
	scionLayer     *slayers.SCION
	//reservation
	rawPacket []byte
}

// NewWorker initializes the worker with its id, tokenbuckets and reservations
func NewWorker(
	config *config.Heliagate, workerId uint32, gatewayId uint32, localAS addr.AS,
) *Worker {
	w := &Worker{
		CoreIdCounter:  (gatewayId << (32 - config.NumBitsForGatewayId)) | (workerId << (32 - config.NumBitsForGatewayId - config.NumBitsForWorkerId)),
		NumCounterBits: config.NumBitsForPerWorkerCounter,
		LocalAS:        localAS,
		Storage:        &storage.Storage{},
	}
	w.Storage.InitStorageWithData(nil)
	return w
}
