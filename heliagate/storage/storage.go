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

package storage

import (
	"github.com/scionproto/scion/pkg/experimental/helia"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/snet"
)

type Storage struct {
	Paths        map[snet.PathFingerprint]*Path
	Reservations map[helia.Hop]*Reservation
}

type Path struct {
	Fingerprint snet.PathFingerprint
	Hops        []helia.Hop
}

type ReservationStatus uint8

const (
	Initialized ReservationStatus = iota
	RequestPending
	Available
	Expired
)

type Reservation struct {
	Hop    helia.Hop
	Status ReservationStatus
	//Token (only extended AES key, does not change during renewal)
	Authenticator []byte
	Timestamp     uint64
}

// InitStorage initializes the reservation storage
func (store *Storage) InitStorage() {
	store.Paths = make(map[snet.PathFingerprint]*Path)
	store.Reservations = make(map[helia.Hop]*Reservation)
}

func (store *Storage) StorePath(path *Path) {
	store.Paths[path.Fingerprint] = path
}

func (store *Storage) CreateReservation(hop *helia.Hop, backward bool) {
	if backward {
		hop = &helia.Hop{
			IA:      hop.IA,
			Ingress: hop.Egress,
			Egress:  hop.Ingress,
		}
	}
	store.Reservations[*hop] = &Reservation{
		Hop:           *hop,
		Status:        Initialized,
		Authenticator: nil,
		Timestamp:     0,
	}
	log.Debug("Created reservation", "storage", store.Reservations[*hop])
}
