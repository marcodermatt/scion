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
	"sync"

	"github.com/scionproto/scion/pkg/experimental/helia"
	"github.com/scionproto/scion/pkg/log"
)

type Storage struct {
	pathsMu      sync.RWMutex
	paths        map[helia.RawPathFingerprint]*Path
	reservMu     sync.RWMutex
	reservations map[helia.Hop]*Reservation
}

type Path struct {
	Fingerprint helia.RawPathFingerprint
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
	store.paths = make(map[helia.RawPathFingerprint]*Path)
	store.reservations = make(map[helia.Hop]*Reservation)
}

func (store *Storage) StorePath(path *Path) {
	store.pathsMu.Lock()
	defer store.pathsMu.Unlock()
	store.paths[path.Fingerprint] = path
}

func (store *Storage) GetPath(fingerprint helia.RawPathFingerprint) (*Path, bool) {
	store.pathsMu.RLock()
	defer store.pathsMu.RUnlock()
	path, found := store.paths[fingerprint]
	return path, found
}

func (store *Storage) StoreReservation(reservation *Reservation) {
	store.reservMu.Lock()
	defer store.reservMu.Unlock()
	store.reservations[reservation.Hop] = reservation
}

func (store *Storage) GetReservation(hop helia.Hop) (*Reservation, bool) {
	store.reservMu.RLock()
	defer store.reservMu.RUnlock()
	reservation, found := store.reservations[hop]
	return reservation, found
}
func (store *Storage) CreateReservation(hop *helia.Hop, backward bool) {
	if backward {
		hop = &helia.Hop{
			IA:      hop.IA,
			Ingress: hop.Egress,
			Egress:  hop.Ingress,
		}
	}
	store.StoreReservation(
		&Reservation{
			Hop:           *hop,
			Status:        Initialized,
			Authenticator: nil,
			Timestamp:     0,
		},
	)
	log.Debug("Created reservation", "storage", hop)
}
