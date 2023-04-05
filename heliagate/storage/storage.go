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
	"crypto/sha256"
	"encoding/binary"
	"sync"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
)

// Storage for the heliagate manages Path structs which contain Hop fields.
// Each Hop can have a Reservation that stores necessary data for a helia reservation.
// These hops are
type Storage struct {
	pathsMu      sync.RWMutex
	paths        map[RawPathFingerprint]*Path
	reservMu     sync.RWMutex
	reservations map[Hop]*Reservation
}

// Path with a unique RawPathFingerprint that contains a list Hop fields.
type Path struct {
	Fingerprint RawPathFingerprint
	Hops        []Hop
}

// A Hop is the smallest part of a helia reservation at a specific AS from ingress interface
// to egress interface.
type Hop struct {
	IA      addr.IA
	Ingress uint16
	Egress  uint16
}

// Reservation contains all persistent data for a helia reservation at a specific Hop
type Reservation struct {
	Hop           Hop
	Status        ReservationStatus
	Timestamp     uint64
	Bandwidth     uint32
	Authenticator []byte
}

// ReservationStatus indicates whether the reservation has just been created, a request has been
// sent out, the reservation is valid, or the reservation has expired
type ReservationStatus uint8

const (
	Initialized ReservationStatus = iota
	RequestPending
	Available
	Expired
)

// RawPathFingerprint is a hash of the sequence of interfaces for a specific path, that can be
// calculated from raw SCION paths. This is only unique for paths with the same source AS.
type RawPathFingerprint string

// CalculateRawPathFingerprint takes a raw SCION path, and creates a hash of the sequence of
// interfaces on the path.
func CalculateRawPathFingerprint(path *scion.Raw) RawPathFingerprint {
	h := sha256.New()
	for idx := 0; idx < path.NumHops; idx++ {
		hf, _ := path.GetHopField(idx)
		err := binary.Write(h, binary.BigEndian, hf.ConsIngress)
		if err != nil {
			panic(err)
		}
		err = binary.Write(h, binary.BigEndian, hf.ConsEgress)
		if err != nil {
			panic(err)
		}
	}
	return RawPathFingerprint(h.Sum(nil))
}

// InitStorage initializes the reservation storage
func (store *Storage) InitStorage() {
	store.paths = make(map[RawPathFingerprint]*Path)
	store.reservations = make(map[Hop]*Reservation)
}

// StorePath write-locks the paths map and inserts the passed path
func (store *Storage) StorePath(path *Path) {
	store.pathsMu.Lock()
	defer store.pathsMu.Unlock()
	store.paths[path.Fingerprint] = path
}

// GetPath read-locks the paths map and returns the path with the passed fingerprint or nil, if
// it does not exist. Also returns an indicator variable whether the path was found.
func (store *Storage) GetPath(fingerprint RawPathFingerprint) (*Path, bool) {
	store.pathsMu.RLock()
	defer store.pathsMu.RUnlock()
	path, found := store.paths[fingerprint]
	return path, found
}

// StoreReservation write-locks the reservations map and inserts the passed reservation
func (store *Storage) StoreReservation(reservation *Reservation) {
	store.reservMu.Lock()
	defer store.reservMu.Unlock()
	store.reservations[reservation.Hop] = reservation
}

// GetReservation read-locks the reservations map and returns the reservation for the passed hop
// or nil, if it does not exist. Also returns an indicator variable if the reservation was found.
func (store *Storage) GetReservation(hop Hop) (Reservation, bool) {
	store.reservMu.RLock()
	defer store.reservMu.RUnlock()
	reservation, found := store.reservations[hop]
	if !found {
		return Reservation{}, false
	}
	return *reservation, found
}

// CreateReservation checks if a reservation already exists for this hop and if not,
// creates it with appropriate initial values.
func (store *Storage) CreateReservation(hop *Hop, backward bool) error {
	// swap ingress and egress IF, if it is a backwards reservation
	if backward {
		hop = &Hop{
			IA:      hop.IA,
			Ingress: hop.Egress,
			Egress:  hop.Ingress,
		}
	}
	store.reservMu.RLock()
	_, found := store.reservations[*hop]
	store.reservMu.RUnlock()
	if found {
		return serrors.New("Reservation already exists", "hop", hop)
	}
	store.StoreReservation(
		&Reservation{
			Hop:           *hop,
			Status:        Initialized,
			Authenticator: nil,
			Timestamp:     0,
		},
	)
	return nil
}
