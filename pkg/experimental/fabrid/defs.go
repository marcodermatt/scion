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

package fabrid

import (
	"fmt"
	"time"

	fabrid_ext "github.com/scionproto/scion/pkg/segment/extensions/fabrid"
)

type PolicyID uint8

type Policy struct {
	IsLocal    bool
	Identifier uint32
	Index      PolicyID
}

func (fpi *Policy) String() string {
	if fpi.IsLocal {
		return fmt.Sprintf("L%d", fpi.Identifier)
	} else {
		return fmt.Sprintf("G%d", fpi.Identifier)
	}
}

// We go through the list of ASEntries and store for each IA a pointer to the FABRID
// Map found in the ASEntries' extensions.  If there is already a map stored, check the info time,
// and replace with the newer FABRID maps. This results in a map[IA]FabridMapEntry, which can be
// used to find the policies that are available for each of the interface pairs on the path.
type FabridMapEntry struct {
	Map *fabrid_ext.Detached
	Ts  time.Time
	// The Digest of the Fabrid Maps, this can be empty.
	Digest []byte
}
