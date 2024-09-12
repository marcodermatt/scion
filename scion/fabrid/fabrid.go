// Copyright 2018 ETH Zurich, Anapaya Systems
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
	"context"
	"encoding/json"
	"fmt"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/private/serrors"
	"io/ioutil"
	"net/http"
)

// Result contains all the discovered paths.
type Result struct {
	Destination *addr.IA `json:"destination" yaml:"destination"`
	Description string   `json:"description,omitempty" yaml:"description,omitempty"`
}

// Run lists information for FABRID policies to stdout.
func Run(ctx context.Context, dst *addr.IA, identifier uint32, cfg Config) (*Result, error) {
	var description string
	if dst != nil {
		sdConn, err := daemon.NewService(cfg.Daemon).Connect(ctx)
		if err != nil {
			return nil, serrors.WrapStr("connecting to the SCION Daemon", err, "addr", cfg.Daemon)
		}
		defer sdConn.Close()

		description, err = sdConn.RemotePolicyDescription(ctx, identifier, *dst)
		if err != nil {
			return nil, serrors.WrapStr("retrieving description from the SCION Daemon", err)
		}
	} else {
		// Replace with the raw URL of your GitHub content (e.g., https://raw.githubusercontent.com/user/repo/branch/path/to/policies.json)
		globalPolicyURL := "https://raw.githubusercontent.com/marcodermatt/fabrid-global-policies/main/policy-descriptions.json"

		// Fetch the global policy from the URL
		policy, err := FetchGlobalPolicy(globalPolicyURL)
		if err != nil {
			return nil, serrors.WrapStr("fetching global policy", err)
		}

		// Retrieve the description for the given identifier
		description, err = GetPolicyDescription(policy, identifier)
		if err != nil {
			return nil, serrors.WrapStr("getting global policy description", err)
		}

	}
	// Output the description
	fmt.Printf("Policy %d: %s\n", identifier, description)
	return &Result{Destination: dst, Description: description}, nil
}

// GlobalPolicy holds the mapping of uint32 identifiers to their string descriptions
type GlobalPolicy map[uint32]string

// FetchGlobalPolicy fetches and parses the global policy from the given URL
func FetchGlobalPolicy(url string) (GlobalPolicy, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, serrors.WrapStr("failed to fetch global policy", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, serrors.New("failed to fetch global policy", "StatusCode", resp.StatusCode)
	}

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, serrors.WrapStr("failed to read response body", err)
	}

	// Unmarshal the JSON data into a map
	var policy GlobalPolicy
	if err = json.Unmarshal(body, &policy); err != nil {
		return nil, serrors.WrapStr("failed to unmarshal policy JSON", err)
	}

	return policy, nil
}

// GetPolicyDescription retrieves the description for the given identifier
func GetPolicyDescription(policy GlobalPolicy, identifier uint32) (string, error) {
	description, exists := policy[identifier]
	if !exists {
		return "", serrors.New("no policy found", "identifier", identifier)
	}
	return description, nil
}
