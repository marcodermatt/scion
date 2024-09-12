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
	"fmt"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/private/serrors"
)

// Result contains all the discovered paths.
type Result struct {
	Destination addr.IA `json:"destination" yaml:"destination"`
	Description string  `json:"description,omitempty" yaml:"description,omitempty"`
}

// Run lists information for FABRID policies to stdout.
func Run(ctx context.Context, dst addr.IA, cfg Config) (*Result, error) {
	sdConn, err := daemon.NewService(cfg.Daemon).Connect(ctx)
	if err != nil {
		return nil, serrors.WrapStr("connecting to the SCION Daemon", err, "addr", cfg.Daemon)
	}
	defer sdConn.Close()

	description, err := sdConn.RemotePolicyDescription(ctx, 10, dst)
	if err != nil {
		return nil, serrors.WrapStr("retrieving description from the SCION Daemon", err)
	}
	fmt.Println(description)
	return &Result{Destination: dst, Description: description}, nil
}
