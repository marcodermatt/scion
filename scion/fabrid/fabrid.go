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
	"net/netip"
	"strings"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/app/path"
	"github.com/scionproto/scion/private/app/path/pathprobe"
	"github.com/scionproto/scion/private/path/pathpol"
)

// Result contains all the discovered paths.
type Result struct {
	LocalIA     addr.IA `json:"local_isd_as" yaml:"local_isd_as"`
	Destination addr.IA `json:"destination" yaml:"destination"`
	Policies    []Path  `json:"paths,omitempty" yaml:"paths,omitempty"`
}

// Policy holds information about the available policy.
type Path struct {
	FullPath        snet.Path       `json:"-" yaml:"-"`
	Fingerprint     string          `json:"fingerprint" yaml:"fingerprint"`
	Hops            []Hop           `json:"hops" yaml:"hops"`
	Sequence        string          `json:"sequence" yaml:"sequence"`
	NextHop         string          `json:"next_hop" yaml:"next_hop"`
	Expiry          time.Time       `json:"expiry" yaml:"expiry"`
	MTU             uint16          `json:"mtu" yaml:"mtu"`
	Latency         []time.Duration `json:"latency" yaml:"latency"`
	CarbonIntensity []int64         `json:"carbon_intensity"`
	Status          string          `json:"status,omitempty" yaml:"status,omitempty"`
	StatusInfo      string          `json:"status_info,omitempty" yaml:"status_info,omitempty"`
	Local           netip.Addr      `json:"local_ip,omitempty" yaml:"local_ip,omitempty"`
}

// Hop represents an hop on the path.
type Hop struct {
	IfID common.IFIDType `json:"ifid"`
	IA   addr.IA         `json:"isd_as"`
}

// Run lists information for FABRID policies to stdout.
func Run(ctx context.Context, dst addr.IA, cfg Config) (*Result, error) {
	sdConn, err := daemon.NewService(cfg.Daemon).Connect(ctx)
	if err != nil {
		return nil, serrors.WrapStr("connecting to the SCION Daemon", err, "addr", cfg.Daemon)
	}
	defer sdConn.Close()
	localIA, err := sdConn.LocalIA(ctx)
	if err != nil {
		return nil, serrors.WrapStr("determining local ISD-AS", err)
	}

	allPaths, err := sdConn.RemotePolicyDescription()
	if err != nil {
		return nil, serrors.WrapStr("retrieving paths from the SCION Daemon", err)
	}
	paths, err := path.Filter(cfg.Sequence, allPaths)
	if err != nil {
		return nil, err
	}
	if cfg.MaxPaths != 0 && len(paths) > cfg.MaxPaths {
		paths = paths[:cfg.MaxPaths]
	}

	// If the epic flag is set, filter all paths that do not have
	// the necessary epic authenticators.
	if cfg.Epic {
		epicPaths := []snet.Path{}
		for _, p := range paths {
			if p.Metadata().EpicAuths.SupportsEpic() {
				epicPaths = append(epicPaths, p)
			}
		}
		paths = epicPaths
	}

	var statuses map[string]pathprobe.Status
	if !cfg.NoProbe {
		p := pathprobe.FilterEmptyPaths(paths)
		statuses, err = pathprobe.Prober{
			DstIA:    dst,
			LocalIA:  localIA,
			LocalIP:  cfg.Local,
			Topology: sdConn,
		}.GetStatuses(ctx, p, pathprobe.WithEPIC(cfg.Epic))
		if err != nil {
			return nil, serrors.WrapStr("getting statuses", err)
		}
	}
	path.Sort(paths)
	res := &Result{
		LocalIA:     localIA,
		Destination: dst,
		Paths:       []Path{},
	}
	for _, path := range paths {
		fingerprint := "local"
		if len(path.Metadata().Interfaces) > 0 {
			fp := snet.Fingerprint(path).String()
			fingerprint = fp[:16]
		}
		var nextHop string
		if nh := path.UnderlayNextHop(); nh != nil {
			nextHop = path.UnderlayNextHop().String()
		}
		pathMeta := path.Metadata()
		rpath := Path{
			FullPath:        path,
			Fingerprint:     fingerprint,
			NextHop:         nextHop,
			Expiry:          pathMeta.Expiry,
			MTU:             pathMeta.MTU,
			Latency:         pathMeta.Latency,
			CarbonIntensity: pathMeta.CarbonIntensity,
			Hops:            []Hop{},
		}
		for _, hop := range path.Metadata().Interfaces {
			rpath.Hops = append(rpath.Hops, Hop{IA: hop.IA, IfID: hop.ID})
		}
		if status, ok := statuses[pathprobe.PathKey(path)]; ok {
			rpath.Status = strings.ToLower(string(status.Status))
			rpath.StatusInfo = status.AdditionalInfo
			rpath.Local = status.LocalIP
		}
		seq, err := pathpol.GetSequence(path)
		rpath.Sequence = seq
		if err != nil {
			rpath.Sequence = "invalid"
		}
		res.Paths = append(res.Paths, rpath)
	}
	return res, nil
}
