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

package main

import (
	"context"

	"golang.org/x/sync/errgroup"

	"github.com/scionproto/scion/heliagate/processing"
	"github.com/scionproto/scion/pkg/experimental/heliagate/config"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/app"
	"github.com/scionproto/scion/private/app/launcher"
	"github.com/scionproto/scion/private/topology"
)

func main() {
	var cfg config.Config
	application := launcher.Application{
		TOMLConfig: &cfg,
		ShortName:  "SCION Helia Gateway",
		Main: func(ctx context.Context) error {
			return realMain(ctx, &cfg)
		},
	}
	application.Run()
}

func realMain(ctx context.Context, cfg *config.Config) error {
	topo, err := topology.NewLoader(
		topology.LoaderCfg{
			File:      cfg.General.Topology(),
			Reload:    app.SIGHUPChannel(ctx),
			Validator: &topology.DefaultValidator{},
			// Metrics: , // TODO(marcoder) add observability to the gateway
		},
	)
	if err != nil {
		return serrors.WrapStr("creating topology loader", err)
	}
	g, errCtx := errgroup.WithContext(ctx)
	g.Go(
		func() error {
			defer log.HandlePanic()
			return topo.Run(errCtx)
		},
	)

	var cleanup app.Cleanup
	log.Info("Heliagate: Service started")
	err = processing.Init(ctx, cfg, &cleanup, g, topo)
	if err != nil {
		return err
	}
	// cleanup when exit
	g.Go(
		func() error {
			defer log.HandlePanic()
			<-errCtx.Done()
			return cleanup.Do()
		},
	)
	return g.Wait()
}
