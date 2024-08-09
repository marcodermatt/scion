// Copyright 2020 Anapaya Systems
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
	"fmt"
	"net"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/app"
	"github.com/scionproto/scion/private/app/flag"
	"github.com/scionproto/scion/private/tracing"
	"github.com/scionproto/scion/scion/fabrid"
	"github.com/spf13/cobra"
)

func newFabrid(pather CommandPather) *cobra.Command {
	var envFlags flag.SCIONEnvironment
	var flags struct {
		timeout  time.Duration
		cfg      fabrid.Config
		extended bool
		json     bool
		logLevel string
		noColor  bool
		tracer   string
		format   string
	}

	var cmd = &cobra.Command{
		Use:   "fabrid",
		Short: "Display FABRID policy information",
		Args:  cobra.ExactArgs(1),
		Example: fmt.Sprintf(`  %[1]s showpaths 1-ff00:0:110 --extended
  %[1]s showpaths 1-ff00:0:110 --local 127.0.0.55 --json
  %[1]s showpaths 1-ff00:0:111 --sequence="0-0#2 0*" # outgoing IfID=2
  %[1]s showpaths 1-ff00:0:111 --sequence="0* 0-0#41" # incoming IfID=41 at dstIA
  %[1]s showpaths 1-ff00:0:111 --sequence="0* 1-ff00:0:112 0*" # 1-ff00:0:112 on the path
  %[1]s showpaths 1-ff00:0:110 --no-probe`, pather.CommandPath()),
		Long: `'fabrid' lists available policies at a remote AS, or shows the
description of a specific policy.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			dst, err := addr.ParseIA(args[0])
			if err != nil {
				return serrors.WrapStr("invalid destination ISD-AS", err)
			}
			if err := app.SetupLog(flags.logLevel); err != nil {
				return serrors.WrapStr("setting up logging", err)
			}
			closer, err := setupTracer("fabrid", flags.tracer)
			if err != nil {
				return serrors.WrapStr("setting up tracing", err)
			}
			defer closer()

			if flags.json && !cmd.Flags().Lookup("format").Changed {
				flags.format = "json"
			}
			printf, err := getPrintf(flags.format, cmd.OutOrStdout())
			if err != nil {
				return serrors.WrapStr("get formatting", err)
			}

			cmd.SilenceUsage = true

			if err := envFlags.LoadExternalVars(); err != nil {
				return err
			}

			flags.cfg.Daemon = envFlags.Daemon()
			flags.cfg.Local = net.IP(envFlags.Local().AsSlice())
			log.Debug("Resolved SCION environment flags",
				"daemon", flags.cfg.Daemon,
				"local", flags.cfg.Local,
			)

			span, traceCtx := tracing.CtxWith(context.Background(), "run")
			span.SetTag("dst.isd_as", dst)
			defer span.Finish()

			ctx, cancel := context.WithTimeout(traceCtx, flags.timeout)
			defer cancel()
			res, err := fabrid.Run(ctx, dst, flags.cfg)
			if err != nil {
				return err
			}

			switch flags.format {
			case "human":
				if res.IsLocal() {
					printf("Empty path, destination is local AS %s\n", res.Destination)
					return nil
				}
				printf("Available policies at %s\n", res.Destination)
				if len(res.Paths) == 0 {
					return app.WithExitCode(serrors.New("no policies found"), 1)
				}
				res.Human(cmd.OutOrStdout(), flags.extended, !flags.noColor)
			case "json":
				return serrors.New("Not implemented", "format", flags.format)
			case "yaml":
				return serrors.New("Not implemented", "format", flags.format)
			default:
				return serrors.New("output format not supported", "format", flags.format)
			}
			return nil
		},
	}

	envFlags.Register(cmd.Flags())
	cmd.Flags().DurationVar(&flags.timeout, "timeout", 5*time.Second, "Timeout")
	cmd.Flags().StringVar(&flags.cfg.Sequence, "sequence", "", app.SequenceUsage)
	cmd.Flags().IntVarP(&flags.cfg.MaxPaths, "maxpaths", "m", 10,
		"Maximum number of paths that are displayed")
	cmd.Flags().BoolVarP(&flags.extended, "extended", "e", false,
		"Show extended path meta data information")
	cmd.Flags().BoolVarP(&flags.cfg.Refresh, "refresh", "r", false,
		"Set refresh flag for SCION Daemon path request")
	cmd.Flags().BoolVar(&flags.cfg.NoProbe, "no-probe", false,
		"Do not probe the paths and print the health status")
	cmd.Flags().BoolVarP(&flags.json, "json", "j", false,
		"Write the output as machine readable json")
	cmd.Flags().StringVar(&flags.format, "format", "human",
		"Specify the output format (human|json|yaml)")
	cmd.Flags().BoolVar(&flags.noColor, "no-color", false, "disable colored output")
	cmd.Flags().StringVar(&flags.logLevel, "log.level", "", app.LogLevelUsage)
	cmd.Flags().StringVar(&flags.tracer, "tracing.agent", "", "Tracing agent address")
	cmd.Flags().BoolVar(&flags.cfg.Epic, "epic", false, "Enable EPIC.")
	err := cmd.Flags().MarkDeprecated("json", "json flag is deprecated, use format flag")
	if err != nil {
		panic(err)
	}
	return cmd
}
