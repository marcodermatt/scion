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
	"encoding/json"
	"fmt"
	"github.com/scionproto/scion/pkg/experimental/fabrid"
	"math"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"gopkg.in/yaml.v2"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	drhelper "github.com/scionproto/scion/pkg/daemon/helper"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	drpb "github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/addrutil"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/pkg/sock/reliable"
	"github.com/scionproto/scion/private/app"
	"github.com/scionproto/scion/private/app/flag"
	"github.com/scionproto/scion/private/app/path"
	"github.com/scionproto/scion/private/path/pathpol"
	"github.com/scionproto/scion/private/tracing"
	"github.com/scionproto/scion/scion/ping"
)

type Result struct {
	Path            Path         `json:"path" yaml:"path"`
	PayloadSize     int          `json:"payload_size" yaml:"payload_size"`
	ScionPacketSize int          `json:"scion_packet_size" yaml:"scion_packet_size"`
	Replies         []PingUpdate `json:"replies" yaml:"replies"`
	Statistics      Stats        `json:"statistics" yaml:"statistics"`
}

type Stats struct {
	ping.Stats `yaml:",inline"`
	Loss       int            `json:"packet_loss" yaml:"packet_loss"`
	Time       durationMillis `json:"time" yaml:"time"`
	MinRTT     durationMillis `json:"min_rtt" yaml:"min_rtt"`
	AvgRTT     durationMillis `json:"avg_rtt" yaml:"avg_rtt"`
	MaxRTT     durationMillis `json:"max_rtt" yaml:"max_rtt"`
	MdevRTT    durationMillis `json:"mdev_rtt" yaml:"mdev_rtt"`
}

type PingUpdate struct {
	Size     int            `json:"scion_packet_size" yaml:"scion_packet_size"`
	Source   string         `json:"source" yaml:"source"`
	Sequence int            `json:"scmp_seq" yaml:"scmp_seq"`
	RTT      durationMillis `json:"round_trip_time" yaml:"round_trip_time"`
	State    string         `json:"state" yaml:"state"`
}

func newPing(pather CommandPather) *cobra.Command {
	var envFlags flag.SCIONEnvironment
	var flags struct {
		count       uint16
		features    []string
		interactive bool
		interval    time.Duration
		logLevel    string
		maxMTU      bool
		noColor     bool
		refresh     bool
		healthyOnly bool
		sequence    string
		size        uint
		pktSize     uint
		timeout     time.Duration
		tracer      string
		epic        bool
		format      string
		fabrid      bool
	}

	var cmd = &cobra.Command{
		Use:   "ping [flags] <remote>",
		Short: "Test connectivity to a remote SCION host using SCMP echo packets",
		Example: fmt.Sprintf(`  %[1]s ping 1-ff00:0:110,10.0.0.1
  %[1]s ping 1-ff00:0:110,10.0.0.1 -c 5`, pather.CommandPath()),
		Long: fmt.Sprintf(`'ping' test connectivity to a remote SCION host using SCMP echo packets.

When the \--count option is set, ping sends the specified number of SCMP echo packets
and reports back the statistics.

When the \--healthy-only option is set, ping first determines healthy paths through probing and
chooses amongst them.

If no reply packet is received at all, ping will exit with code 1.
On other errors, ping will exit with code 2.

%s`, app.SequenceHelp),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			remote, err := snet.ParseUDPAddr(args[0])
			if err != nil {
				return serrors.WrapStr("parsing remote", err)
			}
			if err := app.SetupLog(flags.logLevel); err != nil {
				return serrors.WrapStr("setting up logging", err)
			}
			closer, err := setupTracer("ping", flags.tracer)
			if err != nil {
				return serrors.WrapStr("setting up tracing", err)
			}
			defer closer()
			printf, err := getPrintf(flags.format, cmd.OutOrStdout())
			if err != nil {
				return serrors.WrapStr("get formatting", err)
			}

			cmd.SilenceUsage = true

			if err := envFlags.LoadExternalVars(); err != nil {
				return err
			}
			daemonAddr := envFlags.Daemon()
			dispatcher := envFlags.Dispatcher()
			localIP := net.IP(envFlags.Local().AsSlice())
			log.Debug("Resolved SCION environment flags",
				"daemon", daemonAddr,
				"dispatcher", dispatcher,
				"local", localIP,
			)

			if localIP == nil {
				target := remote.Host.IP
				if remote.NextHop != nil {
					target = remote.NextHop.IP
				}
				if localIP, err = addrutil.ResolveLocal(target); err != nil {
					return serrors.WrapStr("resolving local address", err)
				}
			}
			span, traceCtx := tracing.CtxWith(context.Background(), "run")
			span.SetTag("dst.isd_as", remote.IA)
			span.SetTag("dst.host", remote.Host.IP)
			defer span.Finish()

			ctx, cancelF := context.WithTimeout(traceCtx, time.Second)
			defer cancelF()
			sd, err := daemon.NewService(daemonAddr).Connect(ctx)
			if err != nil {
				return serrors.WrapStr("connecting to SCION Daemon", err)
			}
			defer sd.Close()
			info, err := app.QueryASInfo(traceCtx, sd)
			if err != nil {
				return err
			}
			span.SetTag("src.isd_as", info.IA)

			opts := []path.Option{
				path.WithInteractive(flags.interactive),
				path.WithRefresh(flags.refresh),
				path.WithSequence(flags.sequence),
				path.WithColorScheme(path.DefaultColorScheme(flags.noColor)),
				path.WithEPIC(flags.epic),
				path.WithFABRID(flags.fabrid),
			}
			if flags.healthyOnly {
				opts = append(opts, path.WithProbing(&path.ProbeConfig{
					LocalIA:    info.IA,
					LocalIP:    localIP,
					Dispatcher: dispatcher,
				}))
			}
			cs := path.DefaultColorScheme(false)
			pingPath, err := path.Choose(traceCtx, sd, remote.IA, opts...)

			if err != nil {
				return err
			}
			// Now select the Fabrid Policies that should be applied
			//TODO(jvanbommel): reuse?
			selectSeq, err := pathpol.NewSequence(flags.sequence)
			policies := selectSeq.ListSelectedPolicies(pingPath)
			//now := time.Now()
			//tmp := make([]byte, 100)
			//identifier := extension.IdentifierOption{
			//	Timestamp:     now,
			//	PacketID:      0xabcd,
			//	BaseTimestamp: uint32(now.Unix()),
			//}
			//identifierData := make([]byte, 8)
			//identifier.Serialize(identifierData)
			//
			//switch s := pingPath.Dataplane().(type) {
			//case snetpath.SCION:
			//
			//	var sp scion.Raw
			//	if err := sp.DecodeFromBytes(s.Raw); err != nil {
			//		return err
			//	}
			//	decoded, err := sp.ToDecoded()
			//	if err != nil {
			//		return err
			//
			//	}
			//	fmt.Println(decoded.HopFields)
			//	fabridHops := make([]extension.FabridHopfieldMetadata, len(decoded.HopFields))
			//
			//	for _, policy := range policies {
			//		hfOneToOne := hfIdx < len(decoded.HopFields) &&
			//			decoded.HopFields[hfIdx].ConsIngress == policy.Ingress &&
			//			decoded.HopFields[hfIdx].ConsEgress == policy.Egress
			//		hfTwoToOne := hfIdx+1 < len(decoded.HopFields) &&
			//			decoded.HopFields[hfIdx].ConsIngress == policy.Ingress &&
			//			decoded.HopFields[hfIdx].ConsEgress == 0 &&
			//			decoded.HopFields[hfIdx+1].ConsIngress == 0 &&
			//			decoded.HopFields[hfIdx+1].ConsEgress == policy.Egress
			//		if hfOneToOne {
			//
			//		}
			//	}
			//	polIdx := 0
			//	for i := 0; i < len(decoded.HopFields); i++ {
			//		if decoded.HopFields[i].ConsIngress == policies[polIdx].Ingress &&
			//			decoded.HopFields[i].ConsEgress == policies[polIdx].Egress {
			//			polIdx++
			//		} else if decoded.HopFields[i].ConsIngress == policies[polIdx].Ingress &&
			//			decoded.HopFields[i].ConsEgress == 0 && hf.ConsIngress == 0 && decoded.HopFields[i+1] == policies[polIdx].Egress {
			//
			//		}
			//
			//	}
			//	//decoded.HopFields[0].
			//	hfIdx := 0
			//	for _, policy := range policies {
			//		hfOneToOne := hfIdx < len(decoded.HopFields) &&
			//			decoded.HopFields[hfIdx].ConsIngress == policy.Ingress &&
			//			decoded.HopFields[hfIdx].ConsEgress == policy.Egress
			//		hfTwoToOne := hfIdx+1 < len(decoded.HopFields) &&
			//			decoded.HopFields[hfIdx].ConsIngress == policy.Ingress &&
			//			decoded.HopFields[hfIdx].ConsEgress == 0 &&
			//			decoded.HopFields[hfIdx+1].ConsIngress == 0 &&
			//			decoded.HopFields[hfIdx+1].ConsEgress == policy.Egress
			//		if policy.Pol == nil {
			//			if hfOneToOne {
			//				fabridHops[hfIdx] = extension.FabridHopfieldMetadata{}
			//				hfIdx++
			//			} else if hfTwoToOne {
			//				fabridHops[hfIdx] = extension.FabridHopfieldMetadata{}
			//				fabridHops[hfIdx+1] = extension.FabridHopfieldMetadata{}
			//				hfIdx = hfIdx + 2
			//			}
			//			continue
			//		}
			//		key, err := sd.DRKeyGetASHostKey(traceCtx, drkey.ASHostMeta{
			//			ProtoId:  drkey.Protocol(int32(drkey.FABRID)),
			//			Validity: now,
			//			SrcIA:    xtest.MustParseIA("1-ff00:0:110"),
			//			DstIA:    info.IA,
			//			DstHost:  localIP.String(),
			//		})
			//		if err != nil {
			//			return err
			//		}
			//
			//		policyID := fabrid.FabridPolicyID{
			//			ID: policy.Pol.Index,
			//		}
			//
			//		encPolicyID, err := fabrid.EncryptPolicyID(&policyID, &identifier, key.Key[:])
			//
			//		meta := extension.FabridHopfieldMetadata{
			//			FabridEnabled:     true,
			//			EncryptedPolicyID: encPolicyID,
			//		}
			//		mac, err := scrypto.InitMac(key.Key[:])
			//		if err != nil {
			//			return err
			//		}
			//
			//		var scionLayer slayers.SCION
			//		scionLayer.Version = 0
			//		scionLayer.FlowID = 1
			//		scionLayer.DstIA = remote.IA
			//		scionLayer.SrcIA = info.IA
			//		remoteHostIP, ok := netip.AddrFromSlice(remote.Host.IP)
			//		if !ok {
			//			return serrors.New("invalid remote host IP", "ip", remote.Host.IP)
			//		}
			//		localHostIP, ok := netip.AddrFromSlice(localIP)
			//		if !ok {
			//			return serrors.New("invalid local host IP", "ip", localIP)
			//		}
			//
			//		if err := scionLayer.SetDstAddr(addr.HostIP(remoteHostIP)); err != nil {
			//			return serrors.WrapStr("setting destination address", err)
			//		}
			//		if err := scionLayer.SetSrcAddr(addr.HostIP(localHostIP)); err != nil {
			//			return serrors.WrapStr("setting source address", err)
			//		}
			//		sigma := slayerspath.MAC(mac, decoded.InfoFields[0], decoded.HopFields[1], nil)
			//		err = fabrid.ComputeBaseHVF(&meta, &identifier, &scionLayer, tmp, key.Key[:], sigma[:])
			//
			//		fabridHops[i] = meta
			//		if hfOneToOne {
			//			fabridHops[hfIdx] = extension.FabridHopfieldMetadata{}
			//			hfIdx++
			//		} else if hfTwoToOne {
			//			fabridHops[hfIdx] = extension.FabridHopfieldMetadata{}
			//			fabridHops[hfIdx+1] = extension.FabridHopfieldMetadata{}
			//			hfIdx = hfIdx + 2
			//		}
			//	}
			//}
			//
			fmt.Println(cs.Path(pingPath))
			fmt.Println(policies)
			//fmt.Println(fabridHops)

			//fabrid := extension.FabridOption{
			//	HopfieldMetadata: fabridHops,
			//}
			//fabridData := make([]byte, extension.FabridOptionLen(len(policies)))
			//err = fabrid.SerializeTo(fabridData)
			//if err != nil {
			//	return err
			//}
			//hbh := slayers.HopByHopExtn{
			//	Options: []*slayers.HopByHopOption{
			//		{
			//			OptType:    slayers.OptTypeIdentifier,
			//			OptData:    identifierData,
			//			OptDataLen: uint8(len(identifierData)),
			//		},
			//		{
			//			OptType:    slayers.OptTypeFabrid,
			//			OptData:    fabridData,
			//			OptDataLen: uint8(len(fabridData)),
			//		},
			//	},
			//}
			// If the EPIC flag is set, use the EPIC-HP path type
			if flags.epic {
				switch s := pingPath.Dataplane().(type) {
				case snetpath.SCION:
					epicPath, err := snetpath.NewEPICDataplanePath(s, pingPath.Metadata().EpicAuths)
					if err != nil {
						return err
					}
					remote.Path = epicPath
				case snetpath.Empty:
					remote.Path = s
				default:
					return serrors.New("unsupported path type")
				}
			} else if flags.fabrid {
				switch s := pingPath.Dataplane().(type) {
				case snetpath.SCION:
					polIdentifier := snet.FabridPolicyIdentifier{
						Type:       snet.FabridGlobalPolicy,
						Identifier: 0,
						Index:      0,
					}
					fabridClientConfig := fabrid.SimpleFabridConfig{
						DestinationIA:   remote.IA,
						DestinationAddr: remote.Host.IP.String(),
						LocalIA:         info.IA,
						LocalAddr:       localIP.String(),
						ValidationRatio: 0,
						Policy:          polIdentifier,
					}
					servicesInfo, err := sd.SVCInfo(ctx, []addr.SVC{addr.SvcCS})
					if err != nil {
						return err
					}
					controlServiceInfo := servicesInfo[addr.SvcCS][0]
					localAddr := &net.TCPAddr{
						IP:   localIP,
						Port: 0,
					}
					controlAddr, err := net.ResolveTCPAddr("tcp", controlServiceInfo)
					if err != nil {
						return err
					}

					fmt.Println("CS:", controlServiceInfo)
					dialer := func(ctx context.Context, addr string) (net.Conn, error) {
						return net.DialTCP("tcp", localAddr, controlAddr)
					}
					grpcconn, err := grpc.DialContext(ctx, controlServiceInfo,
						grpc.WithInsecure(), grpc.WithContextDialer(dialer))
					if err != nil {
						return err
					}
					defer grpcconn.Close()
					fabridClient := fabrid.NewFabridClient(*remote, fabridClientConfig, grpcconn)
					fabridConfig := &snetpath.FabridConfig{
						LocalIA:         info.IA,
						LocalAddr:       localIP.String(),
						DestinationIA:   remote.IA,
						DestinationAddr: remote.Host.IP.String(),
					}
					fabridClient.NewFabridPathState(snet.Fingerprint(pingPath))
					fabridPath, err := snetpath.NewFABRIDDataplanePath(s, pingPath.Metadata().Interfaces,
						policies, fabridConfig, fabridClient, snet.Fingerprint(pingPath))
					if err != nil {
						return err
					}
					remote.Path = fabridPath
					if localIP == nil {
						target := remote.Host.IP
						if remote.NextHop != nil {
							target = remote.NextHop.IP
						}
						if localIP, err = addrutil.ResolveLocal(target); err != nil {
							return serrors.WrapStr("resolving local address", err)
						}
						printf("Resolved local address:\n  %s\n", localIP)
						fabridConfig.LocalAddr = localIP.String()
					}
					client := drpb.NewDRKeyIntraServiceClient(grpcconn)
					fabridPath.RegisterDRKeyFetcher(func(ctx context.Context, meta drkey.ASHostMeta) (drkey.ASHostKey, error) {
						rep, err := client.DRKeyASHost(ctx, drhelper.AsHostMetaToProtoRequest(meta))
						if err != nil {
							return drkey.ASHostKey{}, err
						}
						key, err := drhelper.GetASHostKeyFromReply(rep, meta)
						if err != nil {
							return drkey.ASHostKey{}, err
						}
						return key, nil
					})
				default:
					return serrors.New("unsupported path type")
				}
			} else {
				remote.Path = pingPath.Dataplane()
			}
			remote.NextHop = pingPath.UnderlayNextHop()

			// Resolve local IP based on underlay next hop
			if localIP == nil {
				target := remote.Host.IP
				if remote.NextHop != nil {
					target = remote.NextHop.IP
				}
				if localIP, err = addrutil.ResolveLocal(target); err != nil {
					return serrors.WrapStr("resolving local address", err)

				}
				printf("Resolved local address:\n  %s\n", localIP)
			}
			printf("Using path:\n  %s\n\n", pingPath)
			span.SetTag("src.host", localIP)
			local := &snet.UDPAddr{
				IA:   info.IA,
				Host: &net.UDPAddr{IP: localIP},
			}
			pldSize := int(flags.size)

			if cmd.Flags().Changed("packet-size") {
				overhead, err := ping.Size(local, remote, 0)
				if err != nil {
					return err
				}
				if overhead > int(flags.pktSize) {
					return serrors.New(
						"desired packet size smaller than header overhead",
						"minimum_packet_size", overhead)
				}
				pldSize = int(flags.pktSize - uint(overhead))
			}
			if flags.maxMTU {
				mtu := int(pingPath.Metadata().MTU)
				pldSize, err = calcMaxPldSize(local, remote, mtu)
				if err != nil {
					return err
				}
			}
			pktSize, err := ping.Size(local, remote, pldSize)
			if err != nil {
				return err
			}
			printf("PING %s pld=%dB scion_pkt=%dB\n", remote, pldSize, pktSize)

			start := time.Now()
			ctx = app.WithSignal(traceCtx, os.Interrupt, syscall.SIGTERM)
			count := flags.count
			if count == 0 {
				count = math.MaxUint16
			}

			seq, err := pathpol.GetSequence(pingPath)
			if err != nil {
				return serrors.New("get sequence from used path")
			}
			res := Result{
				ScionPacketSize: pktSize,
				Path: Path{
					Fingerprint: snet.Fingerprint(pingPath).String(),
					Hops:        getHops(pingPath),
					Sequence:    seq,
					LocalIP:     localIP,
					NextHop:     pingPath.UnderlayNextHop().String(),
				},
				PayloadSize: pldSize,
			}

			stats, err := ping.Run(ctx, ping.Config{
				Dispatcher:  reliable.NewDispatcher(dispatcher),
				Attempts:    count,
				Interval:    flags.interval,
				Timeout:     flags.timeout,
				Local:       local,
				Remote:      remote,
				PayloadSize: pldSize,
				ErrHandler: func(err error) {
					fmt.Fprintf(os.Stderr, "ERROR: %s\n", err)
				},
				UpdateHandler: func(update ping.Update) {
					var additional string
					switch update.State {
					case ping.AfterTimeout:
						additional = " state=After timeout"
					case ping.OutOfOrder:
						additional = " state=Out of Order"
					case ping.Duplicate:
						additional = " state=Duplicate"
					}
					res.Replies = append(res.Replies, PingUpdate{
						Size:     update.Size,
						Source:   update.Source.String(),
						Sequence: update.Sequence,
						RTT:      durationMillis(update.RTT),
						State:    update.State.String(),
					})
					printf("%d bytes from %s,%s: scmp_seq=%d time=%s%s\n",
						update.Size, update.Source.IA, update.Source.Host, update.Sequence,
						durationMillis(update.RTT), additional)
				},
				Hops: len(pingPath.Metadata().Interfaces) / 2,
			})
			if err != nil {
				return err
			}
			res.Statistics = calculateStats(stats, res.Replies, time.Since(start))

			switch flags.format {
			case "human":
				s := res.Statistics.Stats
				printf("\n--- %s,%s statistics ---\n", remote.IA, remote.Host.IP)
				printf("%d packets transmitted, %d received, %d%% packet loss, time %v\n",
					s.Sent, s.Received, res.Statistics.Loss,
					res.Statistics.Time,
				)
				if s.Received != 0 {
					printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n",
						res.Statistics.MinRTT.Millis(),
						res.Statistics.AvgRTT.Millis(),
						res.Statistics.MaxRTT.Millis(),
						res.Statistics.MdevRTT.Millis(),
					)
				}
				if stats.Received == 0 {
					return app.WithExitCode(serrors.New("no reply packet received"), 1)
				}
			case "json":
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				enc.SetEscapeHTML(false)
				return enc.Encode(res)
			case "yaml":
				enc := yaml.NewEncoder(os.Stdout)
				return enc.Encode(res)
			}

			return nil
		},
	}

	envFlags.Register(cmd.Flags())
	cmd.Flags().BoolVarP(&flags.interactive, "interactive", "i", false, "interactive mode")
	cmd.Flags().BoolVar(&flags.noColor, "no-color", false, "disable colored output")
	cmd.Flags().DurationVar(&flags.timeout, "timeout", time.Second, "timeout per packet")
	cmd.Flags().StringVar(&flags.sequence, "sequence", "", app.SequenceUsage)
	cmd.Flags().BoolVar(&flags.healthyOnly, "healthy-only", false, "only use healthy paths")
	cmd.Flags().BoolVar(&flags.refresh, "refresh", false, "set refresh flag for path request")
	cmd.Flags().DurationVar(&flags.interval, "interval", time.Second, "time between packets")
	cmd.Flags().Uint16VarP(&flags.count, "count", "c", 0, "total number of packets to send")
	cmd.Flags().UintVarP(&flags.size, "payload-size", "s", 0,
		`number of bytes to be sent in addition to the SCION Header and SCMP echo header;
the total size of the packet is still variable size due to the variable size of
the SCION path.`,
	)
	cmd.Flags().UintVar(&flags.pktSize, "packet-size", 0,
		`number of bytes to be sent including the SCION Header and SCMP echo header,
the desired size must provide enough space for the required headers. This flag
overrides the 'payload_size' flag.`,
	)
	cmd.Flags().BoolVar(&flags.maxMTU, "max-mtu", false,
		`choose the payload size such that the sent SCION packet including the SCION Header,
SCMP echo header and payload are equal to the MTU of the path. This flag overrides the
'payload_size' and 'packet_size' flags.`)
	cmd.Flags().StringVar(&flags.logLevel, "log.level", "", app.LogLevelUsage)
	cmd.Flags().StringVar(&flags.tracer, "tracing.agent", "", "Tracing agent address")
	cmd.Flags().BoolVar(&flags.epic, "epic", false, "Enable EPIC for path probing.")
	cmd.Flags().StringVar(&flags.format, "format", "human",
		"Specify the output format (human|json|yaml)")
	cmd.Flags().BoolVar(&flags.fabrid, "fabrid", false, "Enable FABRID")
	return cmd
}

func calcMaxPldSize(local, remote *snet.UDPAddr, mtu int) (int, error) {
	overhead, err := ping.Size(local, remote, 0)
	if err != nil {
		return 0, err
	}
	return mtu - overhead, nil
}

// calculateStats computes the Stats from the ping stats and updates
func calculateStats(s ping.Stats, replies []PingUpdate, run time.Duration) Stats {
	var loss int
	if s.Sent != 0 {
		loss = 100 - s.Received*100/s.Sent
	}

	stats := Stats{
		Stats: s,
		Loss:  loss,
		Time:  durationMillis(run),
	}

	if len(replies) == 0 {
		return stats
	}
	minRTT := replies[0].RTT
	maxRTT := replies[0].RTT
	var sum durationMillis
	for i := 0; i < len(replies); i++ {
		if replies[i].RTT < minRTT {
			minRTT = replies[i].RTT
		}
		if replies[i].RTT > maxRTT {
			maxRTT = replies[i].RTT
		}
		sum += replies[i].RTT
	}
	avgRTT := durationMillis(int(sum) / len(replies))

	// standard deviation
	var sd float64
	for i := 0; i < len(replies); i++ {
		sd += math.Pow(float64(replies[i].RTT-avgRTT), 2)
	}
	mdevRTT := math.Sqrt(sd / float64(len(replies)))
	stats.MinRTT = minRTT
	stats.MaxRTT = maxRTT
	stats.AvgRTT = avgRTT
	stats.MdevRTT = durationMillis(mdevRTT)
	return stats
}
