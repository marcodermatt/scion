// Copyright 2024 ETH Zurich
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
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"
	libfabrid "github.com/scionproto/scion/pkg/experimental/fabrid"
	common2 "github.com/scionproto/scion/pkg/experimental/fabrid/common"
	fabridserver "github.com/scionproto/scion/pkg/experimental/fabrid/server"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/extension"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/private/tracing"
	libint "github.com/scionproto/scion/tools/integration"
	integration "github.com/scionproto/scion/tools/integration/integrationlib"
	"net"
	"net/netip"
	"os"
	"time"

	flag "github.com/spf13/pflag"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/drkey/generic"
	"github.com/scionproto/scion/pkg/drkey/specific"
	"github.com/scionproto/scion/pkg/private/serrors"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	dkpb "github.com/scionproto/scion/pkg/proto/drkey"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/pkg/snet"
	env "github.com/scionproto/scion/private/app/flag"
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	var serverMode bool
	var serverAddrStr, clientAddrStr string
	var protocol uint16
	var fetchSV bool
	var scionEnv env.SCIONEnvironment

	scionEnv.Register(flag.CommandLine)
	flag.BoolVar(&serverMode, "server", false, "Demonstrate server-side key derivation."+
		" (default demonstrate client-side key fetching)")
	flag.StringVar(&serverAddrStr, "server-addr", "", "SCION address for the server-side.")
	flag.StringVar(&clientAddrStr, "client-addr", "", "SCION address for the client-side.")
	flag.Uint16Var(&protocol, "protocol", 1 /* SCMP */, "DRKey protocol identifier.")
	flag.BoolVar(&fetchSV, "fetch-sv", false,
		"Fetch protocol specific secret value to derive server-side keys.")
	flag.Parse()
	if err := scionEnv.LoadExternalVars(); err != nil {
		fmt.Fprintln(os.Stderr, "Error reading SCION environment:", err)
		return 2
	}

	// NOTE: should parse addresses as snet.SCIONAddress not snet.UDPAddress, but
	// these parsing functions don't exist yet.
	serverAddr, err := snet.ParseUDPAddr(serverAddrStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid --server-addr '%s': %s\n", serverAddrStr, err)
		return 2
	}
	clientAddr, err := snet.ParseUDPAddr(clientAddrStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid --client-addr '%s': %s\n", clientAddrStr, err)
		return 2
	}

	if !serverMode && fetchSV {
		fmt.Fprintf(os.Stderr, "Invalid flag --fetch-sv for client-side key derivation\n")
		return 2
	}

	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelF()

	// meta describes the key that both client and server derive
	meta := drkey.HostHostMeta{
		ProtoId: drkey.Protocol(protocol),
		// Validity timestamp; both sides need to use a validity time stamp in the same epoch.
		// Usually this is coordinated by means of a timestamp in the message.
		Validity: time.Now(),
		// SrcIA is the AS on the "fast side" of the DRKey derivation;
		// the server side in this example.
		SrcIA: serverAddr.IA,
		// DstIA is the AS on the "slow side" of the DRKey derivation;
		// the client side in this example.
		DstIA:   clientAddr.IA,
		SrcHost: serverAddr.Host.IP.String(),
		DstHost: clientAddr.Host.IP.String(),
	}

	daemon, err := daemon.NewService(scionEnv.Daemon()).Connect(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error dialing SCION Daemon:", err)
		return 1
	}

	if serverMode {
		// Server: get the Secret Value (SV) for the protocol and derive all
		// subsequent keys in-process
		server := Server{daemon}
		var serverKey drkey.HostHostKey
		var t0, t1, t2 time.Time
		if fetchSV {
			// Fetch the Secret Value (SV); in a real application, this is only done at
			// startup and refreshed for each epoch.
			t0 = time.Now()
			sv, err := server.FetchSV(ctx, drkey.SecretValueMeta{
				ProtoId:  meta.ProtoId,
				Validity: meta.Validity,
			})
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error fetching secret value:", err)
				return 1
			}
			t1 = time.Now()
			serverKey, err = server.DeriveHostHostKeySpecific(sv, meta)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error deriving key:", err)
				return 1
			}
			t2 = time.Now()
		} else {
			// Fetch host-AS key (Level 2). This key can be used to derive keys for
			// all hosts in the destination AS. Depending on the application, it can
			// be cached and refreshed for each epoch.
			t0 = time.Now()
			hostASKey, err := server.FetchHostASKey(ctx, drkey.HostASMeta{
				ProtoId:  meta.ProtoId,
				Validity: meta.Validity,
				SrcIA:    meta.SrcIA,
				DstIA:    meta.DstIA,
				SrcHost:  meta.SrcHost,
			})
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error fetching host-AS key:", err)
				return 1
			}
			t1 = time.Now()
			serverKey, err = server.DeriveHostHostKeyGeneric(hostASKey, meta)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error deriving key:", err)
				return 1
			}
			t2 = time.Now()
		}
		fmt.Printf(
			"Server: host key = %s, protocol = %s, fetch-sv = %v"+
				"\n\tduration without cache: %s\n\tduration with cache: %s\n",
			hex.EncodeToString(serverKey.Key[:]), meta.ProtoId, fetchSV, t2.Sub(t0), t2.Sub(t1),
		)
	} else {
		// Client: fetch key from daemon
		// The daemon will in turn obtain the key from the local CS
		// The CS will fetch the Lvl1 key from the CS in the SrcIA (the server's AS)
		// and derive the Host key based on this.
		client := Client{daemon}
		var t0, t1 time.Time
		t0 = time.Now()
		clientKey, err := client.FetchHostHostKey(ctx, meta)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error fetching key:", err)
			return 1
		}
		t1 = time.Now()

		fmt.Printf(
			"Client: host key = %s, protocol = %s\n\tduration: %s\n",
			hex.EncodeToString(clientKey.Key[:]), meta.ProtoId, t1.Sub(t0),
		)
	}
	return 0
}

type Client struct {
	daemon daemon.Connector
}

func (c Client) FetchHostHostKey(
	ctx context.Context, meta drkey.HostHostMeta) (drkey.HostHostKey, error) {

	// get level 3 key: (slow path)
	return c.daemon.DRKeyGetHostHostKey(ctx, meta)
}

type Server struct {
	daemon daemon.Connector
}

func (s Server) DeriveHostHostKeySpecific(
	sv drkey.SecretValue,
	meta drkey.HostHostMeta,
) (drkey.HostHostKey, error) {

	var deriver specific.Deriver
	lvl1, err := deriver.DeriveLevel1(meta.DstIA, sv.Key)
	if err != nil {
		return drkey.HostHostKey{}, serrors.WrapStr("deriving level 1 key", err)
	}
	asHost, err := deriver.DeriveHostAS(meta.SrcHost, lvl1)
	if err != nil {
		return drkey.HostHostKey{}, serrors.WrapStr("deriving host-AS key", err)
	}
	hosthost, err := deriver.DeriveHostHost(meta.DstHost, asHost)
	if err != nil {
		return drkey.HostHostKey{}, serrors.WrapStr("deriving host-host key", err)
	}
	return drkey.HostHostKey{
		ProtoId: sv.ProtoId,
		Epoch:   sv.Epoch,
		SrcIA:   meta.SrcIA,
		DstIA:   meta.DstIA,
		SrcHost: meta.SrcHost,
		DstHost: meta.DstHost,
		Key:     hosthost,
	}, nil
}

func (s Server) DeriveHostHostKeyGeneric(
	hostAS drkey.HostASKey,
	meta drkey.HostHostMeta,
) (drkey.HostHostKey, error) {

	deriver := generic.Deriver{
		Proto: hostAS.ProtoId,
	}
	hosthost, err := deriver.DeriveHostHost(meta.DstHost, hostAS.Key)
	if err != nil {
		return drkey.HostHostKey{}, serrors.WrapStr("deriving host-host key", err)
	}
	return drkey.HostHostKey{
		ProtoId: hostAS.ProtoId,
		Epoch:   hostAS.Epoch,
		SrcIA:   meta.SrcIA,
		DstIA:   meta.DstIA,
		SrcHost: meta.SrcHost,
		DstHost: meta.DstHost,
		Key:     hosthost,
	}, nil
}

// FetchSV obtains the Secret Value (SV) for the selected protocol/epoch.
// From this SV, all keys for this protocol/epoch can be derived locally.
// The IP address of the server must be explicitly allowed to abtain this SV
// from the the control server.
func (s Server) FetchSV(
	ctx context.Context,
	meta drkey.SecretValueMeta,
) (drkey.SecretValue, error) {

	// Obtain CS address from scion daemon
	svcs, err := s.daemon.SVCInfo(ctx, nil)
	if err != nil {
		return drkey.SecretValue{}, serrors.WrapStr("obtaining control service address", err)
	}
	cs := svcs[addr.SvcCS]
	if len(cs) == 0 {
		return drkey.SecretValue{}, serrors.New("no control service address found")
	}

	// Contact CS directly for SV
	conn, err := grpc.DialContext(ctx, cs[0], grpc.WithInsecure())
	if err != nil {
		return drkey.SecretValue{}, serrors.WrapStr("dialing control service", err)
	}
	defer conn.Close()
	client := cppb.NewDRKeyIntraServiceClient(conn)

	rep, err := client.DRKeySecretValue(ctx, &cppb.DRKeySecretValueRequest{
		ValTime:    timestamppb.New(meta.Validity),
		ProtocolId: dkpb.Protocol(meta.ProtoId),
	})
	if err != nil {
		return drkey.SecretValue{}, serrors.WrapStr("requesting drkey secret value", err)
	}

	key, err := getSecretFromReply(meta.ProtoId, rep)
	if err != nil {
		return drkey.SecretValue{}, serrors.WrapStr("validating drkey secret value reply", err)
	}

	return key, nil
}

func getSecretFromReply(
	proto drkey.Protocol,
	rep *cppb.DRKeySecretValueResponse,
) (drkey.SecretValue, error) {

	if err := rep.EpochBegin.CheckValid(); err != nil {
		return drkey.SecretValue{}, err
	}
	if err := rep.EpochEnd.CheckValid(); err != nil {
		return drkey.SecretValue{}, err
	}
	epoch := drkey.Epoch{
		Validity: cppki.Validity{
			NotBefore: rep.EpochBegin.AsTime(),
			NotAfter:  rep.EpochEnd.AsTime(),
		},
	}
	returningKey := drkey.SecretValue{
		ProtoId: proto,
		Epoch:   epoch,
	}
	copy(returningKey.Key[:], rep.Key)
	return returningKey, nil
}

func (s Server) FetchHostASKey(
	ctx context.Context, meta drkey.HostASMeta) (drkey.HostASKey, error) {

	// get level 2 key: (fast path)
	return s.daemon.DRKeyGetHostASKey(ctx, meta)
}

type server struct {
	fabridServer *fabridserver.Server
}

func (s server) run() {
	fmt.Printf("Starting server", "isd_as", integration.Local.IA)
	defer fmt.Printf("Finished server", "isd_as", integration.Local.IA)

	sdConn := integration.SDConn()
	defer sdConn.Close()
	sn := &snet.SCIONNetwork{
		SCMPHandler: snet.DefaultSCMPHandler{
			RevocationHandler: daemon.RevHandler{Connector: sdConn},
			SCMPErrors:        scmpErrorsCounter,
		},
		PacketConnMetrics: scionPacketConnMetrics,
		Topology:          sdConn,
	}
	conn, err := sn.OpenRaw(context.Background(), integration.Local.Host)
	if err != nil {
		integration.LogFatal("Error listening", "err", err)
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	if len(os.Getenv(libint.GoIntegrationEnv)) > 0 {
		// Needed for integration test ready signal.
		fmt.Printf("Port=%d\n", localAddr.Port)
		fmt.Printf("%s%s\n\n", libint.ReadySignal, integration.Local.IA)
	}
	fmt.Printf("Listening", "local",
		fmt.Sprintf("%v:%d", integration.Local.Host.IP, localAddr.Port))
	s.fabridServer = fabridserver.NewFabridServer(&integration.Local, integration.SDConn())
	s.fabridServer.ValidationHandler = func(connection *fabridserver.ClientConnection,
		option *extension.IdentifierOption, b bool) error {
		log.Debug("Validation handler", "connection", connection, "success", b)
		if !b {
			return serrors.New("Failed validation")
		}
		return nil
	}
	// Receive ping message
	for {
		if err := s.handlePingFabrid(conn); err != nil {
			log.Error("Error handling ping", "err", err)
		}
	}
}

func (s server) handlePingFabrid(conn snet.PacketConn) error {
	var p snet.Packet
	var ov net.UDPAddr
	err := readFromFabrid(conn, &p, &ov)
	if err != nil {
		return serrors.WrapStr("reading packet", err)
	}

	var valResponse *slayers.EndToEndExtn

	// If the packet is from remote IA, validate the FABRID path
	if p.Source.IA != integration.Local.IA {
		if p.HbhExtension == nil {
			return serrors.New("Missing HBH extension")
		}

		// Check extensions for relevant options
		var identifierOption *extension.IdentifierOption
		var fabridOption *extension.FabridOption
		var controlOptions []*extension.FabridControlOption
		var err error

		for _, opt := range p.HbhExtension.Options {
			switch opt.OptType {
			case slayers.OptTypeIdentifier:
				decoded := scion.Decoded{}
				err = decoded.DecodeFromBytes(p.Path.(snet.RawPath).Raw)
				if err != nil {
					return err
				}
				baseTimestamp := decoded.InfoFields[0].Timestamp
				identifierOption, err = extension.ParseIdentifierOption(opt, baseTimestamp)
				if err != nil {
					return err
				}
			case slayers.OptTypeFabrid:
				fabridOption, err = extension.ParseFabridOptionFullExtension(opt,
					(opt.OptDataLen-4)/4)
				if err != nil {
					return err
				}
			}
		}
		if p.E2eExtension != nil {

			for _, opt := range p.E2eExtension.Options {
				switch opt.OptType {
				case slayers.OptTypeFabridControl:
					controlOption, err := extension.ParseFabridControlOption(opt)
					if err != nil {
						return err
					}
					controlOptions = append(controlOptions, controlOption)
				}
			}
		}

		if identifierOption == nil {
			return serrors.New("Missing identifier option")
		}

		if fabridOption == nil {
			return serrors.New("Missing FABRID option")
		}
		valResponse, err = s.fabridServer.HandleFabridPacket(p.Source, fabridOption,
			identifierOption, controlOptions)
		if err != nil {
			return err
		}
	}

	udp, ok := p.Payload.(snet.UDPPayload)
	if !ok {
		return serrors.New("unexpected payload received",
			"source", p.Source,
			"destination", p.Destination,
			"type", common.TypeOf(p.Payload),
		)
	}
	var pld Ping
	if err := json.Unmarshal(udp.Payload, &pld); err != nil {
		return serrors.New("invalid payload contents",
			"source", p.Source,
			"destination", p.Destination,
			"data", string(udp.Payload),
		)
	}

	spanCtx, err := opentracing.GlobalTracer().Extract(
		opentracing.Binary,
		bytes.NewReader(pld.Trace),
	)
	if err != nil {
		return serrors.WrapStr("extracting trace information", err)
	}
	span, _ := opentracing.StartSpanFromContext(
		context.Background(),
		"handle_ping",
		ext.RPCServerOption(spanCtx),
	)
	defer span.Finish()
	withTag := func(err error) error {
		tracing.Error(span, err)
		return err
	}

	if pld.Message != ping || !pld.Server.Equal(integration.Local.IA) {
		return withTag(serrors.New("unexpected data in payload",
			"source", p.Source,
			"destination", p.Destination,
			"data", pld,
		))
	}
	fmt.Printf(fmt.Sprintf("Ping received from %s, sending pong.", p.Source))
	raw, err := json.Marshal(Pong{
		Client:  p.Source.IA,
		Server:  integration.Local.IA,
		Message: pong,
		Trace:   pld.Trace,
	})
	if err != nil {
		return withTag(serrors.WrapStr("packing pong", err))
	}

	p.Destination, p.Source = p.Source, p.Destination
	p.Payload = snet.UDPPayload{
		DstPort: udp.SrcPort,
		SrcPort: udp.DstPort,
		Payload: raw,
	}

	// Remove header extension for reverse path
	p.HbhExtension = nil
	p.E2eExtension = valResponse

	// reverse path
	rpath, ok := p.Path.(snet.RawPath)
	if !ok {
		return serrors.New("unexpected path", "type", common.TypeOf(p.Path))
	}
	replypather := snet.DefaultReplyPather{}
	replyPath, err := replypather.ReplyPath(rpath)
	if err != nil {
		return serrors.WrapStr("creating reply path", err)
	}
	p.Path = replyPath
	// Send pong
	if err := conn.WriteTo(&p, &ov); err != nil {
		return withTag(serrors.WrapStr("sending reply", err))
	}
	fmt.Printf("Sent pong to", "client", p.Destination)
	return nil
}

type client struct {
	network *snet.SCIONNetwork
	conn    *snet.Conn
	rawConn snet.PacketConn
	sdConn  daemon.Connector

	errorPaths map[snet.PathFingerprint]struct{}
}

func (c *client) run() int {
	pair := fmt.Sprintf("%s -> %s", integration.Local.IA, remote.IA)
	fmt.Printf("Starting", "pair", pair)
	defer fmt.Printf("Finished", "pair", pair)
	defer integration.Done(integration.Local.IA, remote.IA)
	c.sdConn = integration.SDConn()
	defer c.sdConn.Close()
	c.network = &snet.SCIONNetwork{
		SCMPHandler: snet.DefaultSCMPHandler{
			RevocationHandler: daemon.RevHandler{Connector: c.sdConn},
			SCMPErrors:        scmpErrorsCounter,
		},
		PacketConnMetrics: scionPacketConnMetrics,
		Topology:          c.sdConn,
	}
	fmt.Printf("Send", "local",
		fmt.Sprintf("%v,[%v] -> %v,[%v]",
			integration.Local.IA, integration.Local.Host,
			remote.IA, remote.Host))
	c.errorPaths = make(map[snet.PathFingerprint]struct{})
	return integration.AttemptRepeatedly("End2End", c.attemptRequest)
}

// attemptRequest sends one ping packet and expect a pong.
// Returns true (which means "stop") *if both worked*.
func (c *client) attemptRequest(n int) bool {
	timeoutCtx, cancel := context.WithTimeout(context.Background(), timeout.Duration)
	defer cancel()
	span, ctx := tracing.CtxWith(timeoutCtx, "attempt")
	span.SetTag("attempt", n)
	span.SetTag("src", integration.Local.IA)
	span.SetTag("dst", remote.IA)
	defer span.Finish()
	logger := log.FromCtx(ctx)

	path, err := c.getRemote(ctx, n)
	if err != nil {
		logger.Error("Could not get remote", "err", err)
		return false
	}
	span, ctx = tracing.StartSpanFromCtx(ctx, "attempt.ping")
	defer span.Finish()
	withTag := func(err error) error {
		tracing.Error(span, err)
		return err
	}

	for i := 0; i < 10; i++ {

		// Send ping
		close, err := c.fabridPing(ctx, n, path)
		if err != nil {
			logger.Error("Could not send packet", "err", withTag(err))
			return false
		}
		defer close()
		// Receive FABRID pong
		if err := c.fabridPong(ctx); err != nil {
			logger.Error("Error receiving pong", "err", withTag(err))
			if path != nil {
				c.errorPaths[snet.Fingerprint(path)] = struct{}{}
			}
			return false
		}
	}
	return true
}

func (c *client) fabridPing(ctx context.Context, n int, path snet.Path) (func(), error) {
	rawPing, err := json.Marshal(Ping{
		Server:  remote.IA,
		Message: ping,
		Trace:   tracing.IDFromCtx(ctx),
	})
	if err != nil {
		return nil, serrors.WrapStr("packing ping", err)
	}
	log.FromCtx(ctx).Info("Dialing", "remote", remote)
	c.rawConn, err = c.network.OpenRaw(ctx, integration.Local.Host)
	if err != nil {
		return nil, serrors.WrapStr("dialing conn", err)
	}
	if err := c.rawConn.SetWriteDeadline(getDeadline(ctx)); err != nil {
		return nil, serrors.WrapStr("setting write deadline", err)
	}
	fmt.Printf("sending ping", "attempt", n, "remote", remote, "local", c.rawConn.LocalAddr())
	localAddr := c.rawConn.LocalAddr().(*net.UDPAddr)
	hostIP, _ := netip.AddrFromSlice(remote.Host.IP)
	dst := snet.SCIONAddress{IA: remote.IA, Host: addr.HostIP(hostIP)}
	localHostIP, _ := netip.AddrFromSlice(integration.Local.Host.IP)
	pkt := &snet.Packet{
		Bytes: make([]byte, common.SupportedMTU),
		PacketInfo: snet.PacketInfo{
			Destination: dst,
			Source: snet.SCIONAddress{
				IA:   integration.Local.IA,
				Host: addr.HostIP(localHostIP),
			},
			Path: remote.Path,
			Payload: snet.UDPPayload{
				SrcPort: uint16(localAddr.Port),
				DstPort: uint16(remote.Host.Port),
				Payload: []byte("ping"),
			},
		},
	}
	fmt.Printf("sending packet", "packet", pkt)
	if err := c.rawConn.WriteTo(pkt, remote.NextHop); err != nil {
		return nil, err
	}
	closer := func() {
		if err := c.rawConn.Close(); err != nil {
			log.Error("Unable to close connection", "err", err)
		}
	}
	return closer, nil
}

func (c *client) getRemote(ctx context.Context, n int) (snet.Path, error) {
	if remote.IA.Equal(integration.Local.IA) {
		remote.Path = snetpath.Empty{}
		return nil, nil
	}
	span, ctx := tracing.StartSpanFromCtx(ctx, "attempt.get_remote")
	defer span.Finish()
	withTag := func(err error) error {
		tracing.Error(span, err)
		return err
	}

	paths, err := c.sdConn.Paths(ctx, remote.IA, integration.Local.IA,
		daemon.PathReqFlags{Refresh: n != 0})
	if err != nil {
		return nil, withTag(serrors.WrapStr("requesting paths", err))
	}
	// If all paths had an error, let's try them again.
	if len(paths) <= len(c.errorPaths) {
		c.errorPaths = make(map[snet.PathFingerprint]struct{})
	}
	// Select first path that didn't error before.
	var path snet.Path
	for _, p := range paths {
		if _, ok := c.errorPaths[snet.Fingerprint(p)]; ok {
			continue
		}
		path = p
		break
	}
	if path == nil {
		return nil, withTag(serrors.New("no path found",
			"candidates", len(paths),
			"errors", len(c.errorPaths),
		))
	}
	// If the fabrid flag is set, try to create FABRID dataplane path.
	if len(path.Metadata().FabridInfo) > 0 {
		// Check if fabrid info is available, otherwise the source
		// AS does not support fabrid

		scionPath, ok := path.Dataplane().(snetpath.SCION)
		if !ok {
			return nil, serrors.New("provided path must be of type scion")
		}
		fabridConfig := &snetpath.FabridConfig{
			LocalIA:         integration.Local.IA,
			LocalAddr:       integration.Local.Host.IP.String(),
			DestinationIA:   remote.IA,
			DestinationAddr: remote.Host.IP.String(),
		}
		fabridConfig.ValidationHandler = func(ps *common2.PathState,
			option *extension.FabridControlOption, b bool) error {
			log.Debug("Validation handler", "pathState", ps, "success", b)
			if !b {
				return serrors.New("Failed validation")
			}
			return nil
		}
		hops := path.Metadata().Hops()
		fmt.Printf("Fabrid path", "path", path, "hops", hops)
		// Use ZERO policy for all hops with fabrid, to just do path validation
		policies := make([]*libfabrid.PolicyID, len(hops))
		zeroPol := libfabrid.PolicyID(0)
		for i, hop := range hops {
			if hop.FabridEnabled {
				policies[i] = &zeroPol
			}
		}
		fabridPath, err := snetpath.NewFABRIDDataplanePath(scionPath, hops,
			policies, fabridConfig, 125)
		if err != nil {
			return nil, serrors.New("Error creating FABRID path", "err", err)
		}
		remote.Path = fabridPath
		fabridPath.RegisterDRKeyFetcher(c.sdConn.FabridKeys)

	} else {
		fmt.Printf("FABRID flag was set for client in non-FABRID AS. Proceeding without FABRID.")
		remote.Path = path.Dataplane()
	}
	remote.NextHop = path.UnderlayNextHop()
	return path, nil
}

func (c *client) pong(ctx context.Context) error {
	if err := c.conn.SetReadDeadline(getDeadline(ctx)); err != nil {
		return serrors.WrapStr("setting read deadline", err)
	}
	rawPld := make([]byte, common.MaxMTU)
	n, serverAddr, err := readFrom(c.conn, rawPld)
	if err != nil {
		return serrors.WrapStr("reading packet", err)
	}

	var pld Pong
	if err := json.Unmarshal(rawPld[:n], &pld); err != nil {
		return serrors.WrapStr("unpacking pong", err, "data", string(rawPld))
	}

	expected := Pong{
		Client:  integration.Local.IA,
		Server:  remote.IA,
		Message: pong,
	}
	if pld.Client != expected.Client || pld.Server != expected.Server || pld.Message != pong {
		return serrors.New("unexpected contents received", "data", pld, "expected", expected)
	}
	fmt.Printf("Received pong", "server", serverAddr)
	return nil
}

func (c *client) fabridPong(ctx context.Context) error {

	if err := c.rawConn.SetReadDeadline(getDeadline(ctx)); err != nil {
		return serrors.WrapStr("setting read deadline", err)
	}
	var p snet.Packet
	var ov net.UDPAddr
	err := readFromFabrid(c.rawConn, &p, &ov)
	if err != nil {
		return serrors.WrapStr("reading packet", err)
	}
	if p.Source.IA != integration.Local.IA {
		// Check extensions for relevant options
		var controlOptions []*extension.FabridControlOption

		if p.E2eExtension != nil {

			for _, opt := range p.E2eExtension.Options {
				switch opt.OptType {
				case slayers.OptTypeFabridControl:
					controlOption, err := extension.ParseFabridControlOption(opt)
					if err != nil {
						return err
					}
					controlOptions = append(controlOptions, controlOption)
					log.Debug("Parsed control option", "option", controlOption)
				}
			}
		}
		switch s := remote.Path.(type) {
		case *snetpath.FABRID:
			for _, option := range controlOptions {
				err := s.HandleFabridControlOption(option, nil)
				if err != nil {
					return err
				}
			}

		default:
			return serrors.New("unsupported path type")
		}
	}

	udp, ok := p.Payload.(snet.UDPPayload)
	if !ok {
		return serrors.New("unexpected payload received",
			"source", p.Source,
			"destination", p.Destination,
			"type", common.TypeOf(p.Payload),
		)
	}
	var pld Pong
	if err := json.Unmarshal(udp.Payload, &pld); err != nil {
		return serrors.WrapStr("unpacking pong", err, "data", string(udp.Payload))
	}

	expected := Pong{
		Client:  integration.Local.IA,
		Server:  remote.IA,
		Message: pong,
	}
	if pld.Client != expected.Client || pld.Server != expected.Server || pld.Message != pong {
		return serrors.New("unexpected contents received", "data", pld, "expected", expected)
	}
	fmt.Printf("Received pong", "server", ov)
	return nil
}

func getDeadline(ctx context.Context) time.Time {
	dl, ok := ctx.Deadline()
	if !ok {
		integration.LogFatal("No deadline in context")
	}
	return dl
}

func readFrom(conn *snet.Conn, pld []byte) (int, net.Addr, error) {
	n, remoteAddr, err := conn.ReadFrom(pld)
	// Attach more context to error
	var opErr *snet.OpError
	if !(errors.As(err, &opErr) && opErr.RevInfo() != nil) {
		return n, remoteAddr, err
	}
	return n, remoteAddr, serrors.WithCtx(err,
		"isd_as", opErr.RevInfo().IA(),
		"interface", opErr.RevInfo().IfID,
	)
}

func readFromFabrid(conn snet.PacketConn, pkt *snet.Packet, ov *net.UDPAddr) error {
	err := conn.ReadFrom(pkt, ov)
	// Attach more context to error
	var opErr *snet.OpError
	if !(errors.As(err, &opErr) && opErr.RevInfo() != nil) {
		return err
	}
	return serrors.WithCtx(err,
		"isd_as", opErr.RevInfo().IA(),
		"interface", opErr.RevInfo().IfID,
	)
}
