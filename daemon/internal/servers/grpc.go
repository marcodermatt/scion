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

package servers

import (
	"context"
	"fmt"
	"net"
	"time"

	durationpb "github.com/golang/protobuf/ptypes/duration"
	timestamppb "github.com/golang/protobuf/ptypes/timestamp"
	"github.com/opentracing/opentracing-go"
	"golang.org/x/sync/singleflight"
	"google.golang.org/protobuf/types/known/emptypb"

	drkey_daemon "github.com/scionproto/scion/daemon/drkey"
	"github.com/scionproto/scion/daemon/fetcher"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/experimental/fabrid"
	fabrid_accumulator "github.com/scionproto/scion/pkg/experimental/fabrid/accumulator"
	libgrpc "github.com/scionproto/scion/pkg/grpc"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/ctrl/path_mgmt"
	"github.com/scionproto/scion/pkg/private/ctrl/path_mgmt/proto"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/proto/control_plane/experimental"
	pb_daemon "github.com/scionproto/scion/pkg/proto/daemon"
	sdpb "github.com/scionproto/scion/pkg/proto/daemon"
	fabrid_ext "github.com/scionproto/scion/pkg/segment/extensions/fabrid"
	"github.com/scionproto/scion/pkg/snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/private/revcache"
	"github.com/scionproto/scion/private/topology"
	"github.com/scionproto/scion/private/trust"
)

type Topology interface {
	InterfaceIDs() []uint16
	UnderlayNextHop(uint16) *net.UDPAddr
	ControlServiceAddresses() []*net.UDPAddr
	PortRange() (uint16, uint16)
}

// DaemonServer handles gRPC requests to the SCION daemon.
type DaemonServer struct {
	IA          addr.IA
	MTU         uint16
	Topology    Topology
	Fetcher     fetcher.Fetcher
	RevCache    revcache.RevCache
	ASInspector trust.Inspector
	DRKeyClient *drkey_daemon.ClientEngine
	Dialer      libgrpc.Dialer
	Metrics     Metrics

	foregroundPathDedupe singleflight.Group
	backgroundPathDedupe singleflight.Group
}

// Paths serves the paths request.
func (s *DaemonServer) Paths(ctx context.Context,
	req *sdpb.PathsRequest) (*sdpb.PathsResponse, error) {

	start := time.Now()
	dstI := addr.IA(req.DestinationIsdAs).ISD()
	response, err := s.paths(ctx, req)
	s.Metrics.PathsRequests.inc(
		pathReqLabels{Result: errToMetricResult(err), Dst: dstI},
		time.Since(start).Seconds(),
	)
	return response, unwrapMetricsError(err)
}

func (s *DaemonServer) paths(ctx context.Context,
	req *sdpb.PathsRequest) (*sdpb.PathsResponse, error) {

	if _, ok := ctx.Deadline(); !ok {
		var cancelF context.CancelFunc
		ctx, cancelF = context.WithTimeout(ctx, 10*time.Second)
		defer cancelF()
	}
	srcIA, dstIA := addr.IA(req.SourceIsdAs), addr.IA(req.DestinationIsdAs)
	go func() {
		defer log.HandlePanic()
		s.backgroundPaths(ctx, srcIA, dstIA, req.Refresh)
	}()
	paths, err := s.fetchPaths(ctx, &s.foregroundPathDedupe, srcIA, dstIA, req.Refresh)
	if err != nil {
		log.FromCtx(ctx).Debug("Fetching paths", "err", err,
			"src", srcIA, "dst", dstIA, "refresh", req.Refresh)
		return nil, err
	}
	if req.FetchFabridDetachedMaps {
		detachedHops := findDetachedHops(paths)
		if len(detachedHops) > 0 {
			log.Info("Detached hops found", "hops", len(detachedHops))
			updateFabridInfo(ctx, s.Dialer, detachedHops)
		}
	}
	reply := &sdpb.PathsResponse{}
	for _, p := range paths {
		reply.Paths = append(reply.Paths, pathToPB(p))
	}
	return reply, nil
}

type tempHopInfo struct {
	IA      addr.IA
	Meta    *snet.PathMetadata
	fiIdx   int
	Ingress uint16
	Egress  uint16
}

// updateFabridInfo updates the FABRID info that is contained in the path Metadata for detached
// hops, by fetching the corresponding FABRID maps from the corresponding AS.
func updateFabridInfo(ctx context.Context, dialer libgrpc.Dialer, detachedHops []tempHopInfo) {
	conn, err := dialer.Dial(ctx, &snet.SVCAddr{SVC: addr.SvcCS})
	if err != nil {
		log.FromCtx(ctx).Debug("Dialing CS failed", "err", err)
	}
	defer conn.Close()
	client := experimental.NewFABRIDIntraServiceClient(conn)
	fabridMaps := make(map[addr.IA]fabrid.FabridMapEntry)
	for _, detachedHop := range detachedHops {
		if _, ok := fabridMaps[detachedHop.IA]; !ok {
			fabridMaps[detachedHop.IA] = fetchMaps(ctx, detachedHop.IA, client,
				detachedHop.Meta.FabridInfo[detachedHop.fiIdx].Digest)
		}
		detachedHop.Meta.FabridInfo[detachedHop.fiIdx] = *fabrid_accumulator.
			GetFabridInfoForIntfs(detachedHop.IA, detachedHop.Ingress, detachedHop.Egress,
				fabridMaps, true)
	}
}

// findDetachedHops finds the hops where the FABRID maps have been detached in a given list of
// paths.
func findDetachedHops(paths []snet.Path) []tempHopInfo {
	detachedHops := make([]tempHopInfo, 0)
	for _, p := range paths {
		if p.Metadata().FabridInfo[0].Enabled && p.Metadata().FabridInfo[0].Detached {
			detachedHops = append(detachedHops, tempHopInfo{
				IA:      p.Metadata().Interfaces[0].IA,
				Meta:    p.Metadata(),
				fiIdx:   0,
				Ingress: 0,
				Egress:  uint16(p.Metadata().Interfaces[0].ID),
			})
		}
		for i := 1; i < len(p.Metadata().Interfaces)-1; i += 2 {
			if p.Metadata().FabridInfo[(i+1)/2].Enabled &&
				p.Metadata().FabridInfo[(i+1)/2].Detached {
				detachedHops = append(detachedHops, tempHopInfo{
					IA:      p.Metadata().Interfaces[i].IA,
					Meta:    p.Metadata(),
					fiIdx:   (i + 1) / 2,
					Ingress: uint16(p.Metadata().Interfaces[i].ID),
					Egress:  uint16(p.Metadata().Interfaces[i+1].ID),
				})
			}
		}
		if p.Metadata().FabridInfo[len(p.Metadata().Interfaces)/2].Enabled &&
			p.Metadata().FabridInfo[len(p.Metadata().Interfaces)/2].Detached {
			detachedHops = append(detachedHops, tempHopInfo{
				IA:      p.Metadata().Interfaces[len(p.Metadata().Interfaces)-1].IA,
				Meta:    p.Metadata(),
				fiIdx:   len(p.Metadata().Interfaces) / 2,
				Ingress: uint16(p.Metadata().Interfaces[len(p.Metadata().Interfaces)-1].ID),
				Egress:  0,
			})
		}
	}
	return detachedHops
}

// fetchMaps retrieves FABRID maps from the Control Service for a given ISD-AS.
// It uses the provided client to communicate with the Control Service and returns a FabridMapEntry
// to be used directly in the combinator.
func fetchMaps(ctx context.Context, ia addr.IA, client experimental.FABRIDIntraServiceClient,
	digest []byte) fabrid.FabridMapEntry {
	maps, err := client.RemoteMaps(ctx, &experimental.RemoteMapsRequest{
		Digest: digest,
		IsdAs:  uint64(ia),
	})
	if err != nil || maps.Maps == nil {
		log.FromCtx(ctx).Debug("Retrieving remote map from CS failed", "err", err, "ia",
			ia)
		return fabrid.FabridMapEntry{}
	}

	detached := fabrid_ext.Detached{
		SupportedIndicesMap: fabrid_ext.SupportedIndicesMapFromPB(maps.Maps.SupportedIndicesMap),
		IndexIdentiferMap:   fabrid_ext.IndexIdentifierMapFromPB(maps.Maps.IndexIdentifierMap),
	}
	return fabrid.FabridMapEntry{
		Map:    &detached,
		Ts:     time.Now(),
		Digest: []byte{}, // leave empty, it can be calculated using detached.Hash()
	}
}
func (s *DaemonServer) fetchPaths(
	ctx context.Context,
	group *singleflight.Group,
	src, dst addr.IA,
	refresh bool,
) ([]snet.Path, error) {

	r, err, _ := group.Do(fmt.Sprintf("%s%s%t", src, dst, refresh),
		func() (interface{}, error) {
			return s.Fetcher.GetPaths(ctx, src, dst, refresh)
		},
	)
	// just cast to the correct type, ignore the "ok", since that can only be
	// false in case of a nil result.
	paths, _ := r.([]snet.Path)
	return paths, err
}

func pathToPB(path snet.Path) *sdpb.Path {
	meta := path.Metadata()
	interfaces := make([]*sdpb.PathInterface, len(meta.Interfaces))
	for i, intf := range meta.Interfaces {
		interfaces[i] = &sdpb.PathInterface{
			Id:    uint64(intf.ID),
			IsdAs: uint64(intf.IA),
		}
	}

	latency := make([]*durationpb.Duration, len(meta.Latency))
	for i, v := range meta.Latency {
		seconds := int64(v / time.Second)
		nanos := int32(v - time.Duration(seconds)*time.Second)
		latency[i] = &durationpb.Duration{Seconds: seconds, Nanos: nanos}
	}
	geo := make([]*sdpb.GeoCoordinates, len(meta.Geo))
	for i, v := range meta.Geo {
		geo[i] = &sdpb.GeoCoordinates{
			Latitude:  v.Latitude,
			Longitude: v.Longitude,
			Address:   v.Address,
		}
	}
	linkType := make([]sdpb.LinkType, len(meta.LinkType))
	for i, v := range meta.LinkType {
		linkType[i] = linkTypeToPB(v)
	}

	var raw []byte
	scionPath, ok := path.Dataplane().(snetpath.SCION)
	if ok {
		raw = scionPath.Raw
	}
	nextHopStr := ""
	if nextHop := path.UnderlayNextHop(); nextHop != nil {
		nextHopStr = nextHop.String()
	}
	fabridInfo := make([]*sdpb.FabridInfo, len(meta.FabridInfo))
	for i, v := range meta.FabridInfo {
		fabridInfo[i] = fabridInfoToPB(&v)
	}
	epicAuths := &sdpb.EpicAuths{
		AuthPhvf: append([]byte(nil), meta.EpicAuths.AuthPHVF...),
		AuthLhvf: append([]byte(nil), meta.EpicAuths.AuthLHVF...),
	}

	return &sdpb.Path{
		Raw: raw,
		Interface: &sdpb.Interface{
			Address: &sdpb.Underlay{Address: nextHopStr},
		},
		Interfaces:      interfaces,
		Mtu:             uint32(meta.MTU),
		Expiration:      &timestamppb.Timestamp{Seconds: meta.Expiry.Unix()},
		Latency:         latency,
		Bandwidth:       meta.Bandwidth,
		CarbonIntensity: meta.CarbonIntensity,
		Geo:             geo,
		LinkType:        linkType,
		InternalHops:    meta.InternalHops,
		Notes:           meta.Notes,
		EpicAuths:       epicAuths,
		FabridInfo:      fabridInfo,
	}
}

func fabridPolicyToPB(fp *fabrid.Policy) *sdpb.FabridPolicy {
	return &sdpb.FabridPolicy{
		PolicyIdentifier: &experimental.FABRIDPolicyIdentifier{
			PolicyIsLocal:    fp.IsLocal,
			PolicyIdentifier: fp.Identifier,
		},
		PolicyIndex: uint32(fp.Index),
	}
}

func fabridInfoToPB(fi *snet.FabridInfo) *sdpb.FabridInfo {
	pbPolicies := make([]*sdpb.FabridPolicy, len(fi.Policies))
	for i, fp := range fi.Policies {
		pbPolicies[i] = fabridPolicyToPB(fp)
	}
	return &sdpb.FabridInfo{
		Enabled:  fi.Enabled,
		Digest:   fi.Digest,
		Policies: pbPolicies,
		Detached: fi.Detached,
	}
}
func linkTypeToPB(lt snet.LinkType) sdpb.LinkType {
	switch lt {
	case snet.LinkTypeDirect:
		return sdpb.LinkType_LINK_TYPE_DIRECT
	case snet.LinkTypeMultihop:
		return sdpb.LinkType_LINK_TYPE_MULTI_HOP
	case snet.LinkTypeOpennet:
		return sdpb.LinkType_LINK_TYPE_OPEN_NET
	default:
		return sdpb.LinkType_LINK_TYPE_UNSPECIFIED
	}
}

func (s *DaemonServer) backgroundPaths(origCtx context.Context, src, dst addr.IA, refresh bool) {
	backgroundTimeout := 5 * time.Second
	deadline, ok := origCtx.Deadline()
	if !ok || time.Until(deadline) > backgroundTimeout {
		// the original context is large enough no need to spin a background fetch.
		return
	}
	ctx, cancelF := context.WithTimeout(context.Background(), backgroundTimeout)
	defer cancelF()
	var spanOpts []opentracing.StartSpanOption
	if span := opentracing.SpanFromContext(origCtx); span != nil {
		spanOpts = append(spanOpts, opentracing.FollowsFrom(span.Context()))
	}
	span, ctx := opentracing.StartSpanFromContext(ctx, "fetch.paths.background", spanOpts...)
	defer span.Finish()
	if _, err := s.fetchPaths(ctx, &s.backgroundPathDedupe, src, dst, refresh); err != nil {
		log.FromCtx(ctx).Debug("Error fetching paths (background)", "err", err,
			"src", src, "dst", dst, "refresh", refresh)
	}
}

// AS serves the AS request.
func (s *DaemonServer) AS(ctx context.Context, req *sdpb.ASRequest) (*sdpb.ASResponse, error) {
	start := time.Now()
	response, err := s.as(ctx, req)
	s.Metrics.ASRequests.inc(
		reqLabels{Result: errToMetricResult(err)},
		time.Since(start).Seconds(),
	)
	return response, unwrapMetricsError(err)
}

func (s *DaemonServer) as(ctx context.Context, req *sdpb.ASRequest) (*sdpb.ASResponse, error) {
	reqIA := addr.IA(req.IsdAs)
	if reqIA.IsZero() {
		reqIA = s.IA
	}
	mtu := uint32(0)
	if reqIA.Equal(s.IA) {
		mtu = uint32(s.MTU)
	}
	core, err := s.ASInspector.HasAttributes(ctx, reqIA, trust.Core)
	if err != nil {
		log.FromCtx(ctx).Error("Inspecting ISD-AS", "err", err, "isd_as", reqIA)
		return nil, serrors.WrapStr("inspecting ISD-AS", err, "isd_as", reqIA)
	}
	reply := &sdpb.ASResponse{
		IsdAs: uint64(reqIA),
		Core:  core,
		Mtu:   mtu,
	}
	return reply, nil
}

// Interfaces serves the interfaces request.
func (s *DaemonServer) Interfaces(ctx context.Context,
	req *sdpb.InterfacesRequest) (*sdpb.InterfacesResponse, error) {

	start := time.Now()
	response, err := s.interfaces(ctx, req)
	s.Metrics.InterfacesRequests.inc(
		reqLabels{Result: errToMetricResult(err)},
		time.Since(start).Seconds(),
	)
	return response, unwrapMetricsError(err)
}

func (s *DaemonServer) interfaces(ctx context.Context,
	_ *sdpb.InterfacesRequest) (*sdpb.InterfacesResponse, error) {

	reply := &sdpb.InterfacesResponse{
		Interfaces: make(map[uint64]*sdpb.Interface),
	}
	topo := s.Topology
	for _, ifID := range topo.InterfaceIDs() {
		nextHop := topo.UnderlayNextHop(ifID)
		if nextHop == nil {
			continue
		}
		reply.Interfaces[uint64(ifID)] = &sdpb.Interface{
			Address: &sdpb.Underlay{
				Address: nextHop.String(),
			},
		}
	}
	return reply, nil
}

// Services serves the services request.
func (s *DaemonServer) Services(ctx context.Context,
	req *sdpb.ServicesRequest) (*sdpb.ServicesResponse, error) {

	start := time.Now()
	respsonse, err := s.services(ctx, req)
	s.Metrics.ServicesRequests.inc(
		reqLabels{Result: errToMetricResult(err)},
		time.Since(start).Seconds(),
	)
	return respsonse, unwrapMetricsError(err)
}

func (s *DaemonServer) services(ctx context.Context,
	_ *sdpb.ServicesRequest) (*sdpb.ServicesResponse, error) {

	reply := &sdpb.ServicesResponse{
		Services: make(map[string]*sdpb.ListService),
	}
	list := &sdpb.ListService{}
	for _, h := range s.Topology.ControlServiceAddresses() {
		// TODO(lukedirtwalker): build actual URI after it's defined (anapapaya/scion#3587)
		list.Services = append(list.Services, &sdpb.Service{Uri: h.String()})
	}
	reply.Services[topology.Control.String()] = list
	return reply, nil
}

// NotifyInterfaceDown notifies the server about an interface that is down.
func (s *DaemonServer) NotifyInterfaceDown(ctx context.Context,
	req *sdpb.NotifyInterfaceDownRequest) (*sdpb.NotifyInterfaceDownResponse, error) {

	start := time.Now()
	response, err := s.notifyInterfaceDown(ctx, req)
	s.Metrics.InterfaceDownNotifications.inc(
		ifDownLabels{Result: errToMetricResult(err), Src: "notification"},
		time.Since(start).Seconds(),
	)
	return response, unwrapMetricsError(err)
}

func (s *DaemonServer) notifyInterfaceDown(ctx context.Context,
	req *sdpb.NotifyInterfaceDownRequest) (*sdpb.NotifyInterfaceDownResponse, error) {

	revInfo := &path_mgmt.RevInfo{
		RawIsdas:     addr.IA(req.IsdAs),
		IfID:         common.IFIDType(req.Id),
		LinkType:     proto.LinkType_core,
		RawTTL:       10,
		RawTimestamp: util.TimeToSecs(time.Now()),
	}
	_, err := s.RevCache.Insert(ctx, revInfo)
	if err != nil {
		log.FromCtx(ctx).Error("Inserting revocation", "err", err, "req", req)
		return nil, metricsError{
			err:    serrors.WrapStr("inserting revocation", err),
			result: prom.ErrDB,
		}
	}
	return &sdpb.NotifyInterfaceDownResponse{}, nil
}

// PortRange returns the port range for the dispatched ports.
func (s *DaemonServer) PortRange(
	_ context.Context,
	_ *emptypb.Empty,
) (*sdpb.PortRangeResponse, error) {

	startPort, endPort := s.Topology.PortRange()
	return &sdpb.PortRangeResponse{
		DispatchedPortStart: uint32(startPort),
		DispatchedPortEnd:   uint32(endPort),
	}, nil
}

func (s *DaemonServer) FabridKeys(ctx context.Context, req *pb_daemon.FabridKeysRequest,
) (*pb_daemon.FabridKeysResponse, error) {
	if s.DRKeyClient == nil {
		return nil, serrors.New("DRKey is not available")
	}
	pathASes := make([]addr.IA, 0, len(req.PathAses))
	for _, as := range req.PathAses {
		pathASes = append(pathASes, addr.IA(as))
	}
	resp, err := s.DRKeyClient.FabridKeys(ctx, drkey.FabridKeysMeta{
		SrcAS:    s.DRKeyClient.IA,
		SrcHost:  req.SrcHost,
		DstHost:  req.DstHost,
		PathASes: pathASes,
		DstAS:    addr.IA(req.DstAs),
	})
	if err != nil {
		return nil, serrors.WrapStr("getting fabrid keys from client store", err)
	}
	fabridKeys := make([]*pb_daemon.FabridKeyResponse, 0, len(resp.ASHostKeys))
	for i := range resp.ASHostKeys {
		key := resp.ASHostKeys[i]
		fabridKeys = append(fabridKeys, &sdpb.FabridKeyResponse{
			EpochBegin: &timestamppb.Timestamp{Seconds: key.Epoch.NotBefore.Unix()},
			EpochEnd:   &timestamppb.Timestamp{Seconds: key.Epoch.NotAfter.Unix()},
			Key:        key.Key[:],
		})
	}

	var hostHostKey *sdpb.FabridKeyResponse = nil
	if req.DstHost != nil {
		hostHostKey = &sdpb.FabridKeyResponse{
			EpochBegin: &timestamppb.Timestamp{Seconds: resp.PathKey.Epoch.NotBefore.Unix()},
			EpochEnd:   &timestamppb.Timestamp{Seconds: resp.PathKey.Epoch.NotAfter.Unix()},
			Key:        resp.PathKey.Key[:],
		}
	}
	return &pb_daemon.FabridKeysResponse{
		AsHostKeys:  fabridKeys,
		HostHostKey: hostHostKey,
	}, nil
}

func (s *DaemonServer) DRKeyASHost(
	ctx context.Context,
	req *pb_daemon.DRKeyASHostRequest,
) (*pb_daemon.DRKeyASHostResponse, error) {

	if s.DRKeyClient == nil {
		return nil, serrors.New("DRKey is not available")
	}
	meta, err := requestToASHostMeta(req)
	if err != nil {
		return nil, serrors.WrapStr("parsing protobuf ASHostReq", err)
	}

	lvl2Key, err := s.DRKeyClient.GetASHostKey(ctx, meta)
	if err != nil {
		return nil, serrors.WrapStr("getting AS-Host from client store", err)
	}

	return &sdpb.DRKeyASHostResponse{
		EpochBegin: &timestamppb.Timestamp{Seconds: lvl2Key.Epoch.NotBefore.Unix()},
		EpochEnd:   &timestamppb.Timestamp{Seconds: lvl2Key.Epoch.NotAfter.Unix()},
		Key:        lvl2Key.Key[:],
	}, nil
}

func (s *DaemonServer) DRKeyHostAS(
	ctx context.Context,
	req *pb_daemon.DRKeyHostASRequest,
) (*pb_daemon.DRKeyHostASResponse, error) {

	if s.DRKeyClient == nil {
		return nil, serrors.New("DRKey is not available")
	}
	meta, err := requestToHostASMeta(req)
	if err != nil {
		return nil, serrors.WrapStr("parsing protobuf HostASReq", err)
	}

	lvl2Key, err := s.DRKeyClient.GetHostASKey(ctx, meta)
	if err != nil {
		return nil, serrors.WrapStr("getting Host-AS from client store", err)
	}

	return &sdpb.DRKeyHostASResponse{
		EpochBegin: &timestamppb.Timestamp{Seconds: lvl2Key.Epoch.NotBefore.Unix()},
		EpochEnd:   &timestamppb.Timestamp{Seconds: lvl2Key.Epoch.NotAfter.Unix()},
		Key:        lvl2Key.Key[:],
	}, nil
}

func (s *DaemonServer) DRKeyHostHost(
	ctx context.Context,
	req *pb_daemon.DRKeyHostHostRequest,
) (*pb_daemon.DRKeyHostHostResponse, error) {

	if s.DRKeyClient == nil {
		return nil, serrors.New("DRKey is not available")
	}
	meta, err := requestToHostHostMeta(req)
	if err != nil {
		return nil, serrors.WrapStr("parsing protobuf HostHostReq", err)
	}
	lvl2Key, err := s.DRKeyClient.GetHostHostKey(ctx, meta)
	if err != nil {
		return nil, serrors.WrapStr("getting Host-Host from client store", err)
	}

	return &sdpb.DRKeyHostHostResponse{
		EpochBegin: &timestamppb.Timestamp{Seconds: lvl2Key.Epoch.NotBefore.Unix()},
		EpochEnd:   &timestamppb.Timestamp{Seconds: lvl2Key.Epoch.NotAfter.Unix()},
		Key:        lvl2Key.Key[:],
	}, nil
}

func requestToASHostMeta(req *sdpb.DRKeyASHostRequest) (drkey.ASHostMeta, error) {
	err := req.ValTime.CheckValid()
	if err != nil {
		return drkey.ASHostMeta{}, serrors.WrapStr("invalid valTime from pb request", err)
	}
	return drkey.ASHostMeta{
		ProtoId:  drkey.Protocol(req.ProtocolId),
		Validity: req.ValTime.AsTime(),
		SrcIA:    addr.IA(req.SrcIa),
		DstIA:    addr.IA(req.DstIa),
		DstHost:  req.DstHost,
	}, nil
}

func requestToHostASMeta(req *sdpb.DRKeyHostASRequest) (drkey.HostASMeta, error) {
	err := req.ValTime.CheckValid()
	if err != nil {
		return drkey.HostASMeta{}, serrors.WrapStr("invalid valTime from pb request", err)
	}
	return drkey.HostASMeta{
		ProtoId:  drkey.Protocol(req.ProtocolId),
		Validity: req.ValTime.AsTime(),
		SrcIA:    addr.IA(req.SrcIa),
		DstIA:    addr.IA(req.DstIa),
		SrcHost:  req.SrcHost,
	}, nil
}

func requestToHostHostMeta(req *sdpb.DRKeyHostHostRequest) (drkey.HostHostMeta, error) {
	err := req.ValTime.CheckValid()
	if err != nil {
		return drkey.HostHostMeta{}, serrors.WrapStr("invalid valTime from pb request", err)
	}
	return drkey.HostHostMeta{
		ProtoId:  drkey.Protocol(req.ProtocolId),
		Validity: req.ValTime.AsTime(),
		SrcIA:    addr.IA(req.SrcIa),
		DstIA:    addr.IA(req.DstIa),
		SrcHost:  req.SrcHost,
		DstHost:  req.DstHost,
	}, nil
}
