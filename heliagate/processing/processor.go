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

package processing

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"math/rand"
	"net"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/sync/errgroup"

	"github.com/scionproto/scion/heliagate/storage"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/experimental/helia"
	common "github.com/scionproto/scion/pkg/experimental/heliagate"
	"github.com/scionproto/scion/pkg/experimental/heliagate/config"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/sock/reliable"
	"github.com/scionproto/scion/private/app"
	"github.com/scionproto/scion/private/topology"
)

type Processor struct {
	dataChannels  []chan *dataPacket
	reservChannel chan *dataPacket
	responseChan  chan *snet.Packet
	storage       *storage.Storage
	borderRouters map[uint16]*ipv4.PacketConn
	saltHasher    common.SaltHasher
	exit          bool
	numWorkers    int
	gatewayAddr   snet.UDPAddr
	ctrlPort      int
	sdAddr        string
	mac           hash.Hash
	ctx           context.Context
}

// BufSize is the maximum size of a datapacket including all the headers.
const bufSize int = 9000

// NumOfMessages is the maximum number of messages that are read as a batch from the socket.
const numOfMessages int = 10

func (p *Processor) shutdown() {
	log.Debug("Heliagate: Shutting down")
	if p.exit {
		return
	}
	p.exit = true
	p.reservChannel <- nil
	p.responseChan <- nil
	for i := 0; i < len(p.dataChannels); i++ {
		p.dataChannels[i] <- nil
	}
}

// Init initializes the helia gateway. Configures the channels, goroutines,
// and the data plane.
func Init(
	ctx context.Context, cfg *config.Config, cleanup *app.Cleanup,
	g *errgroup.Group, topo *topology.Loader,
) error {

	heliagateCfg := &cfg.Heliagate
	borderRouters := make(map[uint16]*ipv4.PacketConn)
	for ifid, info := range topo.InterfaceInfoMap() {
		conn, _ := net.DialUDP("udp", nil, info.InternalAddr)
		borderRouters[uint16(ifid)] = ipv4.NewPacketConn(conn)
		log.Debug("Heliagate: Connected to border router", "ifid", ifid,
			"internal_addr", info.InternalAddr)
	}

	heliagateInfo, err := topo.HeliaGateway(cfg.General.ID)
	if err != nil {
		return serrors.WrapStr("Heliagate not found in topology", err)
	}
	log.Debug(
		"Heliagate: Config loaded", "address", heliagateInfo.Addr, "name", heliagateInfo.Name,
		"egresses", heliagateInfo.Egresses,
	)

	localAS := topo.IA().AS()

	// Loads the salt for load balancing from the config.
	// If the salt is empty a random value will be chosen
	salt := []byte(heliagateCfg.Salt)
	if heliagateCfg.Salt == "" {
		salt := make([]byte, 16)
		rand.Read(salt)
	}
	mac, _ := scrypto.InitMac(helia.TESTING_KEY())
	p := Processor{
		dataChannels:  make([]chan *dataPacket, heliagateCfg.NumWorkers),
		borderRouters: borderRouters,
		saltHasher:    common.NewFnv1aHasher(salt),
		numWorkers:    heliagateCfg.NumWorkers,
		gatewayAddr: snet.UDPAddr{
			IA:      topo.IA(),
			Path:    nil,
			NextHop: nil,
			Host:    heliagateInfo.Addr,
		},
		sdAddr:  cfg.Daemon.Address,
		mac:     mac,
		ctx:     ctx,
		storage: &storage.Storage{},
	}
	p.storage.InitStorage()

	cleanup.Add(
		func() error {
			p.shutdown()
			return nil
		},
	)

	// Creates all the channels and starts the go routines
	for i := 0; i < p.numWorkers; i++ {
		p.dataChannels[i] = make(chan *dataPacket, heliagateCfg.MaxQueueSizePerWorker)
		func(i int) {
			g.Go(
				func() error {
					defer log.HandlePanic()
					return p.workerReceiveEntry(
						heliagateCfg,
						uint32(i), 1, localAS,
					)
				},
			)
		}(i)
	}

	// Create a reservation worker and corresponding channel
	p.reservChannel = make(chan *dataPacket, heliagateCfg.MaxQueueSizePerWorker)
	p.responseChan = make(chan *snet.Packet, 10)
	g.Go(
		func() error {
			defer log.HandlePanic()
			return p.workerCreateReservation()
		},
	)

	if err := p.initDataPlane(heliagateCfg, heliagateInfo.Addr, g, cleanup); err != nil {
		return err
	}

	return nil
}

type ignoreSCMP struct{}

func (ignoreSCMP) Handle(pkt *snet.Packet) error {
	return nil
}

// The function to initialize the data plane of the colibri gateway.
func (p *Processor) initDataPlane(
	config *config.Heliagate, gatewayAddr *net.UDPAddr,
	g *errgroup.Group, cleanup *app.Cleanup,
) error {

	svc := snet.DefaultPacketDispatcherService{
		Dispatcher:  reliable.NewDispatcher(""),
		SCMPHandler: ignoreSCMP{},
	}
	local := p.gatewayAddr.Copy()
	local.Host.Port = 0
	ctrlConn, port, err := svc.Register(p.ctx, p.gatewayAddr.IA, local.Host, addr.SvcNone)
	if err != nil {
		return err
	}
	cleanup.Add(func() error { ctrlConn.Close(); return nil })

	p.ctrlPort = int(port)

	log.Debug("Heliagate: Ctrl connection registered", "port", port)
	udpConn, err := net.ListenUDP("udp", gatewayAddr)
	if err != nil {
		return err
	}
	cleanup.Add(func() error { udpConn.Close(); return nil })
	msgs := make([]ipv4.Message, numOfMessages)
	for i := 0; i < numOfMessages; i++ {
		msgs[i].Buffers = [][]byte{make([]byte, bufSize)}
	}

	var ipv4Conn *ipv4.PacketConn = ipv4.NewPacketConn(udpConn)

	// Handle data packets
	g.Go(
		func() error {
			defer log.HandlePanic()

			for !p.exit {
				numPkts, err := ipv4Conn.ReadBatch(msgs, syscall.MSG_WAITFORONE)
				if err != nil {
					log.Debug("error while reading from network", "err", err)
					continue
				}
				if numPkts == 0 {
					continue
				}
				for _, pkt := range msgs[:numPkts] {
					var d *dataPacket

					d, err = Parse(pkt.Buffers[0][:pkt.N])
					if err != nil {
						log.Debug("error while parsing headers", "err", err)
						continue
					}
					if int(d.scionLayer.PayloadLen) != len(d.scionLayer.Payload) {
						// Packet too large or inconsistent payload size.
						continue
					}
					d.pktArrivalTime = time.Now()

					// assign to worker by scionlayer.flowid
					select {
					case p.dataChannels[p.getWorkerForMessage(d.scionLayer.FlowID, pkt.Addr)] <- d:
					default:
						continue // Packet dropped
					}
				}
			}
			return nil
		},
	)

	// Handle control packets
	g.Go(
		func() error {
			defer log.HandlePanic()

			for !p.exit {
				var pkt snet.Packet
				var ov net.UDPAddr
				if err := ctrlConn.ReadFrom(&pkt, &ov); err != nil {
					return serrors.WrapStr("reading control packet", err)
				}
				select {
				case p.responseChan <- &pkt:
				default:
					log.Debug("Ctrl packet dropped")
					continue // Packet dropped
				}

			}
			return nil
		},
	)
	return nil
}

func (p *Processor) getWorkerForMessage(flowID uint32, source net.Addr) uint32 {
	srcBytes := []byte(source.String())
	buf := make([]byte, 4+len(srcBytes))
	binary.BigEndian.PutUint32(buf, flowID)
	buf = append(buf, srcBytes...)
	return p.saltHasher.Hash(buf) % uint32(p.numWorkers)
}

// Internal method to get the address of the corresponding border router
// to forward the outgoing packets
func (p *Processor) getBorderRouterConnection(proc *dataPacket) (*ipv4.PacketConn, error) {
	hop, err := proc.scionPath.GetCurrentHopField()
	if err != nil {
		return nil, err
	}
	egressId := hop.ConsIngress
	conn, found := p.borderRouters[egressId]
	if !found {
		return nil, serrors.New("egress interface is invalid:", "egressId", egressId)
	}
	return conn, nil
}

// Configures a goroutine to listen for the data plane channel and control plane reservation updates
func (p *Processor) workerReceiveEntry(
	config *config.Heliagate, workerId uint32,
	gatewayId uint32, localAS addr.AS,
) error {

	log.Info("Heliagate: Init traffic worker", "workerId", workerId)
	//worker := NewWorker(config, workerId, gatewayId, localAS)

	writeMsgs := make([]ipv4.Message, 1)
	writeMsgs[0].Buffers = [][]byte{make([]byte, bufSize)}

	ch := p.dataChannels[workerId]

	for !p.exit {
		d := <-ch     // Data plane packet received
		if d == nil { //If d is nil it is meant to be a exit sequence
			return nil
		}
		borderRouterConn, err := p.getBorderRouterConnection(d)
		if err != nil {
			log.Debug("Error getting border router connection", "err", err)
			//workerPacketInInvalidPromCounter.Add(1)
			continue
		}

		// if fingerprint not in map, call reservation routine to parse path and request
		// reservations. Otherwise, lookup available authenticator for triplets
		path, found := p.storage.GetPath(d.fingerprint)
		if !found {
			p.reservChannel <- d
		} else {
			optParams := slayers.PacketReservTrafficParams{}
			for _, hop := range path.Hops {
				reservation, found := p.storage.GetReservation(hop)
				if !found {
					log.Debug("Missing reservation", "hop", hop)
					continue
				}
				if reservation.Status == storage.Available {
					h := sha256.New()
					err := binary.Write(h, binary.BigEndian, hop.IA)
					if err != nil {
						return err
					}
					rf := slayers.ReservationField{
						ASHash: h.Sum(nil)[0],
					}
					copy(rf.RVF[:], reservation.Authenticator)
					optParams.ReservHopFields = append(optParams.ReservHopFields, rf)
				}
			}
			if len(optParams.ReservHopFields) > 0 {
				optParams.Direction = 0
				optParams.CurrRF = 0
				optParams.MaxBackwardLen = 1000
				optParams.TsPkt = uint64(time.Now().UnixNano())
				trafficOpt, _ := slayers.NewPacketReservTrafficOption(optParams)
				err := packTrafficPacket(trafficOpt, optParams.ReservHopFields, d)
				if err != nil {
					return serrors.WrapStr("Failed to pack traffic packet", err)
				}
				log.Debug(
					"Heliagate: Sending traffic packet", "dst", d.scionLayer.DstIA,
					"numHops", len(path.Hops), "numReservations", len(optParams.ReservHopFields),
					"tsPkt", time.UnixMicro(int64(optParams.TsPkt)/1000), "workerID", workerId,
				)
			}

		}

		writeMsgs[0].Buffers[0] = d.rawPacket

		_, err = borderRouterConn.WriteBatch(writeMsgs, syscall.MSG_DONTWAIT)
		if err != nil {
			return err
		}

	}
	return nil
}

func (p *Processor) workerCreateReservation() error {
	daemonService := &daemon.Service{
		Address: p.sdAddr,
	}
	sd, err := daemonService.Connect(p.ctx)
	if err != nil {
		return serrors.WrapStr("connecting to daemon", err)
	}
	defer sd.Close()
	log.Info("Heliagate: Init reservation worker", "sd", p.sdAddr)
	requestMacBuffer := make([]byte, helia.MACBufferSize)
	for !p.exit {
		select {
		case d := <-p.reservChannel:
			if d == nil { //If d is nil it is meant to be a exit sequence
				return nil
			}
			_, found := p.storage.GetPath(d.fingerprint)
			if found {
				continue
			}
			// 1. Packet
			// Parse ASes
			// Lookup existing reservations
			// Request missing reservation (with timeout and re-request)
			paketPath, hops, err := getHopsFromPacket(d, sd, p.ctx)
			if err != nil {
				return err
			}

			// store fingerprint and triplets in map
			path := &storage.Path{
				Fingerprint: d.fingerprint,
				Hops:        hops,
			}

			borderRouterConn, err := p.getBorderRouterConnection(d)
			if err != nil {
				log.Debug("Error getting border router connection", "err", err)
				continue
			}

			p.storage.StorePath(path)
			for hop := range hops {
				if _, found := p.storage.GetReservation(hops[hop]); !found {
					err := p.storage.CreateReservation(&hops[hop], false)
					if err != nil {
						return err
					}
				}
				err = p.sendRequest(paketPath, hops[hop], borderRouterConn, false, requestMacBuffer)
				if err != nil {
					return err
				}
			}

		case pkt := <-p.responseChan:
			if pkt == nil { // If pkt is nil it is meant to be an exit sequence
				return nil
			}
			resp, err := slayers.ParsePacketReservResponseOption(pkt.HopByHopOption)
			if err != nil {
				return err
			}
			hop := storage.Hop{
				IA:      resp.ReservAS(),
				Ingress: resp.IngressIF(),
				Egress:  resp.EgressIF(),
			}
			reservation, found := p.storage.GetReservation(hop)
			if !found {
				log.Debug(
					"Failed to find reservation:", "hop", hop,
				)
			}

			reservation.Status = storage.Available
			reservation.Timestamp = resp.TsExp()
			reservation.Authenticator = resp.AuthEnc()
			p.storage.StoreReservation(&reservation)
			log.Debug(
				"Heliagate: Processed reservation response", "targetAS", resp.ReservAS(),
				"ingressIF", resp.IngressIF(), "egressIF", resp.EgressIF(),
				"bandwidth", resp.Bandwidth(), "tsExp", time.UnixMilli(int64(resp.TsExp())),
				"authenticator", resp.AuthEnc(),
			)
		}
	}
	return nil
}

func (p *Processor) sendRequest(
	path snet.Path, hop storage.Hop, conn *ipv4.PacketConn, backward bool, buffer []byte,
) error {
	req := &helia.ReservationRequest{
		Target:    hop.IA,
		Counter:   helia.PktCounterFromCore(1, 2, 3),
		IngressIF: hop.Ingress,
		EgressIF:  hop.Egress,
		Timestamp: uint64(time.Now().UnixMilli()),
		Backward:  backward,
	}
	setupOpt := helia.CreateSetupRequest(p.mac, req, buffer)
	pkt := &snet.Packet{
		PacketInfo: snet.PacketInfo{
			Destination: snet.SCIONAddress{
				IA:   path.Destination(),
				Host: addr.HostIPv4(net.ParseIP("0.0.0.0").To4()), //Add empty host IP (0.0.0.0)
			},
			Source: snet.SCIONAddress{
				IA:   p.gatewayAddr.IA,
				Host: addr.HostFromIP(p.gatewayAddr.Host.IP), // Gateway address
			},
			Path: path.Dataplane(),
			Payload: snet.UDPPayload{
				SrcPort: uint16(p.ctrlPort), // gateway port
				DstPort: 0,
			},
			HopByHopOption: setupOpt,
		},
	}
	writeMsgs := make([]ipv4.Message, 1)
	writeMsgs[0].Buffers = [][]byte{make([]byte, bufSize)}
	err := pkt.Serialize()
	if err != nil {
		return err
	}
	writeMsgs[0].Buffers[0] = pkt.Bytes

	_, err = conn.WriteBatch(writeMsgs, syscall.MSG_DONTWAIT)
	if err != nil {
		return err
	}
	log.Debug("Heliagate: Reservation request sent", "reservReq", req)
	return nil
}
