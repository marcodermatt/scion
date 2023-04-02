package processing

import (
	"context"
	"encoding/binary"
	"fmt"
	"hash"
	"math/rand"
	"net"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/scionproto/scion/heliagate/storage"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/experimental/helia"
	common "github.com/scionproto/scion/pkg/experimental/heliagate"
	config2 "github.com/scionproto/scion/pkg/experimental/heliagate/config"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/sock/reliable"
	"github.com/scionproto/scion/private/app"
	"github.com/scionproto/scion/private/app/path"
	"github.com/scionproto/scion/private/topology"
	"golang.org/x/net/ipv4"
	"golang.org/x/sync/errgroup"
)

type Processor struct {
	dataChannels  []chan *dataPacket
	reservChannel chan *dataPacket
	responseChan  chan *snet.Packet
	storage       *storage.Storage
	//cleanupChannel  chan *storage.UpdateTask
	borderRouters map[uint16]*ipv4.PacketConn
	saltHasher    common.SaltHasher
	exit          bool
	numWorkers    int
	gatewayAddr   snet.UDPAddr
	ctrlPort      int
	mac           hash.Hash
	ctx           context.Context
}

// BufSize is the maximum size of a datapacket including all the headers.
const bufSize int = 9000

// NumOfMessages is the maximum number of messages that are read as a batch from the socket.
const numOfMessages int = 10

func (c *Processor) shutdown() {
	if c.exit {
		return
	}
	c.exit = true
	for i := 0; i < len(c.dataChannels); i++ {
		c.dataChannels[i] <- nil
	}
}

// Init initializes the helia gateway. Configures the channels, goroutines,
// and the control plane and the data plane.
func Init(
	ctx context.Context, cfg *config2.Config, cleanup *app.Cleanup,
	g *errgroup.Group, topo *topology.Loader,
) error {

	config := &cfg.Heliagate
	var borderRouters map[uint16]*ipv4.PacketConn = make(map[uint16]*ipv4.PacketConn)
	for ifid, info := range topo.InterfaceInfoMap() {
		conn, _ := net.DialUDP("udp", nil, info.InternalAddr)
		borderRouters[uint16(ifid)] = ipv4.NewPacketConn(conn)
		log.Debug("Found Border Router", "ifid", ifid, "internal_addr", info.InternalAddr)
	}

	heliagateInfo, err := topo.HeliaGateway(cfg.General.ID)
	if err != nil {
		return serrors.WrapStr("Heliagate not found in topology", err)
	}
	log.Debug(
		"Heliagate address resolved", "address", heliagateInfo.Addr, "name", heliagateInfo.Name,
		"egresses", heliagateInfo.Egresses,
	)

	localAS := topo.IA().AS()

	// Loads the salt for load balancing from the config.
	// If the salt is empty a random value will be chosen
	salt := []byte(config.Salt)
	if config.Salt == "" {
		salt := make([]byte, 16)
		rand.Read(salt)
	}
	STATIC_KEY := []byte("f5fcc4ce2250db36")
	mac, _ := scrypto.InitMac(STATIC_KEY)
	p := Processor{
		dataChannels:  make([]chan *dataPacket, 1),
		borderRouters: borderRouters,
		saltHasher:    common.NewFnv1aHasher(salt),
		numWorkers:    1,
		gatewayAddr: snet.UDPAddr{
			IA:      topo.IA(),
			Path:    nil,
			NextHop: nil,
			Host:    heliagateInfo.Addr,
		},
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
		p.dataChannels[i] = make(chan *dataPacket, config.MaxQueueSizePerWorker)
		//p.controlChannels[i] = make(chan storage.Task, config.MaxQueueSizePerWorker,)
		func(i int) {
			g.Go(
				func() error {
					defer log.HandlePanic()
					return p.workerReceiveEntry(
						config,
						uint32(i), 1, localAS,
					)
				},
			)
		}(i)
	}

	// Create a reservation worker and corresponding channel
	p.reservChannel = make(chan *dataPacket, config.MaxQueueSizePerWorker)
	p.responseChan = make(chan *snet.Packet, 10)
	g.Go(
		func() error {
			defer log.HandlePanic()
			return p.workerCreateReservation()
		},
	)

	g.Go(
		func() error {
			defer log.HandlePanic()
			//p.initCleanupRoutine()
			return nil
		},
	)

	/*
		g.Go(
			func() error {
				defer log.HandlePanic()
				return p.initControlPlane(config, cleanup, grpcAddr)
			},
		)
	*/
	if err := p.initDataPlane(config, heliagateInfo.Addr, g, cleanup); err != nil {
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
	config *config2.Heliagate, gatewayAddr *net.UDPAddr,
	g *errgroup.Group, cleanup *app.Cleanup,
) error {

	log.Info("Init data plane")
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

	log.Debug("Helia gateway registered", "port", port)
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
				log.Debug("received data packets")
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
					case p.dataChannels[p.getWorkerForFlowId(d.scionLayer.FlowID)] <- d:
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
				log.Debug("Received ctrl packet", "hbh option", pkt.HopByHopOption)
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

func (p *Processor) getWorkerForFlowId(flowId uint32) uint32 {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, flowId)
	return p.saltHasher.Hash(buf) % uint32(p.numWorkers)
}

// Internal method to get the address of the corresponding border router
// to forward the outgoing packets
func (p *Processor) getBorderRouterConnection(proc *dataPacket) (*ipv4.PacketConn, error) {
	hop, err := proc.scionPath.GetCurrentHopField()
	if err != nil {
		return nil, err
	}
	log.Debug("Getting BR interface", "currentHopField", hop)
	egressId := hop.ConsIngress
	conn, found := p.borderRouters[egressId]
	if !found {
		return nil, serrors.New("egress interface is invalid:", "egressId", egressId)
	}
	return conn, nil
}

// Configures a goroutine to listen for the data plane channel and control plane reservation updates
func (p *Processor) workerReceiveEntry(
	config *config2.Heliagate, workerId uint32,
	gatewayId uint32, localAS addr.AS,
) error {

	log.Info("Init worker", "workerId", workerId)
	//worker := NewWorker(config, workerId, gatewayId, localAS)

	writeMsgs := make([]ipv4.Message, 1)
	writeMsgs[0].Buffers = [][]byte{make([]byte, bufSize)}

	ch := p.dataChannels[workerId]
	//chres := p.controlChannels[workerId]

	for !p.exit {
		select {
		case d := <-ch: // Data plane packet received
			if d == nil { //If d is nil it is meant to be a exit sequence
				return nil
			}
			log.Debug("Worker received data packet", "workerId", workerId)
			borderRouterConn, err := p.getBorderRouterConnection(d)
			if err != nil {
				log.Debug("Error getting border router connection", "err", err)
				//workerPacketInInvalidPromCounter.Add(1)
				continue
			}

			// if fingerprint not in map, call reservation routine to parse path and request reservations
			// otherwise, lookup available authenticator for triplets
			path, found := p.storage.Paths[d.fingerprint]
			if !found {
				p.reservChannel <- d
			} else {
				optParams := slayers.PacketReservTrafficParams{}
				for _, hop := range path.Hops {
					reservation := p.storage.Reservations[hop]
					if reservation.Status == storage.Available {
						rf := slayers.ReservationHopField{
							ASHash: byte(hop.IA),
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
					hbh := &slayers.HopByHopExtn{}
					hbh.NextHdr = d.scionLayer.NextHdr
					hbh.Options = []*slayers.HopByHopOption{trafficOpt.HopByHopOption}
					buffer := gopacket.NewSerializeBuffer()
					options := gopacket.SerializeOptions{
						ComputeChecksums: false,
						FixLengths:       true,
					}
					if err := hbh.SerializeTo(buffer, options); err != nil {
						return err
					}
					offset := d.scionLayer.HdrLen * 4
					extLen := uint8(len(buffer.Bytes()))
					pktLen := d.scionLayer.PayloadLen
					d.rawPacket[4] = uint8(slayers.HopByHopClass)
					binary.BigEndian.PutUint16(d.rawPacket[6:8], pktLen+uint16(extLen))
					log.Debug(
						"Sending traffic packet", "offset", offset, "extLen", extLen, "payloadLen",
						pktLen, "newPayloadLen", binary.BigEndian.Uint16(d.rawPacket[6:8]),
						"buffer_cap", cap(d.rawPacket),
					)
					d.rawPacket = append(d.rawPacket, buffer.Bytes()...)
					d.rawPacket = append(
						d.rawPacket[:offset+extLen], d.rawPacket[offset:uint16(offset)+pktLen]...,
					)
					copy(d.rawPacket[offset:offset+extLen], buffer.Bytes())
				}

			}

			// 1. Packet
			// Parse ASes
			// Lookup existing reservations
			// Request missing reservation (with timeout and re-request)

			// 2. Packet
			// Return  already present reservations
			// getReservation(path.fingerprint) -> [Token, Token, Token, Token, _]

			// map[fingerprint] path (list of triplets(AS, Ingress, Egress)
			// map[reservTriplet] authenticators and timestamp

			// Direct forwarding: small latency

			// Parse ASes (SD call): medium/high latency
			// Request missing reservations: high latency

			// reservation routine: atomic write to datastructure

			// worker routines: reads without lock

			//if err = worker.process(d); err != nil {
			//log.Debug("Worker received error while processing.", "workerId", workerId,
			//"error", err.Error())
			//workerPacketInInvalidPromCounter.Add(1)
			//continue
			//}

			writeMsgs[0].Buffers[0] = d.rawPacket

			borderRouterConn.WriteBatch(writeMsgs, syscall.MSG_DONTWAIT)
			//workerPacketOutTotalPromCounter.Add(1)
			log.Debug("Worker forwarded packet", "workerId", workerId)
			//case task := <-chres: // Reservation update received
			//if task == nil {
			//return nil
			//}
			//log.Debug("Worker received reservation update", "workerId", workerId)
			//workerReservationUpdateTotalPromCounter.Add(1)
			//task.Execute(worker.Storage)
		}

	}
	return nil
}

func (p *Processor) workerCreateReservation() error {
	daemonService := &daemon.Service{
		Address: "[fd00:f00d:cafe::7f00:16]:30255",
	}
	sd, err := daemonService.Connect(p.ctx)
	if err != nil {
		return serrors.WrapStr("connecting to daemon", err)
	}
	defer sd.Close()
	log.Debug("Reservation worker Init SD", "scionDaemon", sd)
	for !p.exit {
		select {
		case d := <-p.reservChannel:
			_, found := p.storage.Paths[d.fingerprint]
			if found {
				continue
			}
			if d == nil {
				return nil
			}
			log.Debug("Worker creating reservation")
			paketPath, hops, err := p.getHopsFromPacket(d, sd)
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
				//workerPacketInInvalidPromCounter.Add(1)
				continue
			}

			p.storage.StorePath(path)
			for hop := range hops {
				p.storage.CreateReservation(&hops[hop], false)
				err := p.sendRequest(paketPath, hops[hop], borderRouterConn, false)
				if err != nil {
					return err
				}
				// also request backward reservation, currently not stored
				err = p.sendRequest(paketPath, hops[hop], borderRouterConn, true)
				if err != nil {
					return err
				}
				p.storage.CreateReservation(&hops[hop], true)
			}

			// request reservations for triplets if necessary
			// use available reservations for requests

			//borderRouterConn, err := p.getBorderRouterConnection(d)
			//if err != nil {
			//log.Debug("Error getting border router connection", "err", err)
			////workerPacketInInvalidPromCounter.Add(1)
			//continue
			//}
		case pkt := <-p.responseChan:
			resp, err := slayers.ParsePacketReservResponseOption(pkt.HopByHopOption)
			if err != nil {
				return err
			}
			log.Debug(
				"Reservation worker processing response",
				"targetAS", resp.ReservAS(),
				"ingressIF", resp.IngressIF(),
				"egressIF", resp.EgressIF(),
				"bandwidth", resp.Bandwidth(),
				"tsExp", resp.TsExp(),
				"authenticator", resp.AuthEnc(),
			)
			hop := helia.Hop{
				IA:      resp.ReservAS(),
				Ingress: resp.IngressIF(),
				Egress:  resp.EgressIF(),
			}
			reservation, ok := p.storage.Reservations[hop]
			if !ok {
				log.Debug(
					"Failed to find reservation:", "hop", hop,
				)
			}

			reservation.Status = storage.Available
			reservation.Timestamp = resp.TsExp()
			reservation.Authenticator = resp.AuthEnc()
		}
	}
	return nil
}

func (p *Processor) sendRequest(
	path snet.Path, hop helia.Hop, conn *ipv4.PacketConn, backward bool,
) error {
	req := &helia.ReservationRequest{
		Target:    hop.IA,
		IngressIF: hop.Ingress,
		EgressIF:  hop.Egress,
		Backward:  backward,
		Timestamp: 0,
		Counter:   0,
	}
	setupOpt := helia.CreateSetupRequest(p.mac, req)
	pkt := &snet.Packet{
		PacketInfo: snet.PacketInfo{
			Destination: snet.SCIONAddress{
				IA:   hop.IA,
				Host: addr.HostIPv4(net.ParseIP("0.0.0.0").To4()), //ADd emtpy host IP (0.0.0.0)
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
	log.Debug("Sending request", "hop", hop, "payload", pkt.Payload)
	writeMsgs := make([]ipv4.Message, 1)
	writeMsgs[0].Buffers = [][]byte{make([]byte, bufSize)}
	err := pkt.Serialize()
	if err != nil {
		return err
	}
	writeMsgs[0].Buffers[0] = pkt.Bytes

	conn.WriteBatch(writeMsgs, syscall.MSG_DONTWAIT)
	return nil
}

func (p *Processor) getHopsFromPacket(
	d *dataPacket, sd daemon.Connector,
) (snet.Path, []helia.Hop, error) {
	decoded, err := d.scionPath.ToDecoded()
	if err != nil {
		return nil, nil, err
	}
	sequence := ""
	n := 0
	seg := 0
	nSeg := int(decoded.PathMeta.SegLen[seg])
	consDir := decoded.InfoFields[seg].ConsDir
	for i := 0; i < decoded.NumHops; i++ {
		hf := decoded.HopFields[i]
		log.Debug("Parsing hop", "i", i, "seg", seg, "consDir", consDir, "hf", hf)
		inIF := hf.ConsEgress
		outIF := hf.ConsIngress
		if consDir {
			inIF, outIF = outIF, inIF
		}
		if i == nSeg-1 {
			nNextSeg := int(decoded.PathMeta.SegLen[seg+1])

			if nNextSeg > 0 {
				seg++
				nSeg += nNextSeg
				consDir = decoded.InfoFields[seg].ConsDir

				i++
				hf := decoded.HopFields[i]
				log.Debug("Parsing switchover", "i", i, "seg", seg, "consDir", consDir, "hf", hf)
				if consDir {
					outIF = hf.ConsEgress
				} else {
					outIF = hf.ConsIngress
				}
			}
		}
		n++
		sequence += fmt.Sprintf("0-0#%d,%d ", inIF, outIF)
	}
	opts := []path.Option{
		path.WithSequence(sequence),
	}
	log.Debug("Before path request", "sequence", sequence)
	path, err := path.Choose(p.ctx, sd, d.scionLayer.DstIA, opts...)
	if err != nil {
		log.Error("Path not found", "error", err)
		return nil, nil, err
	}
	hops := make([]addr.IA, n)
	heliaHops := make([]helia.Hop, n)
	ifs := path.Metadata().Interfaces
	heliaHops[0] = helia.Hop{
		IA:      ifs[0].IA,
		Ingress: 0,
		Egress:  uint16(ifs[0].ID),
	}
	for i := 1; i < n-1; i++ {
		heliaHops[i] = helia.Hop{
			IA:      ifs[i*2-1].IA,
			Ingress: uint16(ifs[i*2-1].ID),
			Egress:  uint16(ifs[i*2].ID),
		}
	}
	heliaHops[n-1] = helia.Hop{
		IA:      ifs[(n-1)*2-1].IA,
		Ingress: uint16(ifs[(n-1)*2-1].ID),
		Egress:  0,
	}
	log.Debug("ASes", "hops", hops)
	return path, heliaHops, nil
}
