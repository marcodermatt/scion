package processing

import (
	"context"
	"net"
	"syscall"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	common "github.com/scionproto/scion/pkg/experimental/heliagate"
	config2 "github.com/scionproto/scion/pkg/experimental/heliagate/config"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/app"
	"github.com/scionproto/scion/private/topology"
	"golang.org/x/net/ipv4"
	"golang.org/x/sync/errgroup"
)

type Processor struct {
	dataChannels []chan *dataPacket
	//cleanupChannel  chan *storage.UpdateTask
	borderRouters map[uint16]*ipv4.PacketConn
	saltHasher    common.SaltHasher
	exit          bool
	numWorkers    int
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

	p := Processor{
		borderRouters: borderRouters,
		//cleanupChannel: make(chan *storage.UpdateTask, 1000,),
		dataChannels: make([]chan *dataPacket, 1),
		//controlChannels: make([]chan storage.Task, config.NumWorkers),
		numWorkers: 1,
	}

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

// The function to initialize the data plane of the colibri gateway.
func (p *Processor) initDataPlane(
	config *config2.Heliagate, gatewayAddr *net.UDPAddr,
	g *errgroup.Group, cleanup *app.Cleanup,
) error {

	log.Info("Init data plane")
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

					select {
					case p.dataChannels[0] <- d:
					default:
						continue // Packet dropped
					}
				}

			}
			return nil
		},
	)
	return nil
}

func (p *Processor) getWorkerForSourceID(sourceID []byte) uint32 {
	return p.saltHasher.Hash(sourceID) % uint32(p.numWorkers)
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
