package processing

import (
	"context"
	"net"
	"syscall"

	"github.com/scionproto/scion/heliagate/config"
	"github.com/scionproto/scion/pkg/addr"
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
	exit          bool
	numWorkers    int
}

// BufSize is the maximum size of a datapacket including all the headers.
const bufSize int = 9000

// NumOfMessages is the maximum number of messages that are read as a batch from the socket.
const numOfMessages int = 10

// Init initializes the helia gateway. Configures the channels, goroutines,
// and the control plane and the data plane.
func Init(
	ctx context.Context, cfg *config.Config, cleanup *app.Cleanup,
	g *errgroup.Group, topo *topology.Loader,
) error {

	config := &cfg.Heliagate
	var borderRouters map[uint16]*ipv4.PacketConn = make(map[uint16]*ipv4.PacketConn)
	for ifid, info := range topo.InterfaceInfoMap() {
		conn, _ := net.DialUDP("udp", nil, info.InternalAddr)
		borderRouters[uint16(ifid)] = ipv4.NewPacketConn(conn)
		log.Debug("Found Border Router", "ifid", ifid, "internal_addr", info.InternalAddr)
	}

	coligateAddr := topo.HeliaGatewayAddress(cfg.General.ID)

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
			//p.shutdown()
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
			// We start the data plane as soon as we retrieved the active reservations from colibri service
			if err := p.loadActiveReservationsFromColibriService(
				ctx, config, colibriServiceAddresses[0],
				config.COSyncTimeout,
			); err != nil {
				return err
			}
			if err := p.initDataPlane(config, coligateAddr, g, cleanup); err != nil {
				return err
			}
	*/

	return nil
}

// Internal method to get the address of the corresponding border router
// to forward the outgoing packets
func (p *Processor) getBorderRouterConnection(proc *dataPacket) (*ipv4.PacketConn, error) {
	egressId := p.egressInterface(proc)
	conn, found := p.borderRouters[egressId]
	if !found {
		return nil, serrors.New("egress interface is invalid:", "egressId", egressId)
	}
	return conn, nil
}

func (p *Processor) egressInterface(proc *dataPacket) uint16 {
		return p.hopField.ConsEgress
	}
	return p.hopField.ConsIngress
}

// Configures a goroutine to listen for the data plane channel and control plane reservation updates
func (p *Processor) workerReceiveEntry(
	config *config.Heliagate, workerId uint32,
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
			path := d.scionLayer.Path
			hopField, err := path.GetCurrentHopField()
			if err != nil {
				return nil
			}
			infoField, err := p.path.GetCurrentInfoField()
			if err != nil {
				return nil
			}
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
