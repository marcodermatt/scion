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

package helia

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
)

// Size computes the full SCION packet size for an address pair with a given
// payload size.
func Size(local, remote *snet.UDPAddr, pldSize int) (int, error) {
	pkt, err := pack(
		local, remote, addr.IA(0), false, snet.SCMPEchoRequest{Payload: make([]byte, pldSize)},
	)
	if err != nil {
		return 0, err
	}
	if err := pkt.Serialize(); err != nil {
		return 0, err
	}
	return len(pkt.Bytes), nil
}

func pack(
	local, remote *snet.UDPAddr, target addr.IA, backward bool, req snet.SCMPEchoRequest,
) (*snet.Packet, error) {
	_, isEmpty := remote.Path.(path.Empty)
	if isEmpty && !local.IA.Equal(remote.IA) {
		return nil, serrors.New("no path for remote ISD-AS", "local", local.IA, "remote", remote.IA)
	}
	heliaSetupOpt := createSetupRequest(target, backward)
	pkt := &snet.Packet{
		PacketInfo: snet.PacketInfo{
			Destination: snet.SCIONAddress{
				IA:   remote.IA,
				Host: addr.HostFromIP(remote.Host.IP),
			},
			Source: snet.SCIONAddress{
				IA:   local.IA,
				Host: addr.HostFromIP(local.Host.IP),
			},
			Path:           remote.Path,
			Payload:        req,
			HopByHopOption: heliaSetupOpt,
		},
	}
	return pkt, nil
}

func ChooseAS(path snet.Path, remote addr.IA) (addr.IA, error) {
	fmt.Printf("Available AS on path to %s:\n", remote)
	intfs := path.Metadata().Interfaces
	n := (len(intfs) - 1) / 2
	for i := 0; i < n; i++ {
		inIntf := intfs[i*2+1]
		outIntf := intfs[i*2+2]
		fmt.Printf("[%2d] %s %s>%s\n", i, inIntf.IA, inIntf.ID, outIntf.ID)
	}
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("Choose AS: ")
		asIndexStr, err := reader.ReadString('\n')
		if err != nil {
			return addr.IA(0), err
		}
		idx, err := strconv.Atoi(asIndexStr[:len(asIndexStr)-1])
		if err == nil && 0 <= idx && idx < n {
			return intfs[idx*2+1].IA, nil
		}
		fmt.Fprintf(os.Stderr, "Path index outside of valid range: [0, %v]\n", n-1)
	}
}

func createSetupRequest(target addr.IA, isBackwardReq bool) *slayers.HopByHopOption {
	counter := slayers.PktCounterFromCore(1, 1, 2)
	auth := [16]byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF,
	}
	var tsReq [6]byte
	binary.BigEndian.PutUint32(tsReq[:], uint32(time.Now().UnixMilli()))
	reqParams := slayers.PacketReservReqParams{
		TargetAS:  target,
		Timestamp: tsReq,
		Counter:   counter,
		Auth:      auth,
	}
	if !isBackwardReq {
		optSetup, err := slayers.NewPacketReservReqForwardOption(reqParams)
		if err != nil {
			return nil
		}
		return optSetup.HopByHopOption
	} else {
		optSetup, err := slayers.NewPacketReservReqBackwardOption(reqParams)
		if err != nil {
			return nil
		}
		return optSetup.HopByHopOption
	}
}
