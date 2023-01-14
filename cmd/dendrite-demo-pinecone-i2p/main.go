// Copyright 2022 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/matrix-org/dendrite/cmd/dendrite-demo-pinecone/monolith"
	"github.com/matrix-org/dendrite/cmd/dendrite-demo-yggdrasil/signing"
	"github.com/matrix-org/dendrite/internal"
	"github.com/matrix-org/dendrite/setup"
	"github.com/matrix-org/dendrite/setup/config"
	"github.com/matrix-org/gomatrixserverlib"
	"github.com/sirupsen/logrus"

	pineconeRouter "github.com/matrix-org/pinecone/router"
	pineconeConnections "github.com/matrix-org/pinecone/connections"

	"github.com/eyedeekay/onramp"
)

var (
	instanceName            = flag.String("name", "dendrite-p2p-pinecone", "the name of this P2P demo instance")
	instancePort            = flag.Int("port", 8008, "the port that the client API will listen on")
	instancePeer            = flag.String("peer", "", "the static Pinecone peers to connect to, comma separated-list")
	instanceListen          = flag.String("listen", ":0", "the port Pinecone peers can connect to")
	instanceDir             = flag.String("dir", ".", "the directory to store the databases in (if --config not specified)")
	instanceRelayingEnabled = flag.Bool("relay", false, "whether to enable store & forward relaying for other nodes")
	//i2p
	enablemulticast      = flag.Bool("multicast", false, "enable multicast for local peer discovery (on the same lan)")
	enableclearnetbridge = flag.Bool("clearnetbridge", false, "connect to the clearnet static node and become a bridge")
	samaddr              = flag.String("sam", onramp.SAM_ADDR, "custom sam address")
	help                 = flag.Bool("help", false, "print this help text and exit")
)

func main() {
	flag.Parse()
	internal.SetupPprof()

	if *help {
		flag.PrintDefaults()
		os.Exit(0)
	}

	var pk ed25519.PublicKey
	var sk ed25519.PrivateKey

	// iterate through the cli args and check if the config flag was set
	configFlagSet := false
	for _, arg := range os.Args {
		if arg == "--config" || arg == "-config" {
			configFlagSet = true
			break
		}
	}

	var cfg *config.Dendrite

	// use custom config if config flag is set
	if configFlagSet {
		cfg = setup.ParseFlags(true)
		sk = cfg.Global.PrivateKey
		pk = sk.Public().(ed25519.PublicKey)
	} else {
		keyfile := filepath.Join(*instanceDir, *instanceName) + ".pem"
		oldKeyfile := *instanceName + ".key"
		sk, pk = monolith.GetOrCreateKey(keyfile, oldKeyfile)
		cfg = monolith.GenerateDefaultConfig(sk, *instanceDir, *instanceDir, *instanceName)
	}

	cfg.Global.ServerName = gomatrixserverlib.ServerName(hex.EncodeToString(pk))
	cfg.Global.KeyID = gomatrixserverlib.KeyID(signing.KeyID)

	p2pMonolith := monolith.P2PMonolith{}
	p2pMonolith.SetupPinecone(sk)

	if *enablemulticast {
		p2pMonolith.Multicast.Start()
	}

	//disabled by default due to clear privacy reasons.
	if *enableclearnetbridge {
		p2pMonolith.ConnManager.AddPeer("wss://pinecone.matrix.org/public")
	}

	//i2p stuff
	garlic, err := onramp.NewGarlic(*instanceName, *samaddr, onramp.OPT_DEFAULTS) //maybe different privacy rules?
	if err != nil {
		panic(err)
	}
	defer garlic.Close()

	i2pclient := &http.Client{
		Transport: &http.Transport{
			Dial:        garlic.Dial,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				//fixme should be DialContext, but it seems to be unimplemented
				//we just ignore the context for now and walk around it
				//https://github.com/eyedeekay/sam3/blob/45106d2b7062a690dfad30841163b510855469df/stream.go#L117
				return garlic.Dial(network, address)
			},
		},
	}
	i2pConnManager := pineconeConnections.NewConnectionManager(p2pMonolith.Router, i2pclient)

	if instancePeer != nil && *instancePeer != "" {
		for _, peer := range strings.Split(*instancePeer, ",") {
			//will hang on a lame peer for a long time,
			// pushing them all at once makes phony pick a different one
			go func(peer string) {
				i2pConnManager.AddPeer(strings.Trim(peer, " \t\r\n"))
			}(peer)
		}
	}

	enableMetrics := true
	enableWebsockets := false
	p2pMonolith.SetupDendrite(cfg, *instancePort, *instanceRelayingEnabled, enableMetrics, enableWebsockets)
	p2pMonolith.StartMonolith()
	p2pMonolith.WaitForShutdown()

	//listen for incoming i2p connections
	go func() {
		listener, err := garlic.Listen()

		if err != nil {
			panic(err)
		}

		listenerString := listener.Addr().String()
		fmt.Println("Listening on", listenerString)
		go startLandingpage(listenerString) //boot local webserver

		for {
			conn, err := listener.Accept()
			if err != nil {
				logrus.WithError(err).Error("listener.Accept failed")
				continue
			}

			//check if its someone browsing to us
			ishttp := false
			ishttp, conn = checkHTTP(conn) //the returned conn has the replay bytes pretached
			if ishttp {
				go handleclient(conn, listenerString)
				continue //yep
			}

			port, err := p2pMonolith.Router.Connect(
				conn,
				pineconeRouter.ConnectionPeerType(pineconeRouter.PeerTypeRemote),
			)

			if err != nil {
				logrus.WithError(err).Error("pSwitch.Connect failed")
				continue
			}

			fmt.Println("Inbound connection", conn.RemoteAddr(), "is connected to port", port)
		}
	}()
}


func checkHTTP(conn net.Conn) (bool, net.Conn) {
	const longestMethodName = 7
	thebytes := make([]byte, longestMethodName)

	connpeek := NewPeekerConn(conn)

	//the assumption is, if its a http connection, we already have data waiting to be read.
	//real world testing seems to confirm that. if its a pinecone handshake, we will time out
	//and go into the pinecone routers path.
	if errdeadline := connpeek.SetDeadline(time.Now().Add(time.Millisecond * 20)); errdeadline != nil {
		fmt.Printf("connpeek.SetDeadline: %w\n", errdeadline)
	}

	/*numread,*/
	_, errpeek := connpeek.Peek(thebytes)

	if errdeadline := connpeek.SetDeadline(time.Time{}); errdeadline != nil {
		fmt.Printf("connpeek.SetDeadline: %w\n", errdeadline)
	}

	if errpeek != nil {
		//fmt.Println("failed to peek at conn:", errpeek.Error())
		// timeout -> is not http, likely pinecone
		return false, connpeek
	}

	//fmt.Println("peeked", len(thebytes), "bytes with content:", thebytes, "/", string(thebytes))
	//fmt.Println("wanted 7 bytes and got", numread)

	if isValidHttpMethod(string(thebytes)) {
		return true, connpeek
	}

	return false, connpeek
}

var methods = []string{
	//most likely to least likely
	http.MethodGet, http.MethodPost, http.MethodHead,
	http.MethodPut, http.MethodConnect, http.MethodPatch,
	http.MethodDelete, http.MethodOptions, http.MethodTrace,
}

func isValidHttpMethod(method string) bool {
	//the only good thing about http requests, easy to check if its one
	for _, methodi := range methods {
		if strings.HasPrefix(method, methodi) {
			return true
		}
	}
	return false
}

type peekerConn struct {
	r *bufio.Reader
	net.Conn
}

func NewPeekerConn(c net.Conn) *peekerConn {
	return &peekerConn{bufio.NewReader(c), c}
}

func (b *peekerConn) Peek(p []byte) (int, error) {
	bytes, err := b.r.Peek(len(p))
	copy(p, bytes)
	return len(bytes), err
}

func (b *peekerConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}
