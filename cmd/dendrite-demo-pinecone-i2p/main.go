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
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/matrix-org/dendrite/appservice"
	"github.com/matrix-org/dendrite/cmd/dendrite-demo-pinecone/conn"
	"github.com/matrix-org/dendrite/cmd/dendrite-demo-pinecone/embed"
	"github.com/matrix-org/dendrite/cmd/dendrite-demo-pinecone/rooms"
	"github.com/matrix-org/dendrite/cmd/dendrite-demo-pinecone/users"
	"github.com/matrix-org/dendrite/cmd/dendrite-demo-yggdrasil/signing"
	"github.com/matrix-org/dendrite/federationapi"
	"github.com/matrix-org/dendrite/federationapi/api"
	"github.com/matrix-org/dendrite/internal"
	"github.com/matrix-org/dendrite/internal/httputil"
	"github.com/matrix-org/dendrite/keyserver"
	"github.com/matrix-org/dendrite/roomserver"
	"github.com/matrix-org/dendrite/setup"
	"github.com/matrix-org/dendrite/setup/base"
	"github.com/matrix-org/dendrite/setup/config"
	"github.com/matrix-org/dendrite/test"
	"github.com/matrix-org/dendrite/userapi"
	"github.com/matrix-org/gomatrixserverlib"

	pineconeConnections "github.com/matrix-org/pinecone/connections"
	pineconeMulticast "github.com/matrix-org/pinecone/multicast"
	pineconeRouter "github.com/matrix-org/pinecone/router"
	pineconeEvents "github.com/matrix-org/pinecone/router/events"
	pineconeSessions "github.com/matrix-org/pinecone/sessions"

	"github.com/sirupsen/logrus"

	"github.com/eyedeekay/onramp"
)

var (
	flags                = flag.NewFlagSet("pinecone", flag.ExitOnError)
	instanceName         = flags.String("name", "dendrite-p2p-pinecone-i2p", "the name of this P2P demo instance")
	instancePort         = flags.Int("port", 8008, "the port that the client API will listen on")
	instancePeer         = flags.String("peer", "", "the static Pinecone peers to connect to, comma separated-list")
	instanceDir          = flags.String("dir", ".", "the directory(create manually before use) to store the databases in (if --config not specified)")
	enablemulticast      = flags.Bool("multicast", false, "enable multicast for local peer discovery (on the same lan)")
	enableclearnetbridge = flags.Bool("clearnetbridge", false, "connect to the clearnet static node and become a bridge")
	samaddr              = flags.String("sam", onramp.SAM_ADDR, "custom sam address")
	help                 = flags.Bool("help", false, "print this help text and exit")
)

// nolint:gocyclo
func main() {
	flags.Parse(os.Args[1:])
	internal.SetupPprof()

	if *help {
		flags.PrintDefaults()
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

	cfg := &config.Dendrite{}

	// use custom config if config flag is set
	if configFlagSet {
		cfg = setup.ParseFlags(true)
		sk = cfg.Global.PrivateKey
		pk = sk.Public().(ed25519.PublicKey)
	} else {
		keyfile := filepath.Join(*instanceDir, *instanceName) + ".pem"
		if _, err := os.Stat(keyfile); os.IsNotExist(err) {
			oldkeyfile := *instanceName + ".key"
			if _, err = os.Stat(oldkeyfile); os.IsNotExist(err) {
				if err = test.NewMatrixKey(keyfile); err != nil {
					panic("failed to generate a new PEM key: " + err.Error())
				}
				if _, sk, err = config.LoadMatrixKey(keyfile, os.ReadFile); err != nil {
					panic("failed to load PEM key: " + err.Error())
				}
				if len(sk) != ed25519.PrivateKeySize {
					panic("the private key is not long enough")
				}
			} else {
				if sk, err = os.ReadFile(oldkeyfile); err != nil {
					panic("failed to read the old private key: " + err.Error())
				}
				if len(sk) != ed25519.PrivateKeySize {
					panic("the private key is not long enough")
				}
				if err := test.SaveMatrixKey(keyfile, sk); err != nil {
					panic("failed to convert the private key to PEM format: " + err.Error())
				}
			}
		} else {
			var err error
			if _, sk, err = config.LoadMatrixKey(keyfile, os.ReadFile); err != nil {
				panic("failed to load PEM key: " + err.Error())
			}
			if len(sk) != ed25519.PrivateKeySize {
				panic("the private key is not long enough")
			}
		}

		pk = sk.Public().(ed25519.PublicKey)

		cfg.Defaults(config.DefaultOpts{
			Generate:   true,
			Monolithic: true,
		})
		cfg.Global.PrivateKey = sk
		cfg.Global.JetStream.StoragePath = config.Path(fmt.Sprintf("%s/", filepath.Join(*instanceDir, *instanceName)))
		cfg.UserAPI.AccountDatabase.ConnectionString = config.DataSource(fmt.Sprintf("file:%s-account.db", filepath.Join(*instanceDir, *instanceName)))
		cfg.MediaAPI.Database.ConnectionString = config.DataSource(fmt.Sprintf("file:%s-mediaapi.db", filepath.Join(*instanceDir, *instanceName)))
		cfg.SyncAPI.Database.ConnectionString = config.DataSource(fmt.Sprintf("file:%s-syncapi.db", filepath.Join(*instanceDir, *instanceName)))
		cfg.RoomServer.Database.ConnectionString = config.DataSource(fmt.Sprintf("file:%s-roomserver.db", filepath.Join(*instanceDir, *instanceName)))
		cfg.KeyServer.Database.ConnectionString = config.DataSource(fmt.Sprintf("file:%s-keyserver.db", filepath.Join(*instanceDir, *instanceName)))
		cfg.FederationAPI.Database.ConnectionString = config.DataSource(fmt.Sprintf("file:%s-federationapi.db", filepath.Join(*instanceDir, *instanceName)))
		cfg.MSCs.MSCs = []string{"msc2836", "msc2946"}
		cfg.MSCs.Database.ConnectionString = config.DataSource(fmt.Sprintf("file:%s-mscs.db", filepath.Join(*instanceDir, *instanceName)))
		cfg.ClientAPI.RegistrationDisabled = false
		cfg.ClientAPI.OpenRegistrationWithoutVerificationEnabled = true
		cfg.MediaAPI.BasePath = config.Path(*instanceDir)
		cfg.SyncAPI.Fulltext.Enabled = true
		cfg.SyncAPI.Fulltext.IndexPath = config.Path(*instanceDir)
		if err := cfg.Derive(); err != nil {
			panic(err)
		}
	}

	cfg.Global.ServerName = gomatrixserverlib.ServerName(hex.EncodeToString(pk))
	cfg.Global.KeyID = gomatrixserverlib.KeyID(signing.KeyID)

	base := base.NewBaseDendrite(cfg, "Monolith")
	base.ConfigureAdminEndpoints()
	defer base.Close() // nolint: errcheck

	//fixme all connects up to the pRouter!
	//i2p listens to it, multicast does aswell
	//normienet should be attachable to pRouter too
	//it just gives the router a conn
	//anything implementing a conn can be passed to it!
	pineconeEventChannel := make(chan pineconeEvents.Event)
	pRouter := pineconeRouter.NewRouter(logrus.WithField("pinecone", "router"), sk)
	pRouter.EnableHopLimiting()
	pRouter.EnableWakeupBroadcasts()
	pRouter.Subscribe(pineconeEventChannel)

	pQUIC := pineconeSessions.NewSessions(logrus.WithField("pinecone", "sessions"), pRouter, []string{"matrix"})
	pMulticast := pineconeMulticast.NewMulticast(logrus.WithField("pinecone", "multicast"), pRouter)
	if *enablemulticast {
		pMulticast.Start() //disabled by default due to reasons. needs to be evaluated!
	}

	if *enableclearnetbridge { //disabled by default due to clear privacy reasons.
		pManagerClearnet := pineconeConnections.NewConnectionManager(pRouter, nil)
		go pManagerClearnet.AddPeer(strings.Trim("wss://pinecone.matrix.org/public", " \t\r\n"))
	}

	garlic, err := onramp.NewGarlic(*instanceName, *samaddr, onramp.OPT_DEFAULTS) //maybe different privacy rules?
	if err != nil {
		panic(err)
	}
	defer garlic.Close()

	dialcontext_wrapper := func(ctx context.Context, network, address string) (net.Conn, error) {
		//fixme should be DialContext, but it seems to be unimplemented
		//we just ignore the context for now and walk around it
		//https://github.com/eyedeekay/sam3/blob/45106d2b7062a690dfad30841163b510855469df/stream.go#L117
		return garlic.Dial(network, address)
	}

	transport := http.Transport{
		Dial:        garlic.Dial,
		DialContext: dialcontext_wrapper,
	}
	i2pclient := &http.Client{
		Transport: &transport,
	}

	pManager := pineconeConnections.NewConnectionManager(pRouter, i2pclient)
	if instancePeer != nil && *instancePeer != "" {
		for _, peer := range strings.Split(*instancePeer, ",") {
			//will hang on a lame peer for a long time,
			// pushing them all at once makes phony pick a different one
			go func(peer string) {
				pManager.AddPeer(strings.Trim(peer, " \t\r\n"))
			}(peer)
		}
	}

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

			port, err := pRouter.Connect(
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

	federation := conn.CreateFederationClient(base, pQUIC)

	serverKeyAPI := &signing.YggdrasilKeys{}
	keyRing := serverKeyAPI.KeyRing()

	rsComponent := roomserver.NewInternalAPI(base)
	rsAPI := rsComponent
	fsAPI := federationapi.NewInternalAPI(
		base, federation, rsAPI, base.Caches, keyRing, true,
	)

	keyAPI := keyserver.NewInternalAPI(base, &base.Cfg.KeyServer, fsAPI, rsComponent)
	userAPI := userapi.NewInternalAPI(base, &cfg.UserAPI, nil, keyAPI, rsAPI, base.PushGatewayHTTPClient())
	keyAPI.SetUserAPI(userAPI)

	asAPI := appservice.NewInternalAPI(base, userAPI, rsAPI)

	rsComponent.SetFederationAPI(fsAPI, keyRing)

	userProvider := users.NewPineconeUserProvider(pRouter, pQUIC, userAPI, federation)
	roomProvider := rooms.NewPineconeRoomProvider(pRouter, pQUIC, fsAPI, federation)

	monolith := setup.Monolith{
		Config:    base.Cfg,
		Client:    conn.CreateClient(base, pQUIC),
		FedClient: federation,
		KeyRing:   keyRing,

		AppserviceAPI:            asAPI,
		FederationAPI:            fsAPI,
		RoomserverAPI:            rsAPI,
		UserAPI:                  userAPI,
		KeyAPI:                   keyAPI,
		ExtPublicRoomsProvider:   roomProvider,
		ExtUserDirectoryProvider: userProvider,
	}
	monolith.AddAllPublicRoutes(base)

	wsUpgrader := websocket.Upgrader{
		CheckOrigin: func(_ *http.Request) bool {
			return true
		},
	}
	httpRouter := mux.NewRouter().SkipClean(true).UseEncodedPath()
	httpRouter.PathPrefix(httputil.InternalPathPrefix).Handler(base.InternalAPIMux)
	httpRouter.PathPrefix(httputil.PublicClientPathPrefix).Handler(base.PublicClientAPIMux)
	httpRouter.PathPrefix(httputil.PublicMediaPathPrefix).Handler(base.PublicMediaAPIMux)
	httpRouter.PathPrefix(httputil.DendriteAdminPathPrefix).Handler(base.DendriteAdminMux)
	httpRouter.PathPrefix(httputil.SynapseAdminPathPrefix).Handler(base.SynapseAdminMux)
	httpRouter.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		c, err := wsUpgrader.Upgrade(w, r, nil)
		if err != nil {
			logrus.WithError(err).Error("Failed to upgrade WebSocket connection")
			return
		}
		conn := conn.WrapWebSocketConn(c)
		if _, err = pRouter.Connect(
			conn,
			pineconeRouter.ConnectionZone("websocket"),
			pineconeRouter.ConnectionPeerType(pineconeRouter.PeerTypeRemote),
		); err != nil {
			logrus.WithError(err).Error("Failed to connect WebSocket peer to Pinecone switch")
		}
	})
	httpRouter.HandleFunc("/pinecone", pRouter.ManholeHandler)
	embed.Embed(httpRouter, *instancePort, "Pinecone Demo")

	pMux := mux.NewRouter().SkipClean(true).UseEncodedPath()
	pMux.PathPrefix(users.PublicURL).HandlerFunc(userProvider.FederatedUserProfiles)
	pMux.PathPrefix(httputil.PublicFederationPathPrefix).Handler(base.PublicFederationAPIMux)
	pMux.PathPrefix(httputil.PublicMediaPathPrefix).Handler(base.PublicMediaAPIMux)

	pHTTP := pQUIC.Protocol("matrix").HTTP()
	pHTTP.Mux().Handle(users.PublicURL, pMux)
	pHTTP.Mux().Handle(httputil.PublicFederationPathPrefix, pMux)
	pHTTP.Mux().Handle(httputil.PublicMediaPathPrefix, pMux)

	// Build both ends of a HTTP multiplex.
	httpServer := &http.Server{
		Addr:         ":0",
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
		ReadTimeout:  30 * time.Second, //fixme not sure yet if we should increase them
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
		BaseContext: func(_ net.Listener) context.Context {
			return context.Background()
		},
		Handler: pMux,
	}

	go func() {
		pubkey := pRouter.PublicKey()
		logrus.Info("Listening on ", hex.EncodeToString(pubkey[:]))
		logrus.Fatal(httpServer.Serve(pQUIC.Protocol("matrix")))
	}()
	go func() {
		httpBindAddr := fmt.Sprintf(":%d", *instancePort)
		logrus.Info("Listening on ", httpBindAddr)
		logrus.Fatal(http.ListenAndServe(httpBindAddr, httpRouter))
	}()

	go func(ch <-chan pineconeEvents.Event) {
		eLog := logrus.WithField("pinecone", "events")

		for event := range ch {
			switch e := event.(type) {
			case pineconeEvents.PeerAdded:
			case pineconeEvents.PeerRemoved:
			case pineconeEvents.TreeParentUpdate:
			case pineconeEvents.SnakeDescUpdate:
			case pineconeEvents.TreeRootAnnUpdate:
			case pineconeEvents.SnakeEntryAdded:
			case pineconeEvents.SnakeEntryRemoved:
			case pineconeEvents.BroadcastReceived:
				eLog.Info("Event ", PineconeEventToString(event), " received from: ", e.PeerID)

				req := &api.PerformWakeupServersRequest{
					ServerNames: []gomatrixserverlib.ServerName{gomatrixserverlib.ServerName(e.PeerID)},
				}
				res := &api.PerformWakeupServersResponse{}
				if err := fsAPI.PerformWakeupServers(base.Context(), req, res); err != nil {
					logrus.WithError(err).Error("Failed to wakeup destination", e.PeerID)
				}
			case pineconeEvents.BandwidthReport:
			default:
			}
		}
	}(pineconeEventChannel)

	base.WaitForShutdown()
}

func PineconeEventToString(e pineconeEvents.Event) string {
	switch e.(type) {
	case pineconeEvents.PeerAdded:
		return "PeerAdded"
	case pineconeEvents.PeerRemoved:
		return "PeerRemoved"
	case pineconeEvents.TreeParentUpdate:
		return "TreeParentUpdate"
	case pineconeEvents.SnakeDescUpdate:
		return "SnakeDescUpdate"
	case pineconeEvents.TreeRootAnnUpdate:
		return "TreeRootAnnUpdate"
	case pineconeEvents.SnakeEntryAdded:
		return "SnakeEntryAdded"
	case pineconeEvents.SnakeEntryRemoved:
		return "SnakeEntryRemoved"
	case pineconeEvents.BroadcastReceived:
		return "BroadcastReceived"
	case pineconeEvents.BandwidthReport:
		return "BandwidthReport"
	default:
		return "Unknown Pinecone Event"
	}
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
