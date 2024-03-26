// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"sort"
	"sync"
	"time"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/host"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/promauto"
	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/p2p"
)

// Config defines the config of the relay.
type Config struct {
	DataDir         string
	HTTPAddr        string
	MonitoringAddr  string
	DebugAddr       string
	P2PConfig       p2p.Config
	LogConfig       log.Config
	AutoP2PKey      bool
	MaxResPerPeer   int
	MaxConns        int
	FilterPrivAddrs bool
	LibP2PLogLevel  string
}

// Run starts an Obol libp2p-tcp-relay and udp-discv5 bootnode.
func Run(ctx context.Context, config Config) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ctx = log.WithTopic(ctx, "relay")

	version.LogInfo(ctx, "Charon relay starting")

	key, err := p2p.LoadPrivKey(config.DataDir)
	if errors.Is(err, os.ErrNotExist) {
		if !config.AutoP2PKey {
			return errors.New("charon-enr-private-key not found in data dir (run with --auto-p2pkey to auto generate)")
		}

		log.Info(ctx, "Automatically creating charon-enr-private-key", z.Str("path", p2p.KeyPath(config.DataDir)))

		key, err = p2p.NewSavedPrivKey(config.DataDir)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}

	bwTuples := make(chan bwTuple)
	counter := newBandwidthCounter(ctx, bwTuples)

	tcpNode, err := startP2P(ctx, config, key, counter)
	if err != nil {
		return err
	}

	go monitorConnections(ctx, tcpNode, bwTuples)

	labels := map[string]string{"relay_peer": p2p.PeerName(tcpNode.ID())}
	log.SetLokiLabels(labels)
	promRegistry, err := promauto.NewRegistry(labels)
	if err != nil {
		return err
	}

	// Start serving HTTP: ENR and monitoring.
	serverErr := make(chan error, 3) // Buffer for 3 servers.
	go func() {
		if config.HTTPAddr == "" {
			return
		}

		mux := http.NewServeMux()
		mux.HandleFunc("/", wrapHandler(newMultiaddrHandler(tcpNode)))
		mux.HandleFunc("/enr", wrapHandler(newENRHandler(ctx, tcpNode, key, config.P2PConfig)))
		server := http.Server{Addr: config.HTTPAddr, Handler: mux, ReadHeaderTimeout: time.Second}
		serverErr <- server.ListenAndServe()
	}()

	if config.MonitoringAddr != "" {
		go func() {
			// Serve prometheus metrics wrapped with relay identifiers.
			mux := http.NewServeMux()
			mux.Handle("/metrics", promhttp.InstrumentMetricHandler(
				promRegistry, promhttp.HandlerFor(promRegistry, promhttp.HandlerOpts{}),
			))

			log.Info(ctx, "Monitoring server started", z.Str("address", config.MonitoringAddr))
			server := http.Server{Addr: config.MonitoringAddr, Handler: mux, ReadHeaderTimeout: time.Second}
			serverErr <- server.ListenAndServe()
		}()
	}

	if config.DebugAddr != "" {
		go func() {
			debugMux := http.NewServeMux()

			// Copied from net/http/pprof/pprof.go
			debugMux.HandleFunc("/debug/pprof/", pprof.Index)
			debugMux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
			debugMux.HandleFunc("/debug/pprof/profile", pprof.Profile)
			debugMux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
			debugMux.HandleFunc("/debug/pprof/trace", pprof.Trace)

			log.Info(ctx, "Debug server started", z.Str("address", config.DebugAddr))

			server := http.Server{Addr: config.DebugAddr, Handler: debugMux, ReadHeaderTimeout: time.Second}
			serverErr <- server.ListenAndServe()
		}()
	}

	log.Info(ctx, "Relay started",
		z.Str("peer_name", p2p.PeerName(tcpNode.ID())),
		z.Any("p2p_tcp_addr", config.P2PConfig.TCPAddrs),
	)
	if config.HTTPAddr != "" {
		log.Info(ctx, "Runtime multiaddrs available via http",
			z.Str("url", fmt.Sprintf("http://%s", config.HTTPAddr)),
		)
	} else {
		log.Info(ctx, "Runtime multiaddrs not available via http, since http-address flag is not set")
	}

	for {
		select {
		case err := <-serverErr:
			return err
		case <-ctx.Done():
			log.Info(ctx, "Shutting down")
			return nil
		}
	}
}

// newENRHandler returns a handler that returns the node's ID and public address encoded as a ENR.
func newENRHandler(ctx context.Context, tcpNode host.Host, p2pKey *k1.PrivateKey, config p2p.Config) func(ctx context.Context) ([]byte, error) {
	// Resolve external hostname periodically.
	var (
		extHostMu sync.Mutex
		extHostIP net.IP
	)
	go func() {
		if config.ExternalHost == "" {
			return
		}

		resolveExtHost := func() {
			ip, err := net.LookupIP(config.ExternalHost)
			if err != nil {
				log.Warn(ctx, "Failed to resolve external host", err, z.Str("host", config.ExternalHost))
				return
			}
			extHostMu.Lock()
			extHostIP = ip[0]
			extHostMu.Unlock()
		}

		onStartup := make(chan struct{}, 1)
		onStartup <- struct{}{}

		for {
			select {
			case <-onStartup:
				resolveExtHost()
			case <-time.After(5 * time.Minute):
				resolveExtHost()
			case <-ctx.Done():
				return
			}
		}
	}()

	// getExtHostIP returns the external host IP and true if it is set.
	getExtHostIP := func() (net.IP, bool) {
		extHostMu.Lock()
		defer extHostMu.Unlock()

		return extHostIP, len(extHostIP) != 0
	}

	return func(ctx context.Context) ([]byte, error) {
		// Use libp2p configured and detected addresses.
		addrs := tcpNode.Addrs()
		if len(addrs) == 0 {
			return nil, errors.New("no addresses")
		}

		// Order public addresses first.
		sort.SliceStable(addrs, func(i, j int) bool {
			iPublic, jPublic := manet.IsPublicAddr(addrs[i]), manet.IsPublicAddr(addrs[j])
			if jPublic && !iPublic {
				return true // Only swap if j is public and i is not.
			}

			return false
		})

		// Use first address (ip and port).
		addr, err := manet.ToNetAddr(addrs[0])
		if err != nil {
			return nil, errors.Wrap(err, "failed to convert multiaddr to net addr")
		}
		tcpAddr, ok := addr.(*net.TCPAddr)
		if !ok {
			return nil, errors.New("invalid TCP address")
		}

		// Override IP with external IP or external hostname if set.
		if config.ExternalIP != "" {
			tcpAddr.IP = net.ParseIP(config.ExternalIP)
		} else if extHostIP, ok := getExtHostIP(); ok {
			tcpAddr.IP = extHostIP
		}

		// Build the ENR
		r, err := enr.New(p2pKey, enr.WithIP(tcpAddr.IP), enr.WithTCP(tcpAddr.Port), enr.WithUDP(9999)) // Include invalid dummy UDP port so v0.13 can parse the ENR.
		if err != nil {
			return nil, err
		}

		return []byte(r.String()), nil
	}
}

// newMultiaddrHandler returns a handler that returns the nodes multiaddrs (as json array).
func newMultiaddrHandler(tcpNode host.Host) func(ctx context.Context) ([]byte, error) {
	return func(ctx context.Context) ([]byte, error) {
		p2pAddr, err := ma.NewMultiaddr(fmt.Sprintf("/p2p/%s", tcpNode.ID()))
		if err != nil {
			return nil, errors.Wrap(err, "failed to create p2p multiaddr")
		}

		var addrs []ma.Multiaddr
		for _, addr := range tcpNode.Addrs() {
			addrs = append(addrs, addr.Encapsulate(p2pAddr))
		}

		b, err := json.Marshal(addrs)
		if err != nil {
			return nil, errors.Wrap(err, "marshal json")
		}

		return b, nil
	}
}

// wrapHandler returns a http handler by wrapping the provided function with error handling.
func wrapHandler(handler func(ctx context.Context) (response []byte, err error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		response, err := handler(ctx)
		if err != nil {
			log.Error(ctx, "Handler error", err, z.Str("path", r.URL.Path))
			w.WriteHeader(http.StatusInternalServerError)

			return
		}

		_, _ = w.Write(response)
	}
}
