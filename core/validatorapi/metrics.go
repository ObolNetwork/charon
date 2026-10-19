// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package validatorapi

import (
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/promauto"
)

var (
	apiLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "core",
		Subsystem: "validatorapi",
		Name:      "request_latency_seconds",
		Help:      "The validatorapi request latencies in seconds by endpoint",
	}, []string{"endpoint"})

	proxyAPILatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "core",
		Subsystem: "validatorapi",
		Name:      "proxy_request_latency_seconds",
		Help:      "The validatorapi proxy request latencies in seconds by path",
	}, []string{"path"})

	apiErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "validatorapi",
		Name:      "request_error_total",
		Help:      "The total number of validatorapi request errors",
	}, []string{"endpoint", "status_code"})

	vcContentType = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "validatorapi",
		Name:      "request_total",
		Help:      "The total number of requests per content-type and endpoint",
	}, []string{"endpoint", "content_type"})

	vcUserAgentGauge = promauto.NewResetGaugeVec(prometheus.GaugeOpts{
		Namespace: "core",
		Subsystem: "validatorapi",
		Name:      "vc_user_agent",
		Help:      "Gauge with label set to user agent string of requests made by VC",
	}, []string{"user_agent"})

	proposalFormGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "core",
		Subsystem: "validatorapi",
		Name:      "proposal_form",
		Help:      "The form the validator client requested the latest gloas proposal in: none requested yet (0), stateless with its execution payload, which waits for the shared payload contents (1), or stateful (2)",
	})

	proposerPrefMismatch = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "validatorapi",
		Name:      "proposer_preferences_mismatch_total",
		Help:      "Total number of proposer preferences submitted by the VC that mismatch the cluster-lock value, by field",
	}, []string{"field"})

	builderPrefMismatch = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "core",
		Subsystem: "validatorapi",
		Name:      "builder_preferences_mismatch_total",
		Help: "Total number of builder preferences submitted by the VC that mismatch this node's builders, by builder host " +
			"and reason: a configured builder without a request auth (missing) or an auth for a builder not configured (unknown)",
	}, []string{"builder", "reason"})
)

// Values of proposalFormGauge, the form the latest gloas proposal was requested in.
const (
	proposalFormUnknown   = 0 // No gloas proposal requested yet, the gauge's default.
	proposalFormStateless = 1
	proposalFormStateful  = 2
)

func incProposerPrefMismatch(field string) {
	proposerPrefMismatch.WithLabelValues(field).Inc()
}

func incBuilderPrefMismatch(builder, reason string) {
	builderPrefMismatch.WithLabelValues(builder, reason).Inc()
}

// maxBuilderHostLabelLen bounds the untrusted builder request auth data used as a metric label
// value, at the maximum length of a hostname, the data's default.
const maxBuilderHostLabelLen = 253

// builderHostLabel returns the builder host of a request auth as a metric label value: capped and
// valid UTF-8 like the User-Agent header, since it is unverified validator client input and the
// prometheus client panics on an invalid label value.
func builderHostLabel(host string) string {
	if len(host) > maxBuilderHostLabelLen {
		host = host[:maxBuilderHostLabelLen]
	}

	return strings.ToValidUTF8(host, "")
}

func incAPIErrors(endpoint string, statusCode int) {
	apiErrors.WithLabelValues(endpoint, strconv.Itoa(statusCode)).Inc()
}

func observeAPILatency(endpoint string) func() {
	t0 := time.Now()

	return func() {
		apiLatency.WithLabelValues(endpoint).Observe(time.Since(t0).Seconds())
	}
}

func observeProxyAPILatency(path string) func() {
	t0 := time.Now()

	label := proxyPathLabel(path)

	return func() {
		proxyAPILatency.WithLabelValues(label).Observe(time.Since(t0).Seconds())
	}
}

// proxyPathLabel converts a request path into a bounded metric label by replacing dynamic
// path segments with placeholders. Without this, paths like /eth/v2/beacon/blocks/0x<root>
// produce a unique label value per block root, which grows metric cardinality (and memory)
// without bound.
func proxyPathLabel(path string) string {
	segments := strings.Split(strings.Trim(path, "/"), "/")
	for i, segment := range segments {
		switch {
		case strings.HasPrefix(segment, "0x"):
			segments[i] = "{hex}" // Block/state roots, validator pubkeys.
		case isNumeric(segment):
			segments[i] = "{n}" // Slots, epochs, validator indices.
		case i > 0 && segments[i-1] == "peers":
			segments[i] = "{peer_id}" // libp2p peer IDs are base58/base32, not hex or numeric.
		default:
		}
	}

	return strings.Join(segments, "_")
}

// isNumeric returns true if s is non-empty and contains only ASCII digits.
func isNumeric(s string) bool {
	if s == "" {
		return false
	}

	return !strings.ContainsFunc(s, func(r rune) bool {
		return r < '0' || r > '9'
	})
}

// vcUserAgentRegistry tracks validator client user agents recently seen on API requests,
// so fork readiness checks can evaluate the connected validator clients.
var vcUserAgentRegistry = struct {
	sync.Mutex

	agents map[string]time.Time
}{agents: make(map[string]time.Time)}

const (
	// vcUserAgentTTL bounds how long a user agent is considered connected after its last request.
	vcUserAgentTTL = time.Hour
	// maxVCUserAgents bounds the registry size (and the resulting metric cardinality) since
	// user agents are untrusted request input. New agents are dropped when the registry is
	// full; expired entries make room again. Validator clients connect continuously, so
	// legitimate agents recorded early are retained.
	maxVCUserAgents = 10
)

// recordVCUserAgent records a validator client user agent seen on an API request.
func recordVCUserAgent(agent string) {
	vcUserAgentRegistry.Lock()
	defer vcUserAgentRegistry.Unlock()

	if _, ok := vcUserAgentRegistry.agents[agent]; !ok {
		for existing, seen := range vcUserAgentRegistry.agents {
			if time.Since(seen) > vcUserAgentTTL {
				delete(vcUserAgentRegistry.agents, existing)
			}
		}

		if len(vcUserAgentRegistry.agents) >= maxVCUserAgents {
			return
		}
	}

	vcUserAgentRegistry.agents[agent] = time.Now()
}

// SeenVCUserAgents returns the validator client user agents seen recently on API requests.
func SeenVCUserAgents() []string {
	vcUserAgentRegistry.Lock()
	defer vcUserAgentRegistry.Unlock()

	var resp []string

	for agent, seen := range vcUserAgentRegistry.agents {
		if time.Since(seen) > vcUserAgentTTL {
			delete(vcUserAgentRegistry.agents, agent)
			continue
		}

		resp = append(resp, agent)
	}

	slices.Sort(resp)

	return resp
}
