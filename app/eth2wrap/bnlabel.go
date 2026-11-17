// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"net/url"
	"strconv"
	"strings"
	"sync"
)

const (
	// maxBeaconNodeLabels caps the number of distinct beacon node address label values,
	// bounding metric cardinality regardless of how many addresses are configured.
	maxBeaconNodeLabels = 16
	// maxBeaconNodeLabelLen caps the length of a single beacon node address label value.
	maxBeaconNodeLabelLen = 64
	// otherBeaconNodeLabel is used for addresses beyond maxBeaconNodeLabels.
	otherBeaconNodeLabel = "other"
	// invalidBeaconNodeLabel is used for addresses that don't parse to a host.
	invalidBeaconNodeLabel = "invalid"
	// unknownBeaconNodeLabel is used for clients without a configured address.
	unknownBeaconNodeLabel = "unknown"
)

// bnLabels maps configured beacon node addresses to their metric label values.
var bnLabels = struct {
	sync.Mutex

	byAddr map[string]string
	used   map[string]bool
}{
	byAddr: make(map[string]string),
	used:   make(map[string]bool),
}

// BeaconNodeLabel returns a bounded, credential-free metric label value for a configured beacon
// node address, for example "http://10.0.0.1:5052".
//
// Only the scheme and host:port are kept: user info, path and query are dropped since hosted
// providers put API keys there. Values are truncated to maxBeaconNodeLabelLen, addresses that
// would collide get a "#n" suffix, and after maxBeaconNodeLabels distinct addresses every new
// one maps to "other". The same address always maps to the same label within a process.
func BeaconNodeLabel(addr string) string {
	bnLabels.Lock()
	defer bnLabels.Unlock()

	if label, ok := bnLabels.byAddr[addr]; ok {
		return label
	}

	label := otherBeaconNodeLabel
	if len(bnLabels.byAddr) < maxBeaconNodeLabels {
		label = uniqueLabel(sanitiseBeaconNodeAddr(addr), bnLabels.used)
		bnLabels.used[label] = true
	}

	bnLabels.byAddr[addr] = label

	return label
}

// sanitiseBeaconNodeAddr returns scheme://host[:port] of addr, truncated to maxBeaconNodeLabelLen.
func sanitiseBeaconNodeAddr(addr string) string {
	// Mirror go-eth2-client, which defaults to http when no scheme is given.
	if !strings.HasPrefix(addr, "http") {
		addr = "http://" + addr
	}

	u, err := url.Parse(addr)
	if err != nil || u.Host == "" {
		return invalidBeaconNodeLabel
	}

	label := u.Scheme + "://" + u.Host
	if len(label) > maxBeaconNodeLabelLen {
		label = label[:maxBeaconNodeLabelLen]
	}

	return label
}

// uniqueLabel returns label, or label with the lowest "#n" suffix not in used.
func uniqueLabel(label string, used map[string]bool) string {
	if !used[label] {
		return label
	}

	for i := 2; ; i++ {
		candidate := label + "#" + strconv.Itoa(i)
		if !used[candidate] {
			return candidate
		}
	}
}

// resetBeaconNodeLabelsForT clears the label cache, for tests only.
func resetBeaconNodeLabelsForT() {
	bnLabels.Lock()
	defer bnLabels.Unlock()

	bnLabels.byAddr = make(map[string]string)
	bnLabels.used = make(map[string]bool)
}
