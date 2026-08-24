// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package validatorapi

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestProxyPathLabel(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "static path",
			path: "/eth/v1/beacon/genesis",
			want: "eth_v1_beacon_genesis",
		},
		{
			name: "block by root collapses hex",
			path: "/eth/v2/beacon/blocks/0x0342020caa311b9f104cd1b223872b7d416d868d2e5add744e7af8265ba435ff",
			want: "eth_v2_beacon_blocks_{hex}",
		},
		{
			name: "named block id kept",
			path: "/eth/v2/beacon/blocks/head",
			want: "eth_v2_beacon_blocks_head",
		},
		{
			name: "numeric slot collapsed",
			path: "/eth/v1/beacon/blocks/123456/root",
			want: "eth_v1_beacon_blocks_{n}_root",
		},
		{
			name: "pubkey collapses hex",
			path: "/eth/v1/beacon/states/head/validators/0xa1b2c3",
			want: "eth_v1_beacon_states_head_validators_{hex}",
		},
		{
			name: "validator index collapsed",
			path: "/eth/v1/validator/duties/attester/42",
			want: "eth_v1_validator_duties_attester_{n}",
		},
		{
			name: "peer id collapsed",
			path: "/eth/v1/node/peers/QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N",
			want: "eth_v1_node_peers_{peer_id}",
		},
		{
			name: "peers list (no id) kept",
			path: "/eth/v1/node/peers",
			want: "eth_v1_node_peers",
		},
		{
			name: "empty path",
			path: "/",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, proxyPathLabel(tt.path))
		})
	}
}

func TestProxyPathLabelBoundedCardinality(t *testing.T) {
	// Distinct block roots must collapse to a single label value.
	a := proxyPathLabel("/eth/v2/beacon/blocks/0x0342020caa311b9f104cd1b223872b7d416d868d2e5add744e7af8265ba435ff")
	b := proxyPathLabel("/eth/v2/beacon/blocks/0x04639c0c1fff050014a818280fcd12dc8880077583e83fee738afd74ade618c0")
	require.Equal(t, a, b)
}

func TestVCUserAgentRegistry(t *testing.T) {
	t.Cleanup(func() {
		vcUserAgentRegistry.Lock()
		vcUserAgentRegistry.agents = make(map[string]time.Time)
		vcUserAgentRegistry.Unlock()
	})

	recordVCUserAgent("Lighthouse/v9.0.1")
	recordVCUserAgent("Vouch/v1.12.0")
	recordVCUserAgent("Lighthouse/v9.0.1") // Duplicates refresh, not grow.

	require.Equal(t, []string{"Lighthouse/v9.0.1", "Vouch/v1.12.0"}, SeenVCUserAgents())

	// The registry is bounded: agents beyond the cap are dropped.
	for i := range maxVCUserAgents * 2 {
		recordVCUserAgent(fmt.Sprintf("agent-%d", i))
	}

	require.Len(t, SeenVCUserAgents(), maxVCUserAgents)

	// Expired agents are pruned, making room for new ones.
	vcUserAgentRegistry.Lock()
	for agent := range vcUserAgentRegistry.agents {
		vcUserAgentRegistry.agents[agent] = time.Now().Add(-2 * vcUserAgentTTL)
	}
	vcUserAgentRegistry.Unlock()

	recordVCUserAgent("teku/v25.9.3")
	require.Equal(t, []string{"teku/v25.9.3"}, SeenVCUserAgents())
}
