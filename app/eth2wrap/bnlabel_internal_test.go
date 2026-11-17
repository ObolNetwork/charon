// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSanitiseBeaconNodeAddr(t *testing.T) {
	tests := []struct {
		addr string
		want string
	}{
		{"http://10.0.0.1:5052", "http://10.0.0.1:5052"},
		{"10.0.0.1:5052", "http://10.0.0.1:5052"},
		{"httpbn:5052", "http://httpbn:5052"},
		{"https://user:secret@bn.example.com/apikey123?token=abc", "https://bn.example.com"},
		{"https://bn.example.com/eth/v1/", "https://bn.example.com"},
		{"http://[::1]:5052", "http://[::1]:5052"},
		{"http://", invalidBeaconNodeLabel},
		{"http://bad host:5052", invalidBeaconNodeLabel},
		{"https://" + strings.Repeat("a", 100) + ".com", ("https://" + strings.Repeat("a", 100))[:maxBeaconNodeLabelLen]},
	}

	for _, test := range tests {
		t.Run(test.addr, func(t *testing.T) {
			got := sanitiseBeaconNodeAddr(test.addr)
			require.Equal(t, test.want, got)
			require.NotContains(t, got, "secret")
			require.NotContains(t, got, "apikey")
			require.LessOrEqual(t, len(got), maxBeaconNodeLabelLen)
		})
	}
}

func TestBeaconNodeLabel(t *testing.T) {
	resetBeaconNodeLabelsForT()
	t.Cleanup(resetBeaconNodeLabelsForT)

	// Stable for the same address.
	require.Equal(t, "http://10.0.0.1:5052", BeaconNodeLabel("http://10.0.0.1:5052"))
	require.Equal(t, "http://10.0.0.1:5052", BeaconNodeLabel("http://10.0.0.1:5052"))

	// Different addresses on the same host don't collide.
	require.Equal(t, "https://bn.example.com", BeaconNodeLabel("https://bn.example.com/key1"))
	require.Equal(t, "https://bn.example.com#2", BeaconNodeLabel("https://bn.example.com/key2"))
	require.Equal(t, "https://bn.example.com#2", BeaconNodeLabel("https://bn.example.com/key2"))

	// Capped.
	for i := range 2 * maxBeaconNodeLabels {
		BeaconNodeLabel(fmt.Sprintf("http://10.1.0.%d:5052", i))
	}

	distinct := make(map[string]bool)
	for _, label := range bnLabels.byAddr {
		distinct[label] = true
	}

	require.Len(t, distinct, maxBeaconNodeLabels+1) // Including "other".
	require.True(t, distinct[otherBeaconNodeLabel])
	require.Equal(t, otherBeaconNodeLabel, BeaconNodeLabel("http://10.2.0.1:5052"))

	// Earlier addresses keep their label.
	require.Equal(t, "http://10.0.0.1:5052", BeaconNodeLabel("http://10.0.0.1:5052"))
}
