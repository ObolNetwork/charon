// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package peerinfo

import (
	"fmt"
	"strings"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

func TestSupporterVersion(t *testing.T) {
	tests := []struct {
		PeerVersion       string
		SupportedVersions []version.SemVer
		ErrContains       string
	}{
		{
			PeerVersion:       "v0.1.0",
			SupportedVersions: semvers("v0.1"),
		},
		{
			PeerVersion:       "v0.1.1",
			SupportedVersions: semvers("v0.1"),
		},
		{
			PeerVersion:       "v0.1.2",
			SupportedVersions: semvers("v0.2", "v0.1"),
		},
		{
			PeerVersion:       "v0.1-rc",
			SupportedVersions: semvers("v0.1"),
		},
		{
			PeerVersion:       "v0.1.3",
			SupportedVersions: semvers("v0.2"),
			ErrContains:       "unsupported peer version",
		},
		{
			PeerVersion:       "v0.2.0",
			SupportedVersions: semvers("v0.1"),
		},
		{
			PeerVersion:       "",
			SupportedVersions: semvers("v0.1"),
			ErrContains:       "invalid version string",
		},
	}
	for _, test := range tests {
		t.Run(test.PeerVersion, func(t *testing.T) {
			err := supportedPeerVersion(test.PeerVersion, test.SupportedVersions)
			if test.ErrContains != "" {
				require.ErrorContains(t, err, test.ErrContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestPeerBuilderAPIEnabledGauge(t *testing.T) {
	server := testutil.CreateHost(t, testutil.AvailableAddr(t))
	client := testutil.CreateHost(t, testutil.AvailableAddr(t))

	lockHash := []byte("123")
	gitHash := "abc"
	peerName := p2p.PeerName(server.ID())

	tests := []struct {
		name           string
		builderEnabled bool
		expectedValue  int
	}{
		{"builder enabled", true, 1},
		{"builder disabled", false, 0},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_ = New(server, []peer.ID{server.ID(), client.ID()}, version.Version, lockHash, gitHash, nil, test.builderEnabled)

			expectedMetric := fmt.Sprintf(`
			# HELP app_peerinfo_builder_api_enabled Set to 1 if builder API is enabled on this peer, else 0 if disabled.
			# TYPE app_peerinfo_builder_api_enabled gauge
			app_peerinfo_builder_api_enabled{ peer = "%s" } %d
			`, peerName, test.expectedValue)

			if err := promtestutil.CollectAndCompare(peerBuilderAPIEnabledGauge, strings.NewReader(expectedMetric), "app_peerinfo_builder_api_enabled"); err != nil {
				require.NoError(t, err, "failed to collect metric")
			}
		})
	}
}

func semvers(s ...string) []version.SemVer {
	var resp []version.SemVer
	for _, v := range s {
		sv, _ := version.Parse(v)
		resp = append(resp, sv)
	}

	return resp
}
