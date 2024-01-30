// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package peerinfo

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/version"
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

func semvers(s ...string) []version.SemVer {
	var resp []version.SemVer
	for _, v := range s {
		sv, _ := version.Parse(v)
		resp = append(resp, sv)
	}

	return resp
}
