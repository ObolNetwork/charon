// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package version

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidVersion(t *testing.T) {
	v, err := Parse(version)
	require.NoError(t, err)
	require.Equal(t, v, Version)
}

func TestParseSemVer(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    SemVer
		wantErr bool
	}{
		{
			name:    "Patch",
			version: "v1.2.3",
			want:    SemVer{major: 1, minor: 2, patch: 3, semVerType: typePatch},
			wantErr: false,
		},
		{
			name:    "PreRelease",
			version: "v0.17-dev",
			want:    SemVer{major: 0, minor: 17, preRelease: "dev", semVerType: typePreRelease},
		},
		{
			name:    "Minor",
			version: "v0.1",
			want:    SemVer{major: 0, minor: 1, semVerType: typeMinor},
		},
		{
			name:    "Empty",
			version: "",
			wantErr: true,
		},
		{
			name:    "Invalid 1",
			version: "invalid",
			wantErr: true,
		},
		{
			name:    "No v prefix",
			version: "1.2.3",
			wantErr: true,
		},
		{
			name:    "Invalid 2",
			version: "12-dev",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.version)

			if (err != nil) != tt.wantErr {
				require.Fail(t, "Unexpected error", "ParseSemVer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			require.Equal(t, tt.want, got)
		})
	}
}
