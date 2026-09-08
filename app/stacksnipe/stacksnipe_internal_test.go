// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package stacksnipe

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRedactCmdline(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "sensitive flag space form",
			args: []string{"--keystore-password", "SuperSecretPw123!"},
			want: []string{"--keystore-password", redactedValue},
		},
		{
			name: "sensitive flag equals form",
			args: []string{"--keymanager-auth-token=eyJhbGciOiJSUzI1NiJ9.secret"},
			want: []string{"--keymanager-auth-token=" + redactedValue},
		},
		{
			name: "non-sensitive flags untouched",
			args: []string{"--datadir", "/var/lib/lighthouse", "--debug-level", "info"},
			want: []string{"--datadir", "/var/lib/lighthouse", "--debug-level", "info"},
		},
		{
			name: "value starting with a dash is still redacted",
			args: []string{"--keystore-password", "-hunter2", "--debug-level", "info"},
			want: []string{"--keystore-password", redactedValue, "--debug-level", "info"},
		},
		{
			name: "sensitive boolean flag followed by a long flag",
			args: []string{"--keymanager", "--datadir", "/var/lib/teku"},
			want: []string{"--keymanager", "--datadir", "/var/lib/teku"},
		},
		{
			name: "basic-auth credentials in a URL value of an innocuous flag",
			args: []string{"--beacon-nodes", "https://user:s3cret@bn.internal:5052"},
			want: []string{"--beacon-nodes", "https://user:" + redactedValue + "@bn.internal:5052"},
		},
		{
			name: "basic-auth credentials in the equals form",
			args: []string{"--beacon-nodes=https://user:s3cret@bn.internal"},
			want: []string{"--beacon-nodes=https://user:" + redactedValue + "@bn.internal"},
		},
		{
			name: "sensitive query parameter in a URL value",
			args: []string{"--metrics-url", "https://push.internal/ingest?token=abc123&interval=5s"},
			want: []string{"--metrics-url", "https://push.internal/ingest?token=" + redactedValue + "&interval=5s"},
		},
		{
			name: "innocuous query parameters untouched",
			args: []string{"--beacon-nodes", "https://bn.internal?timeout=5s&retries=3"},
			want: []string{"--beacon-nodes", "https://bn.internal?timeout=5s&retries=3"},
		},
		{
			name: "plain host:port URL without credentials untouched",
			args: []string{"--validators-external-signer-url", "https://signer.internal:9000"},
			want: []string{"--validators-external-signer-url", "https://signer.internal:9000"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, redactCmdline(tt.args))
		})
	}
}

// TestRedactCmdlineBlob covers the fail-safe fallback for a whole command line that arrives as a
// single blob rather than the NUL separated form a real /proc exposes.
func TestRedactCmdlineBlob(t *testing.T) {
	tests := []struct {
		name           string
		blob           string
		wantContain    []string
		wantNotContain []string
	}{
		{
			name:           "unquoted multi word value redacts every token, not just the first",
			blob:           "lighthouse vc --keystore-password My Secret Pw --debug-level info",
			wantContain:    []string{"--keystore-password " + redactedValue, "--debug-level info"},
			wantNotContain: []string{"My", "Secret", "Pw"},
		},
		{
			name:           "quoted value with spaces stays one argument and is redacted whole",
			blob:           `lighthouse vc --keystore-password "alpha beta gamma" --debug-level info`,
			wantContain:    []string{"--keystore-password " + redactedValue, "--debug-level info"},
			wantNotContain: []string{"alpha", "beta", "gamma"},
		},
		{
			name:           "single quotes are honoured too",
			blob:           `teku vc --validators-keystore-password 'p a s s'`,
			wantContain:    []string{"--validators-keystore-password " + redactedValue},
			wantNotContain: []string{"p a s s", "a s s"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := strings.Join(redactCmdline([]string{tt.blob}), " ")

			for _, want := range tt.wantContain {
				require.Contains(t, got, want)
			}

			for _, notWant := range tt.wantNotContain {
				require.NotContains(t, got, notWant)
			}
		})
	}
}

func TestIsSensitiveFlag(t *testing.T) {
	sensitive := []string{
		"--keystore-password", "--jwt-secret", "--api-token", "--wallet-passphrase",
		"--mnemonic-file", "--auth-token", "--graffiti-key",
	}
	for _, name := range sensitive {
		require.True(t, isSensitiveFlag(name), name)
	}

	innocuous := []string{"--datadir", "--debug-level", "--suggested-fee-recipient", "--network"}
	for _, name := range innocuous {
		require.False(t, isSensitiveFlag(name), name)
	}
}
