// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// addrClient is a minimal Client stub for prepState tests. preparedClients only calls Address(),
// so the embedded nil Client never has its other methods invoked.
type addrClient struct {
	Client

	addr string
}

func (c addrClient) Address() string { return c.addr }

// TestPrepState_BeforeAnyPrep returns clients unchanged before any markSuccess/markFailure
// — failing closed here would cause missed proposals.
func TestPrepState_BeforeAnyPrep(t *testing.T) {
	p := newPrepState()
	a := addrClient{addr: "http://a"}
	b := addrClient{addr: "http://b"}

	got := p.preparedClients([]Client{a, b})
	require.Equal(t, []Client{a, b}, got)
}

// TestPrepState_AllFailed falls back to the full client list rather than excluding everyone.
func TestPrepState_AllFailed(t *testing.T) {
	p := newPrepState()
	p.markFailure("http://a")
	p.markFailure("http://b")

	a := addrClient{addr: "http://a"}
	b := addrClient{addr: "http://b"}

	got := p.preparedClients([]Client{a, b})
	require.Equal(t, []Client{a, b}, got)
}

// TestPrepState_MixedSuccessAndFailure excludes only the explicitly-failed BN.
func TestPrepState_MixedSuccessAndFailure(t *testing.T) {
	p := newPrepState()
	p.markSuccess("http://a")
	p.markFailure("http://b")

	a := addrClient{addr: "http://a"}
	b := addrClient{addr: "http://b"}

	got := p.preparedClients([]Client{a, b})
	require.Equal(t, []Client{a}, got)
}

// TestPrepState_MissingKeysAreIncluded verifies that a client never recorded — e.g. its prep
// was skipped by the cancellation guard — is included rather than incorrectly excluded.
// Without this, a BN whose state is "unknown" gets dropped from future Proposal calls until
// its next markSuccess, which is the failure mode #4477's cancellation guard exists to prevent.
func TestPrepState_MissingKeysAreIncluded(t *testing.T) {
	p := newPrepState()
	// Only one BN got a recorded outcome; the other was never touched.
	p.markSuccess("http://recorded")

	recorded := addrClient{addr: "http://recorded"}
	missing := addrClient{addr: "http://missing"}

	got := p.preparedClients([]Client{recorded, missing})
	require.Equal(t, []Client{recorded, missing}, got, "missing-key client must be included")
}
