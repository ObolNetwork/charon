// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestClientForAddressConfigured asserts that configured addresses match their clients via the
// original configured address, since client Address() returns the masked form (credentials,
// path and query redacted) which is ambiguous between endpoints on the same host.
func TestClientForAddressConfigured(t *testing.T) {
	newConfClient := func(confAddr string) Client {
		l := newLazy(nil)
		l.confAddress = confAddr

		return l
	}

	var (
		// Two endpoints on the same host differ only by path, which the masked form hides.
		clientA = newConfClient("http://bn.example.com:5052/node-a")
		clientB = newConfClient("http://bn.example.com:5052/node-b")
		// Credentials and scheme-less forms are also lost in the masked form.
		clientC = newConfClient("http://user:secret@bn-c.example.com:5052")
		clientD = newConfClient("bn-d.example.com:5052")
	)

	m := multi{clients: []Client{clientA, clientB, clientC, clientD}}

	scoped := m.ClientForAddress("http://bn.example.com:5052/node-b")
	require.Same(t, clientB, scoped.(multi).clients[0])

	scoped = m.ClientForAddress("http://user:secret@bn-c.example.com:5052")
	require.Same(t, clientC, scoped.(multi).clients[0])

	scoped = m.ClientForAddress("bn-d.example.com:5052")
	require.Same(t, clientD, scoped.(multi).clients[0])

	// Unknown addresses return the unscoped multi client.
	unscoped := m.ClientForAddress("http://unknown.example.com:5052")
	require.Len(t, unscoped.(multi).clients, 4)

	// Fallbacks are matched the same way.
	mf := multi{clients: []Client{clientA}, fallbacks: []Client{clientC}}

	scoped = mf.ClientForAddress("http://user:secret@bn-c.example.com:5052")
	require.Same(t, clientC, scoped.(multi).clients[0])
}
