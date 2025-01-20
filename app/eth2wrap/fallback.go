// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"sync"
	"time"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

// FallbackClient holds a list of initialized Clients to be used when main client calls
// return errors.
type FallbackClient struct {
	clients []Client
	next    int

	lock sync.Mutex
}

// NewFallbackClient initializes a FallbackClient with the provided settings
func NewFallbackClient(timeout time.Duration, forkVersion [4]byte, addresses []string) *FallbackClient {
	return &FallbackClient{
		clients: newClients(timeout, forkVersion, map[string]string{}, addresses),
	}
}

// NewFallbackClientT initializes a FallbackClient with initialized clients for testing
func NewFallbackClientT(clients ...Client) *FallbackClient {
	return &FallbackClient{
		clients: clients,
	}
}

// pick returns an available fallback client.
// If no clients are available, it'll return an error.
func (f *FallbackClient) pick() (Client, error) {
	f.lock.Lock()
	defer f.lock.Unlock()

	if f.next >= len(f.clients) {
		return nil, errors.New("all fallback clients have been taken", z.Int("total", len(f.clients)))
	}

	ret := f.clients[f.next]
	f.next++

	return ret, nil
}

// place returns a client back to the fallback client list.
// Callers must not re-use a client previously taken through pick() after this function has been called.
func (f *FallbackClient) place() {
	f.lock.Lock()
	defer f.lock.Unlock()

	if len(f.clients) == 0 {
		return // no clients initialized, no need to place anything
	}

	f.next--
}
