// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"context"
	"sync"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2http "github.com/attestantio/go-eth2-client/http"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/testutil/validatormock" // Allow testutil
)

// wireValidatorMock wires the validator mock if enabled. It connects via http validatorapi.Router.
func wireValidatorMock(ctx context.Context, conf Config, eth2Cl eth2wrap.Client, pubshares []eth2p0.BLSPubKey, sched core.Scheduler) error {
	if !conf.SimnetVMock {
		return nil
	}

	signer, err := newVMockSigner(conf, pubshares)
	if err != nil {
		return err
	}

	spec, err := eth2wrap.FetchNetworkSpec(ctx, eth2Cl)
	if err != nil {
		return err
	}

	vmock := validatormock.New(ctx, newVMockEth2Provider(conf, pubshares), signer, pubshares, spec.GenesisTime, spec.SlotDuration,
		spec.SlotsPerEpoch, conf.BuilderAPI)
	sched.SubscribeSlots(vmock.SlotTicked)

	return nil
}

// newVMockEth2Provider returns a function that returns a cached validator mock eth2 client.
func newVMockEth2Provider(conf Config, pubshares []eth2p0.BLSPubKey) func() (eth2wrap.Client, error) {
	var (
		cached eth2wrap.Client
		mu     sync.Mutex
	)
	const timeout = time.Second * 10

	return func() (eth2wrap.Client, error) {
		mu.Lock()
		defer mu.Unlock()

		if cached != nil {
			return cached, nil
		}

		// Try three times to reduce test startup issues.
		var err error
		for range 3 {
			var eth2Svc eth2client.Service
			eth2Svc, err = eth2http.New(context.Background(),
				eth2http.WithLogLevel(1),
				eth2http.WithAddress("http://"+conf.ValidatorAPIAddr),
				eth2http.WithTimeout(timeout), // Allow sufficient time to block while fetching duties.
			)
			if err != nil {
				time.Sleep(time.Millisecond * 100) // Test startup backoff
				continue
			}
			eth2Http, ok := eth2Svc.(*eth2http.Service)
			if !ok {
				return nil, errors.New("invalid eth2 http service")
			}

			cached = eth2wrap.AdaptEth2HTTP(eth2Http, nil, timeout)
			valCache := eth2wrap.NewValidatorCache(cached, pubshares)
			cached.SetValidatorCache(valCache.GetByHead)

			break
		}

		return cached, err
	}
}

// newVMockSigner returns a validator mock sign function using keystore loaded from disk.
func newVMockSigner(conf Config, pubshares []eth2p0.BLSPubKey) (validatormock.SignFunc, error) {
	secrets := conf.TestConfig.SimnetKeys
	if len(secrets) == 0 {
		keyFiles, err := keystore.LoadFilesUnordered(conf.SimnetValidatorKeysDir)
		if err != nil {
			return nil, err
		}

		secrets, err = keyFiles.SequencedKeys()
		if err != nil {
			return nil, err
		}
	}

	signer, err := validatormock.NewSigner(secrets...)
	if err != nil {
		return nil, err
	}

	if len(secrets) == 0 && len(pubshares) != 0 {
		return nil, errors.New("validator mock keys empty")
	}
	if len(secrets) < len(pubshares) {
		return nil, errors.New("some validator mock keys missing", z.Int("expect", len(pubshares)), z.Int("found", len(secrets)))
	}
	for i, pubshare := range pubshares {
		_, err := signer(pubshare, []byte("test signing"))
		if err != nil {
			return nil, errors.Wrap(err, "validator mock key missing", z.Int("index", i))
		}
	}

	return signer, nil
}
