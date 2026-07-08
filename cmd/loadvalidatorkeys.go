// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/tbls"
)

// loadValidatorShares loads the operator's local validator key shares from dir and maps them to
// their cluster validators.
//
// When allowIncomplete is false it requires shares for every validator in the lock. When true it
// accepts any subset (matching by public key, ignoring keystore filename-index gaps) and warns
// when the on-disk set covers fewer validators than the lock.
func loadValidatorShares(ctx context.Context, cl cluster.Lock, dir string, allowIncomplete bool) (keystore.ValidatorShares, error) {
	rawValKeys, err := keystore.LoadFilesUnordered(dir)
	if err != nil {
		return nil, errors.Wrap(err, "load keystore, check if path exists", z.Str("validator_keys_dir", dir))
	}

	var valKeys []tbls.PrivateKey
	if allowIncomplete {
		// Match by derived public key; keystore filename indexes are meaningless for these
		// commands, so a non-sequential subset (e.g. keystore-5.json alone) is valid.
		valKeys = rawValKeys.Keys()
	} else {
		valKeys, err = rawValKeys.SequencedKeys()
		if err != nil {
			return nil, errors.Wrap(err, "load keystore")
		}
	}

	shares, err := keystore.KeysharesToValidatorPubkey(cl, valKeys)
	if err != nil {
		return nil, errors.Wrap(err, "match local validator key shares with their counterparty in cluster lock")
	}

	if !allowIncomplete && len(shares) != len(cl.Validators) {
		return nil, errors.New("validator_keys directory does not contain key shares for all cluster validators; use --allow-incomplete-keystores to operate on the available subset",
			z.Int("found", len(shares)), z.Int("cluster_validators", len(cl.Validators)), z.Str("validator_keys_dir", dir))
	}

	if allowIncomplete && len(shares) < len(cl.Validators) {
		log.Warn(ctx, "Operating on a subset of the cluster's validators", nil,
			z.Int("found", len(shares)), z.Int("cluster_validators", len(cl.Validators)), z.Str("validator_keys_dir", dir))
	}

	return shares, nil
}
