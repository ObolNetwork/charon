// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapi

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/cluster"
)

const (
	// publishLockPath is the path to publish a cluster lockfile to obol-api.
	publishLockPath = "lock"

	// publishDefinitionPath is the path to publish a cluster definition to obol-api.
	publishDefinitionPath = "/definition"

	// termsAndConditionsPath is the path to sign Obol's Terms and Conditions.
	termsAndConditionsPath = "/termsAndConditions"

	// termsAndConditionsHash is the hash of the terms and conditions that the user must sign.
	termsAndConditionsHash = "0xd33721644e8f3afab1495a74abe3523cec12d48b8da6cb760972492ca3f1a273"
)

// PublishLock posts the lockfile to obol-api.
// It respects the timeout specified in the Client instance.
func (c Client) PublishLock(ctx context.Context, lock cluster.Lock) error {
	addr := c.url()
	addr.Path = publishLockPath

	b, err := lock.MarshalJSON()
	if err != nil {
		return errors.Wrap(err, "marshal lock")
	}

	ctx, cancel := context.WithTimeout(ctx, c.reqTimeout)
	defer cancel()

	err = httpPost(ctx, addr, b, nil)
	if err != nil {
		return err
	}

	return nil
}

// PublishDefinition posts the cluster definition to obol-api.
// It requires the cluster creator to previously sign Obol's Terms and Conditions.
func (c Client) PublishDefinition(ctx context.Context, def cluster.Definition, sig []byte) error {
	addr := c.url()
	addr.Path += publishDefinitionPath

	b, err := def.MarshalJSONAPI()
	if err != nil {
		return errors.Wrap(err, "marshal definition")
	}

	headers := map[string]string{
		"authorization": bearerString(sig),
	}

	ctx, cancel := context.WithTimeout(ctx, c.reqTimeout)
	defer cancel()

	return httpPost(ctx, addr, b, headers)
}

type RequestSignTermsAndConditions struct {
	Address                string `json:"address"`
	Version                int    `json:"version"`
	TermsAndConditionsHash string `json:"terms_and_conditions_hash"`
	ForkVersion            string `json:"fork_version"`
}

// SignTermsAndConditions submits the user's signature of Obol's Terms and Conditions to obol-api.
func (c Client) SignTermsAndConditions(ctx context.Context, userAddr string, forkVersion []byte, sig []byte) error {
	addr := c.url()
	addr.Path += termsAndConditionsPath

	req := RequestSignTermsAndConditions{
		Address:                userAddr,
		Version:                1,
		TermsAndConditionsHash: termsAndConditionsHash,
		ForkVersion:            fmt.Sprintf("0x%x", forkVersion),
	}

	r, err := json.Marshal(req)
	if err != nil {
		return errors.Wrap(err, "marshal sign terms and Conditions")
	}

	headers := map[string]string{
		"authorization": bearerString(sig),
	}

	ctx, cancel := context.WithTimeout(ctx, c.reqTimeout)
	defer cancel()
	return httpPost(ctx, addr, r, headers)
}
