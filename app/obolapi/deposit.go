// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
)

const (
	submitPartialDepositTmpl = "/deposit_data/partial_deposits/" + lockHashPath + "/" + shareIndexPath
)

// submitPartialDepositURL returns the partial deposit Obol API URL for a given lock hash.
func submitPartialDepositURL(lockHash string, shareIndex uint64) string {
	return strings.NewReplacer(
		lockHashPath,
		lockHash,
		shareIndexPath,
		strconv.FormatUint(shareIndex, 10),
	).Replace(submitPartialDepositTmpl)
}

// PostPartialDeposits POSTs the set of msg's to the Obol API, for a given lock hash.
// It respects the timeout specified in the Client instance.
func (c Client) PostPartialDeposits(ctx context.Context, lockHash []byte, shareIndex uint64, depositBlobs []eth2p0.DepositData) error {
	lockHashStr := "0x" + hex.EncodeToString(lockHash)

	path := submitPartialDepositURL(lockHashStr, shareIndex)

	u, err := url.ParseRequestURI(c.baseURL)
	if err != nil {
		return errors.Wrap(err, "bad Obol API url")
	}

	u.Path = path

	data, err := json.Marshal(depositBlobs)
	if err != nil {
		return errors.Wrap(err, "json marshal error")
	}

	ctx, cancel := context.WithTimeout(ctx, c.reqTimeout)
	defer cancel()

	err = httpPost(ctx, u, data, nil)
	if err != nil {
		return errors.Wrap(err, "http Obol API POST request")
	}

	return nil
}
