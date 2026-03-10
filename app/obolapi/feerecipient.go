// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	"github.com/obolnetwork/charon/app/errors"
)

const (
	submitPartialFeeRecipientTmpl = "/fee_recipient/partial/" + lockHashPath + "/" + shareIndexPath
	fetchFeeRecipientTmpl         = "/fee_recipient/" + lockHashPath
)

// submitPartialFeeRecipientURL returns the partial fee recipient Obol API URL for a given lock hash.
func submitPartialFeeRecipientURL(lockHash string, shareIndex uint64) string {
	return strings.NewReplacer(
		lockHashPath,
		lockHash,
		shareIndexPath,
		strconv.FormatUint(shareIndex, 10),
	).Replace(submitPartialFeeRecipientTmpl)
}

// fetchFeeRecipientURL returns the fee recipient Obol API URL for a given lock hash.
func fetchFeeRecipientURL(lockHash string) string {
	return strings.NewReplacer(
		lockHashPath,
		lockHash,
	).Replace(fetchFeeRecipientTmpl)
}

// PostPartialFeeRecipients POSTs partial fee recipient registrations to the Obol API.
// It respects the timeout specified in the Client instance.
func (c Client) PostPartialFeeRecipients(ctx context.Context, lockHash []byte, shareIndex uint64, partialRegs []PartialRegistration) error {
	lockHashStr := "0x" + hex.EncodeToString(lockHash)

	path := submitPartialFeeRecipientURL(lockHashStr, shareIndex)

	u, err := url.ParseRequestURI(c.baseURL)
	if err != nil {
		return errors.Wrap(err, "bad Obol API url")
	}

	u.Path = path

	req := PartialFeeRecipientRequest{PartialRegistrations: partialRegs}

	data, err := json.Marshal(req)
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

// PostFeeRecipientsFetch fetches aggregated fee recipient registrations and per-validator status from the Obol API.
// If pubkeys is non-empty, only the specified validators are included in the response.
// If pubkeys is empty, status for all validators in the cluster is returned.
// It respects the timeout specified in the Client instance.
func (c Client) PostFeeRecipientsFetch(ctx context.Context, lockHash []byte, pubkeys []string) (FeeRecipientFetchResponse, error) {
	path := fetchFeeRecipientURL("0x" + hex.EncodeToString(lockHash))

	u, err := url.ParseRequestURI(c.baseURL)
	if err != nil {
		return FeeRecipientFetchResponse{}, errors.Wrap(err, "bad Obol API url")
	}

	u.Path = path

	req := FeeRecipientFetchRequest{Pubkeys: pubkeys}

	data, err := json.Marshal(req)
	if err != nil {
		return FeeRecipientFetchResponse{}, errors.Wrap(err, "json marshal error")
	}

	ctx, cancel := context.WithTimeout(ctx, c.reqTimeout)
	defer cancel()

	respBody, err := httpPostWithResponse(ctx, u, data, nil)
	if err != nil {
		return FeeRecipientFetchResponse{}, errors.Wrap(err, "http Obol API POST request")
	}

	defer respBody.Close()

	var resp FeeRecipientFetchResponse
	if err := json.NewDecoder(respBody).Decode(&resp); err != nil {
		return FeeRecipientFetchResponse{}, errors.Wrap(err, "unmarshal response")
	}

	return resp, nil
}
