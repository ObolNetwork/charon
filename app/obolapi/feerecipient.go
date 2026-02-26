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
	fetchPartialFeeRecipientTmpl  = "/fee_recipient/" + lockHashPath + "/" + valPubkeyPath
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

// fetchPartialFeeRecipientURL returns the partial fee recipient Obol API URL for a given validator public key.
func fetchPartialFeeRecipientURL(valPubkey, lockHash string) string {
	return strings.NewReplacer(
		valPubkeyPath,
		valPubkey,
		lockHashPath,
		lockHash,
	).Replace(fetchPartialFeeRecipientTmpl)
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

// GetPartialFeeRecipients fetches partial fee recipient registrations from the Obol API.
// It respects the timeout specified in the Client instance.
func (c Client) GetPartialFeeRecipients(ctx context.Context, valPubkey string, lockHash []byte, _ int) (PartialFeeRecipientResponse, error) {
	path := fetchPartialFeeRecipientURL(valPubkey, "0x"+hex.EncodeToString(lockHash))

	u, err := url.ParseRequestURI(c.baseURL)
	if err != nil {
		return PartialFeeRecipientResponse{}, errors.Wrap(err, "bad Obol API url")
	}

	u.Path = path

	ctx, cancel := context.WithTimeout(ctx, c.reqTimeout)
	defer cancel()

	respBody, err := httpGet(ctx, u, map[string]string{})
	if err != nil {
		return PartialFeeRecipientResponse{}, errors.Wrap(err, "http Obol API GET request")
	}

	defer respBody.Close()

	var resp PartialFeeRecipientResponse
	if err := json.NewDecoder(respBody).Decode(&resp); err != nil {
		return PartialFeeRecipientResponse{}, errors.Wrap(err, "unmarshal response")
	}

	if len(resp.Partials) == 0 {
		return PartialFeeRecipientResponse{}, ErrNoValue
	}

	return resp, nil
}
