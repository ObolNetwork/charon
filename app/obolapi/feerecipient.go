// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapi

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

const (
	submitPartialFeeRecipientTmpl = "/fee_recipient/partial/" + lockHashPath + "/" + shareIndexPath
	fetchFeeRecipientTmpl         = "/fee_recipient/" + lockHashPath

	errNoPartialsRegistrations = "no partial registrations found"
	errLockNotFound            = "lock not found"
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

// PostPartialFeeRecipients POSTs partial builder registrations to the Obol API.
// It respects the timeout specified in the Client instance.
func (c Client) PostPartialFeeRecipients(ctx context.Context, lockHash []byte, shareIndex uint64, partialRegs []PartialRegistration) error {
	lockHashStr := "0x" + hex.EncodeToString(lockHash)

	u, err := url.ParseRequestURI(c.baseURL)
	if err != nil {
		return errors.Wrap(err, "bad Obol API url")
	}

	u.Path = submitPartialFeeRecipientURL(lockHashStr, shareIndex)

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

// PostFeeRecipientsFetch fetches builder registrations from the Obol API.
// If pubkeys is non-empty, only the specified validators are included in the response.
// If pubkeys is empty, status for all validators in the cluster is returned.
// It respects the timeout specified in the Client instance.
func (c Client) PostFeeRecipientsFetch(ctx context.Context, lockHash []byte, pubkeys []string) (FeeRecipientFetchResponse, error) {
	u, err := url.ParseRequestURI(c.baseURL)
	if err != nil {
		return FeeRecipientFetchResponse{}, errors.Wrap(err, "bad Obol API url")
	}

	u.Path = fetchFeeRecipientURL("0x" + hex.EncodeToString(lockHash))

	req := FeeRecipientFetchRequest{Pubkeys: pubkeys}

	data, err := json.Marshal(req)
	if err != nil {
		return FeeRecipientFetchResponse{}, errors.Wrap(err, "json marshal error")
	}

	ctx, cancel := context.WithTimeout(ctx, c.reqTimeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(data))
	if err != nil {
		return FeeRecipientFetchResponse{}, errors.Wrap(err, "create POST request")
	}

	httpReq.Header.Add("Content-Type", "application/json")

	httpResp, err := new(http.Client).Do(httpReq)
	if err != nil {
		return FeeRecipientFetchResponse{}, errors.Wrap(err, "call POST endpoint")
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode/100 != 2 {
		body, err := io.ReadAll(httpResp.Body)
		if err != nil {
			return FeeRecipientFetchResponse{}, errors.Wrap(err, "read response", z.Int("status", httpResp.StatusCode))
		}

		if httpResp.StatusCode == http.StatusNotFound {
			if strings.Contains(string(body), errNoPartialsRegistrations) {
				return FeeRecipientFetchResponse{}, nil
			}

			if strings.Contains(string(body), errLockNotFound) {
				return FeeRecipientFetchResponse{}, errors.New("cluster is unknown to the API, publish the lock file first")
			}
		}

		return FeeRecipientFetchResponse{}, errors.New("http POST failed", z.Int("status", httpResp.StatusCode), z.Str("body", string(body)))
	}

	var resp FeeRecipientFetchResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		return FeeRecipientFetchResponse{}, errors.Wrap(err, "unmarshal response")
	}

	return resp, nil
}
