// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

const (
	submitPartialDepositTmpl = "/deposit_data/partial_deposits/" + lockHashPath + "/" + shareIndexPath
	fetchFullDepositTmpl     = "/deposit_data/" + lockHashPath + "/" + valPubkeyPath
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

// fetchFullDepositURL returns the full deposit Obol API URL for a given validator public key.
func fetchFullDepositURL(valPubkey, lockHash string) string {
	return strings.NewReplacer(
		valPubkeyPath,
		valPubkey,
		lockHashPath,
		lockHash,
	).Replace(fetchFullDepositTmpl)
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

	apiDepositWrap := PartialDepositRequest{PartialDepositData: depositBlobs}

	data, err := json.Marshal(apiDepositWrap)
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

// GetFullDeposit gets the full deposit message for a given validator public key, lock hash and share index.
// It respects the timeout specified in the Client instance.
func (c Client) GetFullDeposit(ctx context.Context, valPubkey string, lockHash []byte, threshold int) ([]eth2p0.DepositData, error) {
	valPubkeyBytes, err := from0x(valPubkey, len(eth2p0.BLSPubKey{}))
	if err != nil {
		return []eth2p0.DepositData{}, errors.Wrap(err, "validator pubkey to bytes")
	}

	path := fetchFullDepositURL(valPubkey, "0x"+hex.EncodeToString(lockHash))

	u, err := url.ParseRequestURI(c.baseURL)
	if err != nil {
		return []eth2p0.DepositData{}, errors.Wrap(err, "bad Obol API url")
	}

	u.Path = path

	ctx, cancel := context.WithTimeout(ctx, c.reqTimeout)
	defer cancel()

	respBody, err := httpGet(ctx, u, map[string]string{})
	if err != nil {
		return []eth2p0.DepositData{}, errors.Wrap(err, "http Obol API GET request")
	}

	defer respBody.Close()

	var dr FullDepositResponse
	if err := json.NewDecoder(respBody).Decode(&dr); err != nil {
		return []eth2p0.DepositData{}, errors.Wrap(err, "json unmarshal error")
	}

	withdrawalCredentialsBytes, err := hex.DecodeString(strings.TrimPrefix(dr.WithdrawalCredentials, "0x"))
	if err != nil {
		return []eth2p0.DepositData{}, errors.Wrap(err, "withdrawal credentials to bytes")
	}

	// do aggregation
	fullDeposits := []eth2p0.DepositData{}

	for _, am := range dr.Amounts {
		rawSignatures := make(map[int]tbls.Signature)

		if len(am.Partials) < threshold {
			submittedPubKeys := []string{}
			for _, sigStr := range am.Partials {
				submittedPubKeys = append(submittedPubKeys, sigStr.PartialPublicKey)
			}

			return []eth2p0.DepositData{}, errors.New("not enough partial signatures to meet threshold", z.Any("submitted_public_keys", submittedPubKeys), z.Int("submitted_public_keys_length", len(submittedPubKeys)), z.Int("required_threshold", threshold))
		}

		for sigIdx, sigStr := range am.Partials {
			if len(sigStr.PartialDepositSignature) == 0 {
				// ignore, the associated share index didn't push a partial signature yet
				continue
			}

			if len(sigStr.PartialDepositSignature) < 2 {
				return []eth2p0.DepositData{}, errors.New("signature string has invalid size", z.Int("size", len(sigStr.PartialDepositSignature)))
			}

			sigBytes, err := from0x(sigStr.PartialDepositSignature, 96) // a signature is 96 bytes long
			if err != nil {
				return []eth2p0.DepositData{}, errors.Wrap(err, "partial signature unmarshal")
			}

			sig, err := tblsconv.SignatureFromBytes(sigBytes)
			if err != nil {
				return []eth2p0.DepositData{}, errors.Wrap(err, "invalid partial signature")
			}

			rawSignatures[sigIdx+1] = sig
		}

		fullSig, err := tbls.ThresholdAggregate(rawSignatures)
		if err != nil {
			return []eth2p0.DepositData{}, errors.Wrap(err, "partial signatures threshold aggregate")
		}

		amountUint, err := strconv.ParseUint(am.Amount, 10, 64)
		if err != nil {
			return []eth2p0.DepositData{}, errors.Wrap(err, "parse amount to uint")
		}

		fullDeposits = append(fullDeposits, eth2p0.DepositData{
			PublicKey:             eth2p0.BLSPubKey(valPubkeyBytes),
			WithdrawalCredentials: withdrawalCredentialsBytes,
			Amount:                eth2p0.Gwei(amountUint),
			Signature:             eth2p0.BLSSignature(fullSig),
		})
	}

	return fullDeposits, nil
}
