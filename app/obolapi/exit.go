// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapi

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

const (
	lockHashPath     = "{lock_hash}"
	valPubkeyPath    = "{validator_pubkey}"
	shareIndexPath   = "{share_index}"
	fullExitBaseTmpl = "/exp/exit"
	fullExitEndTmp   = "/" + lockHashPath + "/" + shareIndexPath + "/" + valPubkeyPath

	partialExitTmpl = "/exp/partial_exits/" + lockHashPath
	fullExitTmpl    = fullExitBaseTmpl + fullExitEndTmp
)

var ErrNoExit = errors.New("no exit for the given validator public key")

// partialExitURL returns the partial exit Obol API URL for a given lock hash.
func partialExitURL(lockHash string) string {
	return strings.NewReplacer(
		lockHashPath,
		lockHash,
	).Replace(partialExitTmpl)
}

// bearerString returns the bearer token authentication string given a token.
func bearerString(data []byte) string {
	return fmt.Sprintf("Bearer %#x", data)
}

// fullExitURL returns the full exit Obol API URL for a given validator public key.
func fullExitURL(valPubkey, lockHash string, shareIndex uint64) string {
	return strings.NewReplacer(
		valPubkeyPath,
		valPubkey,
		lockHashPath,
		lockHash,
		shareIndexPath,
		strconv.FormatUint(shareIndex, 10),
	).Replace(fullExitTmpl)
}

// PostPartialExit POSTs the set of msg's to the Obol API, for a given lock hash.
func (c Client) PostPartialExit(ctx context.Context, lockHash []byte, shareIndex uint64, identityKey *k1.PrivateKey, exitBlobs ...ExitBlob) error {
	lockHashStr := "0x" + hex.EncodeToString(lockHash)

	path := partialExitURL(lockHashStr)

	u, err := url.ParseRequestURI(c.baseURL)
	if err != nil {
		return errors.Wrap(err, "bad obol api url")
	}

	u.Path = path

	// sort by validator index ascending
	sort.Slice(exitBlobs, func(i, j int) bool {
		return exitBlobs[i].SignedExitMessage.Message.ValidatorIndex < exitBlobs[j].SignedExitMessage.Message.ValidatorIndex
	})

	msg := UnsignedPartialExitRequest{
		ShareIdx:     shareIndex,
		PartialExits: exitBlobs,
	}

	msgRoot, err := msg.HashTreeRoot()
	if err != nil {
		return errors.Wrap(err, "partial exits hash tree root")
	}

	signature, err := k1util.Sign(identityKey, msgRoot[:])
	if err != nil {
		return errors.Wrap(err, "k1 sign")
	}

	data, err := json.Marshal(PartialExitRequest{
		UnsignedPartialExitRequest: msg,
		Signature:                  signature,
	})
	if err != nil {
		return errors.Wrap(err, "json marshal error")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(data))
	if err != nil {
		return errors.Wrap(err, "http new post request")
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "http post error")
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusCreated {
		return errors.New("http error", z.Int("status_code", resp.StatusCode))
	}

	return nil
}

// GetFullExit gets the full exit message for a given validator public key, lock hash and share index.
func (c Client) GetFullExit(ctx context.Context, valPubkey string, lockHash []byte, shareIndex uint64, identityKey *k1.PrivateKey) (ExitBlob, error) {
	valPubkeyBytes, err := from0x(valPubkey, 48) // public key is 48 bytes long
	if err != nil {
		return ExitBlob{}, errors.Wrap(err, "validator pubkey to bytes")
	}

	path := fullExitURL(valPubkey, "0x"+hex.EncodeToString(lockHash), shareIndex)

	u, err := url.ParseRequestURI(c.baseURL)
	if err != nil {
		return ExitBlob{}, errors.Wrap(err, "bad obol api url")
	}

	u.Path = path

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return ExitBlob{}, errors.Wrap(err, "http new get request")
	}

	exitAuthData := FullExitAuthBlob{
		LockHash:        lockHash,
		ValidatorPubkey: valPubkeyBytes,
		ShareIndex:      shareIndex,
	}

	exitAuthDataRoot, err := exitAuthData.HashTreeRoot()
	if err != nil {
		return ExitBlob{}, errors.Wrap(err, "exit auth data root")
	}

	// sign the lockHash *bytes* with identity key
	lockHashSignature, err := k1util.Sign(identityKey, exitAuthDataRoot[:])
	if err != nil {
		return ExitBlob{}, errors.Wrap(err, "k1 sign")
	}

	req.Header.Set("Authorization", bearerString(lockHashSignature))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ExitBlob{}, errors.Wrap(err, "http get error")
	}

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return ExitBlob{}, ErrNoExit
		}

		return ExitBlob{}, errors.New("http error", z.Int("status_code", resp.StatusCode))
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	var er FullExitResponse
	if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
		return ExitBlob{}, errors.Wrap(err, "json unmarshal error")
	}

	// do aggregation
	rawSignatures := make(map[int]tbls.Signature)

	for sigIdx, sigStr := range er.Signatures {
		if len(sigStr) == 0 {
			// ignore, the associated share index didn't push a partial signature yet
			continue
		}

		if len(sigStr) < 2 {
			return ExitBlob{}, errors.New("signature string has invalid size", z.Int("size", len(sigStr)))
		}

		sigBytes, err := from0x(sigStr, 96) // a signature is 96 bytes long
		if err != nil {
			return ExitBlob{}, errors.Wrap(err, "partial signature unmarshal")
		}

		sig, err := tblsconv.SignatureFromBytes(sigBytes)
		if err != nil {
			return ExitBlob{}, errors.Wrap(err, "invalid partial signature")
		}

		rawSignatures[sigIdx+1] = sig
	}

	fullSig, err := tbls.ThresholdAggregate(rawSignatures)
	if err != nil {
		return ExitBlob{}, errors.Wrap(err, "partial signatures threshold aggregate")
	}

	epochUint64, err := strconv.ParseUint(er.Epoch, 10, 64)
	if err != nil {
		return ExitBlob{}, errors.Wrap(err, "epoch parsing")
	}

	return ExitBlob{
		PublicKey: valPubkey,
		SignedExitMessage: eth2p0.SignedVoluntaryExit{
			Message: &eth2p0.VoluntaryExit{
				Epoch:          eth2p0.Epoch(epochUint64),
				ValidatorIndex: er.ValidatorIndex,
			},
			Signature: eth2p0.BLSSignature(fullSig),
		},
	}, nil
}
