// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	lockHashPath   = "{lock_hash}"
	valPubkeyPath  = "{validator_pubkey}"
	shareIndexPath = "{share_index}"

	submitPartialExitTmpl = "/exp/partial_exits/" + lockHashPath
	deletePartialExitTmpl = "/exp/partial_exits/" + lockHashPath + "/" + shareIndexPath + "/" + valPubkeyPath
	fetchFullExitTmpl     = "/exp/exit/" + lockHashPath + "/" + shareIndexPath + "/" + valPubkeyPath
)

var ErrNoExit = errors.New("no exit for the given validator public key")

// bearerString returns the bearer token authentication string given a token.
func bearerString(data []byte) string {
	return fmt.Sprintf("Bearer %#x", data)
}

// submitPartialExitURL returns the partial exit Obol API URL for a given lock hash.
func submitPartialExitURL(lockHash string) string {
	return strings.NewReplacer(
		lockHashPath,
		lockHash,
	).Replace(submitPartialExitTmpl)
}

// deletePartialExitURL returns the full exit Obol API URL for a given validator public key.
func deletePartialExitURL(valPubkey, lockHash string, shareIndex uint64) string {
	return strings.NewReplacer(
		valPubkeyPath,
		valPubkey,
		lockHashPath,
		lockHash,
		shareIndexPath,
		strconv.FormatUint(shareIndex, 10),
	).Replace(deletePartialExitTmpl)
}

// fetchFullExitURL returns the full exit Obol API URL for a given validator public key.
func fetchFullExitURL(valPubkey, lockHash string, shareIndex uint64) string {
	return strings.NewReplacer(
		valPubkeyPath,
		valPubkey,
		lockHashPath,
		lockHash,
		shareIndexPath,
		strconv.FormatUint(shareIndex, 10),
	).Replace(fetchFullExitTmpl)
}

// PostPartialExits POSTs the set of msg's to the Obol API, for a given lock hash.
// It respects the timeout specified in the Client instance.
func (c Client) PostPartialExits(ctx context.Context, lockHash []byte, shareIndex uint64, identityKey *k1.PrivateKey, exitBlobs ...ExitBlob) error {
	lockHashStr := "0x" + hex.EncodeToString(lockHash)

	path := submitPartialExitURL(lockHashStr)

	u, err := url.ParseRequestURI(c.baseURL)
	if err != nil {
		return errors.Wrap(err, "bad Obol API url")
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

	ctx, cancel := context.WithTimeout(ctx, c.reqTimeout)
	defer cancel()

	err = httpPost(ctx, u, data, nil)
	if err != nil {
		return errors.Wrap(err, "http Obol API POST request")
	}

	return nil
}

// GetFullExit gets the full exit message for a given validator public key, lock hash and share index.
// It respects the timeout specified in the Client instance.
func (c Client) GetFullExit(ctx context.Context, valPubkey string, lockHash []byte, shareIndex uint64, identityKey *k1.PrivateKey) (ExitBlob, error) {
	valPubkeyBytes, err := from0x(valPubkey, 48) // public key is 48 bytes long
	if err != nil {
		return ExitBlob{}, errors.Wrap(err, "validator pubkey to bytes")
	}

	path := fetchFullExitURL(valPubkey, "0x"+hex.EncodeToString(lockHash), shareIndex)

	u, err := url.ParseRequestURI(c.baseURL)
	if err != nil {
		return ExitBlob{}, errors.Wrap(err, "bad Obol API url")
	}

	u.Path = path

	ctx, cancel := context.WithTimeout(ctx, c.reqTimeout)
	defer cancel()

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

	respBody, err := httpGet(ctx, u, map[string]string{"Authorization": bearerString(lockHashSignature)})
	if err != nil {
		return ExitBlob{}, errors.Wrap(err, "http Obol API GET request")
	}

	defer respBody.Close()

	var er FullExitResponse
	if err := json.NewDecoder(respBody).Decode(&er); err != nil {
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

// DeletePartialExit deletes the partial exit message for a given validator public key, lock hash and share index.
// It respects the timeout specified in the Client instance.
func (c Client) DeletePartialExit(ctx context.Context, valPubkey string, lockHash []byte, shareIndex uint64, identityKey *k1.PrivateKey) error {
	valPubkeyBytes, err := from0x(valPubkey, 48) // public key is 48 bytes long
	if err != nil {
		return errors.Wrap(err, "validator pubkey to bytes")
	}

	path := deletePartialExitURL(valPubkey, "0x"+hex.EncodeToString(lockHash), shareIndex)

	fmt.Println("path")
	fmt.Println(path)
	u, err := url.ParseRequestURI(c.baseURL)
	if err != nil {
		return errors.Wrap(err, "bad Obol API url")
	}

	u.Path = path

	ctx, cancel := context.WithTimeout(ctx, c.reqTimeout)
	defer cancel()

	exitAuthData := FullExitAuthBlob{
		LockHash:        lockHash,
		ValidatorPubkey: valPubkeyBytes,
		ShareIndex:      shareIndex,
	}

	exitAuthDataRoot, err := exitAuthData.HashTreeRoot()
	if err != nil {
		return errors.Wrap(err, "exit auth data root")
	}

	// sign the lockHash *bytes* with identity key
	lockHashSignature, err := k1util.Sign(identityKey, exitAuthDataRoot[:])
	if err != nil {
		return errors.Wrap(err, "k1 sign")
	}

	err = httpDelete(ctx, u, map[string]string{"Authorization": bearerString(lockHashSignature)})
	if err != nil {
		return errors.Wrap(err, "http Obol API DELETE request")
	}

	return nil
}
