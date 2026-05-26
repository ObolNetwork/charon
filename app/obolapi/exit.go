// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util/signing"
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

var ErrNoValue = errors.New("no value for the given validator public key")

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
		return errors.Wrap(err, "parse Obol API URL")
	}

	u.Path = path

	// sort by validator index ascending
	slices.SortFunc(exitBlobs, func(i, j ExitBlob) int {
		if i.SignedExitMessage.Message.ValidatorIndex < j.SignedExitMessage.Message.ValidatorIndex {
			return -1
		}

		if i.SignedExitMessage.Message.ValidatorIndex > j.SignedExitMessage.Message.ValidatorIndex {
			return 1
		}

		return 0
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
		return errors.Wrap(err, "marshal PartialExitRequest to JSON")
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
// partialPubKeys is the validator's ordered list of public-key shares (lock.Validators[i].PubShares).
// eth2Cl is used to compute the voluntary-exit domain so each returned partial signature can be
// BLS-verified against its pub share to recover the true share index — guarding against positional
// ambiguity in the API response.
// It respects the timeout specified in the Client instance.
func (c Client) GetFullExit(ctx context.Context, valPubkey string, lockHash []byte, shareIndex uint64, identityKey *k1.PrivateKey, partialPubKeys [][]byte, eth2Cl eth2wrap.Client) (ExitBlob, error) {
	valPubkeyBytes, err := from0x(valPubkey, 48) // public key is 48 bytes long
	if err != nil {
		return ExitBlob{}, errors.Wrap(err, "validator pubkey to bytes")
	}

	path := fetchFullExitURL(valPubkey, "0x"+hex.EncodeToString(lockHash), shareIndex)

	u, err := url.ParseRequestURI(c.baseURL)
	if err != nil {
		return ExitBlob{}, errors.Wrap(err, "parse Obol API URL")
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
		return ExitBlob{}, errors.Wrap(err, "unmarshal FullExitResponse from JSON")
	}

	epochUint64, err := strconv.ParseUint(er.Epoch, 10, 64)
	if err != nil {
		return ExitBlob{}, errors.Wrap(err, "parse epoch")
	}

	exitEpoch := eth2p0.Epoch(epochUint64)

	exitMsg := eth2p0.VoluntaryExit{Epoch: exitEpoch, ValidatorIndex: er.ValidatorIndex}

	msgRoot, err := exitMsg.HashTreeRoot()
	if err != nil {
		return ExitBlob{}, errors.Wrap(err, "voluntary exit hash tree root")
	}

	domain, err := signing.GetDomain(ctx, eth2Cl, signing.DomainExit, exitEpoch)
	if err != nil {
		return ExitBlob{}, errors.Wrap(err, "get voluntary exit domain")
	}

	sigData, err := (&eth2p0.SigningData{ObjectRoot: msgRoot, Domain: domain}).HashTreeRoot()
	if err != nil {
		return ExitBlob{}, errors.Wrap(err, "signing data hash tree root")
	}

	// Resolve each partial signature's true share index by BLS-verifying against each pub share.
	// The API's positional ordering is not trusted: if some shares are missing the response may be
	// compact, and naively using slice position would assign wrong x-coordinates to ThresholdAggregate.
	rawSignatures := make(map[int]tbls.Signature)

	for _, sigStr := range er.Signatures {
		if sigStr == "" {
			// ignore, the associated share index didn't push a partial signature yet
			continue
		}

		sigBytes, err := from0x(sigStr, 96) // a signature is 96 bytes long
		if err != nil {
			return ExitBlob{}, errors.Wrap(err, "partial signature unmarshal")
		}

		sig, err := tblsconv.SignatureFromBytes(sigBytes)
		if err != nil {
			return ExitBlob{}, errors.Wrap(err, "invalid partial signature")
		}

		shareIdx := 0

		for i, pubShare := range partialPubKeys {
			pk, err := tblsconv.PubkeyFromBytes(pubShare)
			if err != nil {
				return ExitBlob{}, errors.Wrap(err, "invalid public key share", z.Int("share_index", i+1))
			}

			if err := tbls.Verify(pk, sigData[:], sig); err == nil {
				shareIdx = i + 1
				break
			}
		}

		if shareIdx == 0 {
			return ExitBlob{}, errors.New("partial signature did not verify against any validator public share")
		}

		if _, dup := rawSignatures[shareIdx]; dup {
			return ExitBlob{}, errors.New("duplicate partial signature for share index", z.Int("share_index", shareIdx))
		}

		rawSignatures[shareIdx] = sig
	}

	fullSig, err := tbls.ThresholdAggregate(rawSignatures)
	if err != nil {
		return ExitBlob{}, errors.Wrap(err, "threshold aggregate partial signatures")
	}

	valPubKey, err := tblsconv.PubkeyFromBytes(valPubkeyBytes)
	if err != nil {
		return ExitBlob{}, errors.Wrap(err, "invalid validator public key")
	}

	if err := tbls.Verify(valPubKey, sigData[:], fullSig); err != nil {
		return ExitBlob{}, errors.Wrap(err, "aggregated exit signature failed BLS verification", z.Str("validator_pubkey", valPubkey))
	}

	return ExitBlob{
		PublicKey: valPubkey,
		SignedExitMessage: eth2p0.SignedVoluntaryExit{
			Message: &eth2p0.VoluntaryExit{
				Epoch:          exitEpoch,
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

	u, err := url.ParseRequestURI(c.baseURL)
	if err != nil {
		return errors.Wrap(err, "parse Obol API URL")
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
