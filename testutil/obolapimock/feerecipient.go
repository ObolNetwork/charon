// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapimock

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/gorilla/mux"

	"github.com/obolnetwork/charon/app/obolapi"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util/registration"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

const (
	submitPartialFeeRecipientTmpl = "/fee_recipient/partial/" + lockHashPath + "/" + shareIndexPath
	fetchFeeRecipientTmpl         = "/fee_recipient/" + lockHashPath
)

// feeRecipientPartial represents a single partial fee recipient registration.
type feeRecipientPartial struct {
	ShareIdx  int
	Message   *eth2v1.ValidatorRegistration
	Signature []byte
}

// feeRecipientBlob represents partial fee recipient registrations for a validator.
type feeRecipientBlob struct {
	partials map[int]feeRecipientPartial // keyed by share index
}

func (ts *testServer) HandleSubmitPartialFeeRecipient(writer http.ResponseWriter, request *http.Request) {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	vars := mux.Vars(request)

	var data obolapi.PartialFeeRecipientRequest

	if err := json.NewDecoder(request.Body).Decode(&data); err != nil {
		writeErr(writer, http.StatusBadRequest, "invalid body")
		return
	}

	lockHash := vars[cleanTmpl(lockHashPath)]
	if lockHash == "" {
		writeErr(writer, http.StatusBadRequest, "invalid lock hash")
		return
	}

	lock, ok := ts.lockFiles[lockHash]
	if !ok {
		writeErr(writer, http.StatusNotFound, "lock not found")
		return
	}

	shareIndexVar := vars[cleanTmpl(shareIndexPath)]
	if shareIndexVar == "" {
		writeErr(writer, http.StatusBadRequest, "invalid share index")
		return
	}

	shareIndex, err := strconv.Atoi(shareIndexVar)
	if err != nil {
		writeErr(writer, http.StatusBadRequest, "malformed share index")
		return
	}

	// check that share index is valid
	if shareIndex <= 0 || shareIndex > len(lock.Operators) {
		writeErr(writer, http.StatusBadRequest, "invalid share index")
		return
	}

	for _, partialReg := range data.PartialRegistrations {
		// Verify the partial signature using the public share.
		sigRoot, err := registration.GetMessageSigningRoot(partialReg.Message, eth2p0.Version(lock.ForkVersion))
		if err != nil {
			writeErr(writer, http.StatusInternalServerError, "cannot calculate signing root")
			return
		}

		var publicKeyShare tbls.PublicKey

		validatorPubkeyHex := hex.EncodeToString(partialReg.Message.Pubkey[:])

		for _, v := range lock.Validators {
			if strings.TrimPrefix(v.PublicKeyHex(), "0x") == validatorPubkeyHex {
				publicKeyShare, err = v.PublicShare(shareIndex - 1)
				if err != nil {
					writeErr(writer, http.StatusBadRequest, "cannot fetch public share: "+err.Error())
					return
				}

				break
			}
		}

		if len(publicKeyShare) == 0 {
			writeErr(writer, http.StatusBadRequest, "cannot find public key in lock file")
			return
		}

		if err := tbls.Verify(publicKeyShare, sigRoot[:], partialReg.Signature); err != nil {
			writeErr(writer, http.StatusBadRequest, "cannot verify signature: "+err.Error())
			return
		}

		// Store the partial registration.
		key := lockHash + "/" + validatorPubkeyHex

		existing, ok := ts.partialFeeRecipients[key]
		if !ok {
			existing = feeRecipientBlob{
				partials: make(map[int]feeRecipientPartial),
			}
		}

		existing.partials[shareIndex] = feeRecipientPartial{
			ShareIdx:  shareIndex,
			Message:   partialReg.Message,
			Signature: partialReg.Signature[:],
		}

		ts.partialFeeRecipients[key] = existing
	}

	writer.WriteHeader(http.StatusOK)
}

func (ts *testServer) HandleGetFeeRecipient(writer http.ResponseWriter, request *http.Request) {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	vars := mux.Vars(request)

	lockHash := vars[cleanTmpl(lockHashPath)]
	if lockHash == "" {
		writeErr(writer, http.StatusBadRequest, "invalid lock hash")
		return
	}

	lock, ok := ts.lockFiles[lockHash]
	if !ok {
		writeErr(writer, http.StatusNotFound, "lock not found")
		return
	}

	var (
		registrations []*eth2api.VersionedSignedValidatorRegistration
		validators    []obolapi.FeeRecipientValidatorStatus
	)

	for _, v := range lock.Validators {
		pubkeyHex := strings.TrimPrefix(v.PublicKeyHex(), "0x")
		key := lockHash + "/" + pubkeyHex

		existing, hasPartials := ts.partialFeeRecipients[key]

		partialCount := 0
		if hasPartials {
			partialCount = len(existing.partials)
		}

		status := "pending"
		if partialCount >= lock.Threshold {
			status = "complete"
		}

		validators = append(validators, obolapi.FeeRecipientValidatorStatus{
			Pubkey:       "0x" + pubkeyHex,
			Status:       status,
			PartialCount: partialCount,
			Threshold:    lock.Threshold,
		})

		if status != "complete" {
			continue
		}

		// Aggregate partial signatures server-side.
		signedReg, err := ts.aggregateFeeRecipient(lock, v, existing)
		if err != nil {
			writeErr(writer, http.StatusInternalServerError, "aggregate error: "+err.Error())
			return
		}

		registrations = append(registrations, signedReg)
	}

	resp := obolapi.FeeRecipientFetchResponse{
		Registrations: registrations,
		Validators:    validators,
	}

	if err := json.NewEncoder(writer).Encode(resp); err != nil {
		writeErr(writer, http.StatusInternalServerError, "cannot encode response")
	}
}

// aggregateFeeRecipient aggregates partial BLS signatures into a fully signed registration.
func (ts *testServer) aggregateFeeRecipient(lock cluster.Lock, v cluster.DistValidator, blob feeRecipientBlob) (*eth2api.VersionedSignedValidatorRegistration, error) {
	// Use the message from the first partial (all should have the same message).
	var msg *eth2v1.ValidatorRegistration
	for _, p := range blob.partials {
		msg = p.Message
		break
	}

	// Collect partial signatures.
	partialSigs := make(map[int]tbls.Signature)
	for _, p := range blob.partials {
		if ts.dropOnePsig && len(partialSigs) == len(blob.partials)-1 {
			continue
		}

		sig, err := tblsconv.SignatureFromBytes(p.Signature)
		if err != nil {
			return nil, err
		}

		partialSigs[p.ShareIdx] = sig
	}

	// Aggregate signatures.
	fullSig, err := tbls.ThresholdAggregate(partialSigs)
	if err != nil {
		return nil, err
	}

	// Verify aggregated signature against the group public key.
	pubkeyBytes := v.PubKey

	groupPubkey, err := tblsconv.PubkeyFromBytes(pubkeyBytes)
	if err != nil {
		return nil, err
	}

	sigRoot, err := registration.GetMessageSigningRoot(msg, eth2p0.Version(lock.ForkVersion))
	if err != nil {
		return nil, err
	}

	if err := tbls.Verify(groupPubkey, sigRoot[:], fullSig); err != nil {
		return nil, err
	}

	return &eth2api.VersionedSignedValidatorRegistration{
		Version: eth2spec.BuilderVersionV1,
		V1: &eth2v1.SignedValidatorRegistration{
			Message:   msg,
			Signature: eth2p0.BLSSignature(fullSig),
		},
	}, nil
}
