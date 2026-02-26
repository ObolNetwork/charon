// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapimock

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/gorilla/mux"

	"github.com/obolnetwork/charon/app/obolapi"
	"github.com/obolnetwork/charon/eth2util/registration"
	"github.com/obolnetwork/charon/tbls"
)

const (
	submitPartialFeeRecipientTmpl = "/fee_recipient/partial/" + lockHashPath + "/" + shareIndexPath
	fetchPartialFeeRecipientTmpl  = "/fee_recipient/" + lockHashPath + "/" + valPubkeyPath
)

// feeRecipientBlob represents partial fee recipient registrations for a validator.
type feeRecipientBlob struct {
	partials map[int]obolapi.PartialFeeRecipientResponsePartial // keyed by share index
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

	shareIndex, err := strconv.ParseUint(shareIndexVar, 10, 64)
	if err != nil {
		writeErr(writer, http.StatusBadRequest, "malformed share index")
		return
	}

	// check that share index is valid
	if shareIndex == 0 || shareIndex > uint64(len(lock.Operators)) {
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
				publicKeyShare, err = v.PublicShare(int(shareIndex) - 1)
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
				partials: make(map[int]obolapi.PartialFeeRecipientResponsePartial),
			}
		}

		existing.partials[int(shareIndex)] = obolapi.PartialFeeRecipientResponsePartial{
			ShareIdx:  int(shareIndex),
			Message:   partialReg.Message,
			Signature: partialReg.Signature[:],
		}

		ts.partialFeeRecipients[key] = existing
	}

	writer.WriteHeader(http.StatusOK)
}

func (ts *testServer) HandleGetPartialFeeRecipient(writer http.ResponseWriter, request *http.Request) {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	vars := mux.Vars(request)

	lockHash := vars[cleanTmpl(lockHashPath)]
	if lockHash == "" {
		writeErr(writer, http.StatusBadRequest, "invalid lock hash")
		return
	}

	_, ok := ts.lockFiles[lockHash]
	if !ok {
		writeErr(writer, http.StatusNotFound, "lock not found")
		return
	}

	valPubkey := vars[cleanTmpl(valPubkeyPath)]
	if valPubkey == "" {
		writeErr(writer, http.StatusBadRequest, "invalid validator pubkey")
		return
	}

	// Normalize pubkey (remove 0x prefix for storage key lookup).
	valPubkeyNormalized := strings.TrimPrefix(valPubkey, "0x")

	key := lockHash + "/" + valPubkeyNormalized

	existing, ok := ts.partialFeeRecipients[key]
	if !ok {
		writeErr(writer, http.StatusNotFound, "no partial registrations found")
		return
	}

	resp := obolapi.PartialFeeRecipientResponse{
		Partials: make([]obolapi.PartialFeeRecipientResponsePartial, 0, len(existing.partials)),
	}

	for i, partial := range existing.partials {
		// Optionally drop one partial signature for testing threshold behavior.
		if ts.dropOnePsig && i == len(existing.partials)-1 {
			continue
		}

		resp.Partials = append(resp.Partials, partial)
	}

	if err := json.NewEncoder(writer).Encode(resp); err != nil {
		writeErr(writer, http.StatusInternalServerError, "cannot encode response")
		return
	}
}
