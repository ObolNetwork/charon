// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapimock

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/gorilla/mux"

	"github.com/obolnetwork/charon/app/obolapi"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util/registration"
	"github.com/obolnetwork/charon/tbls"
)

const (
	submitPartialFeeRecipientTmpl = "/fee_recipient/partial/" + lockHashPath + "/" + shareIndexPath
	fetchFeeRecipientTmpl         = "/fee_recipient/" + lockHashPath
)

// feeRecipientPartial represents a single partial builder registration.
type feeRecipientPartial struct {
	ShareIdx  int
	Message   *eth2v1.ValidatorRegistration
	Signature []byte
}

// feeRecipientBlob holds partial registrations for a validator, grouped by message identity.
// The outer key is a message hash (fee_recipient|timestamp|gas_limit), the inner key is share index.
type feeRecipientBlob struct {
	groups map[string]map[int]feeRecipientPartial
}

// msgKey returns a stable string key identifying a registration message's content.
func msgKey(msg *eth2v1.ValidatorRegistration) string {
	return fmt.Sprintf("%s|%d|%d", msg.FeeRecipient.String(), msg.Timestamp.Unix(), msg.GasLimit)
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

	if shareIndex <= 0 || shareIndex > len(lock.Operators) {
		writeErr(writer, http.StatusBadRequest, "invalid share index")
		return
	}

	for _, partialReg := range data.PartialRegistrations {
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

		key := lockHash + "/" + validatorPubkeyHex

		existing, ok := ts.partialFeeRecipients[key]
		if !ok {
			existing = feeRecipientBlob{
				groups: make(map[string]map[int]feeRecipientPartial),
			}
		}

		mk := msgKey(partialReg.Message)

		group, ok := existing.groups[mk]
		if !ok {
			group = make(map[int]feeRecipientPartial)
		}

		group[shareIndex] = feeRecipientPartial{
			ShareIdx:  shareIndex,
			Message:   partialReg.Message,
			Signature: partialReg.Signature[:],
		}

		existing.groups[mk] = group
		ts.partialFeeRecipients[key] = existing
	}

	writer.WriteHeader(http.StatusOK)
}

func (ts *testServer) HandlePostFeeRecipientFetch(writer http.ResponseWriter, request *http.Request) {
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

	var fetchReq obolapi.FeeRecipientFetchRequest
	if err := json.NewDecoder(request.Body).Decode(&fetchReq); err != nil {
		writeErr(writer, http.StatusBadRequest, "invalid body")
		return
	}

	pubkeyFilter := make(map[string]bool)
	for _, pk := range fetchReq.Pubkeys {
		pubkeyFilter[strings.ToLower(strings.TrimPrefix(pk, "0x"))] = true
	}

	type validatorInfo struct {
		pubkeyHex string
		validator *cluster.DistValidator
	}

	var targets []validatorInfo

	for i := range lock.Validators {
		pkHex := strings.TrimPrefix(lock.Validators[i].PublicKeyHex(), "0x")
		if len(pubkeyFilter) > 0 && !pubkeyFilter[strings.ToLower(pkHex)] {
			continue
		}

		targets = append(targets, validatorInfo{
			pubkeyHex: pkHex,
			validator: &lock.Validators[i],
		})
	}

	var validators []obolapi.FeeRecipientValidator

	for _, t := range targets {
		key := lockHash + "/" + t.pubkeyHex
		existing, hasPartials := ts.partialFeeRecipients[key]

		if !hasPartials || len(existing.groups) == 0 {
			continue // omit validators with no registration data
		}

		var builderRegs []obolapi.FeeRecipientBuilderRegistration

		var (
			latestQuorum     *obolapi.FeeRecipientBuilderRegistration
			latestIncomplete *obolapi.FeeRecipientBuilderRegistration
		)

		for _, group := range existing.groups {
			// Pick a representative message from the group (all entries share the same message).
			var msg *eth2v1.ValidatorRegistration
			for _, p := range group {
				msg = p.Message
				break
			}

			// Build partial_signatures list; apply dropOnePsig if set.
			partials := make([]feeRecipientPartial, 0, len(group))
			for _, p := range group {
				partials = append(partials, p)
			}

			if ts.dropOnePsig && len(partials) > 0 {
				partials = partials[:len(partials)-1]
			}

			partialSigs := make([]obolapi.FeeRecipientPartialSig, 0, len(partials))
			for _, p := range partials {
				var sig tbls.Signature
				copy(sig[:], p.Signature)

				partialSigs = append(partialSigs, obolapi.FeeRecipientPartialSig{
					ShareIndex: p.ShareIdx,
					Signature:  sig,
				})
			}

			quorum := len(group) >= lock.Threshold

			reg := obolapi.FeeRecipientBuilderRegistration{
				Message:           msg,
				PartialSignatures: partialSigs,
				Quorum:            quorum,
			}

			if quorum {
				if latestQuorum == nil || msg.Timestamp.After(latestQuorum.Message.Timestamp) {
					regCopy := reg
					latestQuorum = &regCopy
				}
			} else {
				if latestIncomplete == nil || msg.Timestamp.After(latestIncomplete.Message.Timestamp) {
					regCopy := reg
					latestIncomplete = &regCopy
				}
			}
		}

		// Return at most one quorum group and one incomplete group per spec.
		if latestQuorum != nil {
			builderRegs = append(builderRegs, *latestQuorum)
		}

		if latestIncomplete != nil {
			builderRegs = append(builderRegs, *latestIncomplete)
		}

		validators = append(validators, obolapi.FeeRecipientValidator{
			Pubkey:               t.pubkeyHex, // no 0x prefix per spec
			BuilderRegistrations: builderRegs,
		})
	}

	resp := obolapi.FeeRecipientFetchResponse{
		Validators: validators,
	}

	if err := json.NewEncoder(writer).Encode(resp); err != nil {
		writeErr(writer, http.StatusInternalServerError, "cannot encode response")
	}
}
