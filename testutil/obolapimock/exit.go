// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapimock

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/gorilla/mux"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/obolapi"
	"github.com/obolnetwork/charon/eth2util/signing"
	"github.com/obolnetwork/charon/tbls"
)

const (
	expPartialExits = "/exp/partial_exits"
	expExit         = "/exp/exit"

	submitPartialExitTmpl = "/" + lockHashPath
	deletePartialExitTmpl = "/" + lockHashPath + "/" + shareIndexPath + "/" + valPubkeyPath
	fetchFullExitTmpl     = "/" + lockHashPath + "/" + shareIndexPath + "/" + valPubkeyPath
)

// exitBlob represents an Obol API ExitBlob with its share index.
type exitBlob struct {
	obolapi.ExitBlob

	shareIdx uint64
}

func (ts *testServer) HandleSubmitPartialExit(writer http.ResponseWriter, request *http.Request) {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	vars := mux.Vars(request)

	var data obolapi.PartialExitRequest

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

	// check that data has been signed with ShareIdx-th identity key
	if data.ShareIdx == 0 || data.ShareIdx > uint64(len(lock.Operators)) {
		writeErr(writer, http.StatusBadRequest, "invalid share index")
		return
	}

	signedExitsRoot, err := data.HashTreeRoot()
	if err != nil {
		writeErr(writer, http.StatusInternalServerError, "cannot calculate hash tree root for provided signed exits")
		return
	}

	if err := verifyIdentitySignature(lock.Operators[data.ShareIdx-1], data.Signature, signedExitsRoot[:]); err != nil {
		writeErr(writer, http.StatusBadRequest, "cannot verify signature: "+err.Error())
		return
	}

	for _, exit := range data.PartialExits {
		var (
			validatorFound bool
			partialPubkey  []byte
		)

		for _, lockVal := range lock.Validators {
			valHex := lockVal.PublicKeyHex()
			if strings.EqualFold(exit.PublicKey, valHex) {
				partialPubkey = lockVal.PubShares[data.ShareIdx-1]
				validatorFound = true

				break
			}
		}

		if !validatorFound {
			writeErr(writer, http.StatusBadRequest, fmt.Sprintf("could not find validator %s in lock file", exit.PublicKey))
			return
		}

		exitSigData, err := sigDataForExit(request.Context(), *exit.SignedExitMessage.Message, ts.beacon, exit.SignedExitMessage.Message.Epoch)
		if err != nil {
			writeErr(writer, http.StatusInternalServerError, err.Error())
			return
		}

		if err := tbls.Verify(tbls.PublicKey(partialPubkey), exitSigData[:], tbls.Signature(exit.SignedExitMessage.Signature)); err != nil {
			writeErr(writer, http.StatusBadRequest, err.Error())
			return
		}

		// check that the last partial exit's data is the same as the new one
		if len(ts.partialExits[exit.PublicKey]) > 0 && !ts.partialExitsMatch(exit) {
			writeErr(writer, http.StatusBadRequest, "wrong partial exit for the selected validator")
			return
		}

		if len(ts.partialExits[exit.PublicKey])+1 > len(lock.Operators) { // we're already at threshold, ignore
			continue
		}

		ts.partialExits[exit.PublicKey] = append(ts.partialExits[exit.PublicKey], exitBlob{
			ExitBlob: exit,
			shareIdx: data.ShareIdx,
		})
	}

	writer.WriteHeader(http.StatusCreated)
}

func (ts *testServer) HandleGetFullExit(writer http.ResponseWriter, request *http.Request) {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	authToken, ok := request.Context().Value(tokenContextKey).([]byte)
	if !ok {
		log.Error(request.Context(), "Internal error: context is missing authorization token", nil)
		return
	}

	vars := mux.Vars(request)

	valPubkey := vars[cleanTmpl(valPubkeyPath)]
	lockHash := vars[cleanTmpl(lockHashPath)]
	shareIndexStr := vars[cleanTmpl(shareIndexPath)]

	shareIndex, err := strconv.ParseUint(shareIndexStr, 10, 64)
	if err != nil {
		writeErr(writer, http.StatusBadRequest, "malformed share index")
		return
	}

	valPubkeyBytes, err := from0x(valPubkey, 48)
	if err != nil {
		writeErr(writer, http.StatusBadRequest, "invalid public key")
		return
	}

	lockHashBytes, err := from0x(lockHash, 32)
	if err != nil {
		writeErr(writer, http.StatusBadRequest, "invalid lock hash")
		return
	}

	lock, ok := ts.lockFiles[lockHash]
	if !ok {
		writeErr(writer, http.StatusNotFound, "lock not found")
		return
	}

	partialExits, ok := ts.partialExits[valPubkey]
	if !ok {
		writeErr(writer, http.StatusNotFound, "validator not found")
		return
	}

	if len(partialExits) < lock.Threshold {
		writeErr(writer, http.StatusUnauthorized, "not enough partial exits stored")
		return
	}

	// check that data has been signed with ShareIdx-th identity key
	if shareIndex == 0 || shareIndex > uint64(len(lock.Operators)) {
		writeErr(writer, http.StatusBadRequest, "invalid share index")
		return
	}

	exitAuthData := obolapi.FullExitAuthBlob{
		LockHash:        lockHashBytes,
		ValidatorPubkey: valPubkeyBytes,
		ShareIndex:      shareIndex,
	}

	exitAuthDataRoot, err := exitAuthData.HashTreeRoot()
	if err != nil {
		writeErr(writer, http.StatusInternalServerError, "cannot calculate exit auth data root")
		return
	}

	if err := verifyIdentitySignature(lock.Operators[shareIndex-1], authToken, exitAuthDataRoot[:]); err != nil {
		writeErr(writer, http.StatusBadRequest, "cannot verify signature: "+err.Error())
		return
	}

	var ret obolapi.FullExitResponse

	// order partial exits by share index
	sort.Slice(partialExits, func(i, j int) bool {
		return partialExits[i].shareIdx < partialExits[j].shareIdx
	})

	for _, pExit := range partialExits {
		ret.Signatures = append(ret.Signatures, "0x"+hex.EncodeToString(pExit.SignedExitMessage.Signature[:]))
		ret.Epoch = strconv.FormatUint(uint64(pExit.SignedExitMessage.Message.Epoch), 10)
		ret.ValidatorIndex = pExit.SignedExitMessage.Message.ValidatorIndex
	}

	if ts.dropOnePsig {
		ret.Signatures[0] = "" // blank out the first signature, as if the API didn't receive the partial exit for it
	}

	if err := json.NewEncoder(writer).Encode(ret); err != nil {
		writeErr(writer, http.StatusInternalServerError, errors.Wrap(err, "marshal exit message").Error())
		return
	}
}

func (ts *testServer) HandleDeletePartialExit(writer http.ResponseWriter, request *http.Request) {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	authToken, ok := request.Context().Value(tokenContextKey).([]byte)
	if !ok {
		log.Error(request.Context(), "Internal error: context is missing authorization token", nil)
		return
	}

	vars := mux.Vars(request)

	valPubkey := vars[cleanTmpl(valPubkeyPath)]
	lockHash := vars[cleanTmpl(lockHashPath)]
	shareIndexStr := vars[cleanTmpl(shareIndexPath)]

	shareIndex, err := strconv.ParseUint(shareIndexStr, 10, 64)
	if err != nil {
		writeErr(writer, http.StatusBadRequest, "malformed share index")
		return
	}

	valPubkeyBytes, err := from0x(valPubkey, 48)
	if err != nil {
		writeErr(writer, http.StatusBadRequest, "invalid public key")
		return
	}

	lockHashBytes, err := from0x(lockHash, 32)
	if err != nil {
		writeErr(writer, http.StatusBadRequest, "invalid lock hash")
		return
	}

	lock, ok := ts.lockFiles[lockHash]
	if !ok {
		writeErr(writer, http.StatusNotFound, "lock not found")
		return
	}

	partialExits, ok := ts.partialExits[valPubkey]
	if !ok {
		writeErr(writer, http.StatusNotFound, "validator not found")
		return
	}

	// check that data has been signed with ShareIdx-th identity key
	if shareIndex == 0 || shareIndex > uint64(len(lock.Operators)) {
		writeErr(writer, http.StatusBadRequest, "invalid share index")
		return
	}

	exitAuthData := obolapi.FullExitAuthBlob{
		LockHash:        lockHashBytes,
		ValidatorPubkey: valPubkeyBytes,
		ShareIndex:      shareIndex,
	}

	exitAuthDataRoot, err := exitAuthData.HashTreeRoot()
	if err != nil {
		writeErr(writer, http.StatusInternalServerError, "cannot calculate exit auth data root")
		return
	}

	if err := verifyIdentitySignature(lock.Operators[shareIndex-1], authToken, exitAuthDataRoot[:]); err != nil {
		writeErr(writer, http.StatusBadRequest, "cannot verify signature: "+err.Error())
		return
	}

	found := false

	for idx, pExit := range partialExits {
		if pExit.shareIdx == shareIndex {
			partialExits = slices.Delete(partialExits, idx, idx+1)
			found = true

			break
		}
	}

	if !found {
		writeErr(writer, http.StatusNotFound, "share index not found for validator")
		return
	}

	ts.partialExits[valPubkey] = partialExits
}

func (ts *testServer) partialExitsMatch(newOne obolapi.ExitBlob) bool {
	// get the last one
	exitsLen := len(ts.partialExits[newOne.PublicKey])
	last := ts.partialExits[newOne.PublicKey][exitsLen-1]

	return *last.SignedExitMessage.Message == *newOne.SignedExitMessage.Message
}

// sigDataForExit returns the hash tree root for the given exit message, at the given exit epoch.
func sigDataForExit(ctx context.Context, exit eth2p0.VoluntaryExit, eth2Cl eth2wrap.Client, exitEpoch eth2p0.Epoch) ([32]byte, error) {
	sigRoot, err := exit.HashTreeRoot()
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "exit hash tree root")
	}

	domain, err := signing.GetDomain(ctx, eth2Cl, signing.DomainExit, exitEpoch)
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "get domain")
	}

	sigData, err := (&eth2p0.SigningData{ObjectRoot: sigRoot, Domain: domain}).HashTreeRoot()
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "signing data hash tree root")
	}

	return sigData, nil
}
