// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapimock

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/gorilla/mux"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/obolapi"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/eth2util/signing"
	"github.com/obolnetwork/charon/tbls"
)

const (
	lockHashPath     = "{lock_hash}"
	valPubkeyPath    = "{validator_pubkey}"
	shareIndexPath   = "{share_index}"
	fullExitBaseTmpl = "/exp/exit"
	fullExitEndTmp   = "/" + lockHashPath + "/" + shareIndexPath + "/" + valPubkeyPath

	partialExitTmpl = "/exp/partial_exits/" + lockHashPath
)

type contextKey string

const (
	tokenContextKey contextKey = "token"
)

type tsError struct {
	Message string
}

func writeErr(wr http.ResponseWriter, status int, msg string) {
	resp, err := json.Marshal(tsError{Message: msg})
	if err != nil {
		panic(err) // never happens
	}

	wr.WriteHeader(status)
	_, _ = wr.Write(resp)
}

// exitBlob represents an Obol API ExitBlob with its share index.
type exitBlob struct {
	obolapi.ExitBlob
	shareIdx uint64
}

// testServer is a mock implementation (but that actually does cryptography) of the Obol API side,
// which will handle storing and recollecting partial signatures.
type testServer struct {
	// for convenience, this thing handles one request at a time
	lock sync.Mutex

	// store the partial exits by the validator pubkey
	partialExits map[string][]exitBlob

	// store the lock file by its lock hash
	lockFiles map[string]cluster.Lock

	// drop one partial signature when returning the full set
	dropOnePsig bool

	// Beacon node client, needed to verify exits.
	beacon eth2wrap.Client
}

// addLockFiles adds a set of lock files to ts.
func (ts *testServer) addLockFiles(lock cluster.Lock) {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	ts.lockFiles["0x"+hex.EncodeToString(lock.LockHash)] = lock
}

func (ts *testServer) HandlePartialExit(writer http.ResponseWriter, request *http.Request) {
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
		var validatorFound bool
		var partialPubkey []byte

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

func (ts *testServer) HandleFullExit(writer http.ResponseWriter, request *http.Request) {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	authToken, ok := request.Context().Value(tokenContextKey).([]byte)
	if !ok {
		log.Error(request.Context(), "received context without token, that's impossible!", nil)
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
		writeErr(writer, http.StatusInternalServerError, errors.Wrap(err, "cannot marshal exit message").Error())
		return
	}
}

func (ts *testServer) partialExitsMatch(newOne obolapi.ExitBlob) bool {
	// get the last one
	exitsLen := len(ts.partialExits[newOne.PublicKey])
	last := ts.partialExits[newOne.PublicKey][exitsLen-1]

	return *last.SignedExitMessage.Message == *newOne.SignedExitMessage.Message
}

// verifyIdentitySignature verifies that sig for hash has been created with operator's identity key.
func verifyIdentitySignature(operator cluster.Operator, sig, hash []byte) error {
	opENR, err := enr.Parse(operator.ENR)
	if err != nil {
		return errors.Wrap(err, "operator enr")
	}

	verified, err := k1util.Verify65(opENR.PubKey, hash, sig)
	if err != nil {
		return errors.Wrap(err, "k1 signature verify")
	}

	if !verified {
		return errors.New("identity signature verification failed")
	}

	return nil
}

// cleanTmpl cleans tmpl from '{' and '}', used in path definitions.
func cleanTmpl(tmpl string) string {
	return strings.NewReplacer(
		"{",
		"",
		"}",
		"").Replace(tmpl)
}

// MockServer returns a obol API mock test server.
// It returns a http.Handler to be served over HTTP, and a function to add cluster lock files to its database.
func MockServer(dropOnePsig bool, beacon eth2wrap.Client) (http.Handler, func(lock cluster.Lock)) {
	ts := testServer{
		lock:         sync.Mutex{},
		partialExits: map[string][]exitBlob{},
		lockFiles:    map[string]cluster.Lock{},
		dropOnePsig:  dropOnePsig,
		beacon:       beacon,
	}

	router := mux.NewRouter()

	full := router.PathPrefix(fullExitBaseTmpl).Subrouter()
	full.Use(authMiddleware)
	full.HandleFunc(fullExitEndTmp, ts.HandleFullExit).Methods(http.MethodGet)

	router.HandleFunc(partialExitTmpl, ts.HandlePartialExit).Methods(http.MethodPost)

	return router, ts.addLockFiles
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer")
		bearer = strings.TrimSpace(bearer)
		if bearer == "" {
			writeErr(w, http.StatusUnauthorized, "missing authorization header")
			return
		}

		bearerBytes, err := from0x(bearer, 65)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bearer token must be hex-encoded")
			return
		}

		r = r.WithContext(context.WithValue(r.Context(), tokenContextKey, bearerBytes))

		// compare the return-value to the authMW
		next.ServeHTTP(w, r)
	})
}

// from0x decodes hex-encoded data and expects it to be exactly of len(length).
// Accepts both 0x-prefixed strings or not.
func from0x(data string, length int) ([]byte, error) {
	if data == "" {
		return nil, errors.New("empty data")
	}

	b, err := hex.DecodeString(strings.TrimPrefix(data, "0x"))
	if err != nil {
		return nil, errors.Wrap(err, "decode hex")
	} else if len(b) != length {
		return nil, errors.Wrap(err,
			"invalid hex length",
			z.Int("expect", length),
			z.Int("actual", len(b)),
		)
	}

	return b, nil
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
