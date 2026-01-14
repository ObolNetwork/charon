// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapimock

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync"

	"github.com/gorilla/mux"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util/enr"
)

const (
	lockHashPath   = "{lock_hash}"
	valPubkeyPath  = "{validator_pubkey}"
	shareIndexPath = "{share_index}"
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

// testServer is a mock implementation (but that actually does cryptography) of the Obol API side,
// which will handle storing and recollecting partial signatures.
type testServer struct {
	// for convenience, this thing handles one request at a time
	lock sync.Mutex

	// store the partial exits by the validator pubkey
	partialExits map[string][]exitBlob

	// store the partial deposits by the validator pubkey
	partialDeposits map[string]depositBlob

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

// MockServer returns an Obol API mock test server.
// It returns a http.Handler to be served over HTTP, and a function to add cluster lock files to its database.
func MockServer(dropOnePsig bool, beacon eth2wrap.Client) (http.Handler, func(lock cluster.Lock)) {
	ts := testServer{
		lock:            sync.Mutex{},
		partialExits:    map[string][]exitBlob{},
		partialDeposits: map[string]depositBlob{},
		lockFiles:       map[string]cluster.Lock{},
		dropOnePsig:     dropOnePsig,
		beacon:          beacon,
	}

	router := mux.NewRouter()

	getFull := router.PathPrefix(expExit).Subrouter()
	getFull.Use(authMiddleware)
	getFull.HandleFunc(fetchFullExitTmpl, ts.HandleGetFullExit).Methods(http.MethodGet)

	deletePartial := router.PathPrefix(expPartialExits).Subrouter()
	deletePartial.Use(authMiddleware)
	deletePartial.HandleFunc(deletePartialExitTmpl, ts.HandleDeletePartialExit).Methods(http.MethodDelete)

	router.HandleFunc(expPartialExits+submitPartialExitTmpl, ts.HandleSubmitPartialExit).Methods(http.MethodPost)

	router.HandleFunc(submitPartialDepositTmpl, ts.HandleSubmitPartialDeposit).Methods(http.MethodPost)
	router.HandleFunc(fetchFullDepositTmpl, ts.HandleGetFullDeposit).Methods(http.MethodGet)

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
