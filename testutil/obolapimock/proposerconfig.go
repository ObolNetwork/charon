// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapimock

import (
	"bytes"
	"io"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"

	"github.com/obolnetwork/charon/app/obolapi"
	"github.com/obolnetwork/charon/cluster/proposerconfig"
)

const (
	proposerConfigPrefix      = "/proposer_config"
	publishProposerConfigTmpl = proposerConfigPrefix + "/" + lockHashPath
	fetchProposerConfigTmpl   = "/" + lockHashPath + "/" + shareIndexPath
)

// HandlePublishProposerConfig stores a signed proposer config revision: 201 for a new one, 200 if already stored,
// 409 for a revision lower than the latest or another document of a stored revision.
func (ts *testServer) HandlePublishProposerConfig(writer http.ResponseWriter, request *http.Request) {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	lockHash := mux.Vars(request)[cleanTmpl(lockHashPath)]

	lock, ok := ts.lockFiles[lockHash]
	if !ok {
		writeErr(writer, http.StatusNotFound, "lock not found")
		return
	}

	body, err := io.ReadAll(request.Body)
	if err != nil {
		writeErr(writer, http.StatusBadRequest, "cannot read body")
		return
	}

	doc, err := proposerconfig.Unmarshal(body)
	if err != nil {
		writeErr(writer, http.StatusBadRequest, "invalid proposer config")
		return
	}

	// Revision 0 is the unsigned per-node bootstrap, never uploaded.
	if doc.Revision == 0 {
		writeErr(writer, http.StatusBadRequest, "revision 0 is not accepted")
		return
	}

	if err := proposerconfig.Verify(doc, lock); err != nil {
		writeErr(writer, http.StatusBadRequest, err.Error())
		return
	}

	revisions := ts.proposerConfigs[lockHash]
	if revisions == nil {
		revisions = make(map[uint64]proposerconfig.Document)
		ts.proposerConfigs[lockHash] = revisions
	}

	if stored, ok := revisions[doc.Revision]; ok {
		// The signature set may differ between the nodes publishing the same revision.
		if bytes.Equal(stored.StoredHash, doc.StoredHash) {
			writer.WriteHeader(http.StatusOK)
		} else {
			writeErr(writer, http.StatusConflict, "another document of this revision is stored")
		}

		return
	}

	if doc.Revision < latestRevision(revisions) {
		writeErr(writer, http.StatusConflict, "a later revision is stored")
		return
	}

	revisions[doc.Revision] = doc

	writer.WriteHeader(http.StatusCreated)
}

// HandleGetProposerConfig returns the latest stored proposer config revision, or the one of the revision query
// parameter, to an operator of the cluster authenticated by its identity key.
func (ts *testServer) HandleGetProposerConfig(writer http.ResponseWriter, request *http.Request) {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	authToken, ok := request.Context().Value(tokenContextKey).([]byte)
	if !ok {
		writeErr(writer, http.StatusUnauthorized, "missing authorization token")
		return
	}

	vars := mux.Vars(request)
	lockHash := vars[cleanTmpl(lockHashPath)]

	lock, ok := ts.lockFiles[lockHash]
	if !ok {
		writeErr(writer, http.StatusNotFound, "lock not found")
		return
	}

	shareIndex, err := strconv.ParseUint(vars[cleanTmpl(shareIndexPath)], 10, 64)
	if err != nil || shareIndex == 0 || shareIndex > uint64(len(lock.Operators)) {
		writeErr(writer, http.StatusBadRequest, "invalid share index")
		return
	}

	root, err := obolapi.ProposerConfigAuthBlob{LockHash: lock.LockHash, ShareIndex: shareIndex}.HashTreeRoot()
	if err != nil {
		writeErr(writer, http.StatusInternalServerError, "cannot calculate auth root")
		return
	}

	if err := verifyIdentitySignature(lock.Operators[shareIndex-1], authToken, root[:]); err != nil {
		writeErr(writer, http.StatusUnauthorized, "signature not from the share index's operator")
		return
	}

	revisions := ts.proposerConfigs[lockHash]

	revision := latestRevision(revisions)
	if q := request.URL.Query().Get("revision"); q != "" {
		revision, err = strconv.ParseUint(q, 10, 64)
		if err != nil {
			writeErr(writer, http.StatusBadRequest, "invalid revision")
			return
		}
	}

	doc, ok := revisions[revision]
	if !ok {
		writeErr(writer, http.StatusNotFound, "proposer config not found")
		return
	}

	b, err := proposerconfig.Marshal(doc)
	if err != nil {
		writeErr(writer, http.StatusInternalServerError, "cannot marshal proposer config")
		return
	}

	_, _ = writer.Write(b)
}

// latestRevision returns the highest stored revision, 0 if none.
func latestRevision(revisions map[uint64]proposerconfig.Document) uint64 {
	var latest uint64
	for revision := range revisions {
		latest = max(latest, revision)
	}

	return latest
}
