// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package genericsig

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync"

	"github.com/gorilla/mux"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
)

const (
	PushSigRoute  = "/genericsig/push"
	FetchSigRoute = "/genericsig/{validator_pubkey}/{hash}"
)

func hexStrToBytes(s string) ([]byte, error) {
	if !strings.HasPrefix(s, "0x") {
		return nil, errors.New("string doesn't begin with 0x")
	}

	s = s[2:]

	sb, err := hex.DecodeString(s)
	if err != nil {
		return nil, errors.Wrap(err, "hex decode")
	}

	return sb, nil
}

type fullSignatureJSON struct {
	Signature string `json:"signature"`
}

type fullSignature struct {
	Signature core.Signature `json:"signature"`
}

func (f fullSignature) MarshalJSON() ([]byte, error) {
	fStr := "0x" + hex.EncodeToString(f.Signature[:])

	ret := fullSignatureJSON{Signature: fStr}

	return json.Marshal(ret)
}

type GenericSignature struct {
	store      map[core.PubKey]map[[32]byte]core.Signature
	storeMutex sync.RWMutex
	shareIdx   int

	currSlot      core.Slot
	currSlotMutex sync.RWMutex

	parsigDBStoreInternal func(context.Context, core.Duty, core.ParSignedDataSet) error
}

func New(shareIdx int, pdbStore func(context.Context, core.Duty, core.ParSignedDataSet) error) GenericSignature {
	return GenericSignature{
		store:                 make(map[core.PubKey]map[[32]byte]core.Signature),
		storeMutex:            sync.RWMutex{},
		shareIdx:              shareIdx,
		parsigDBStoreInternal: pdbStore,
	}
}

func (gs *GenericSignature) Slot(_ context.Context, slot core.Slot) error {
	gs.currSlotMutex.Lock()
	defer gs.currSlotMutex.Unlock()

	gs.currSlot = slot

	return nil
}

func (gs *GenericSignature) StoreFullSignatures(ctx context.Context, duty core.Duty, data core.SignedDataSet) error {
	if duty.Type != core.DutyGenericSignature {
		// Ignore everything besides DutyGenericSignature
		return nil
	}

	gs.storeMutex.Lock()
	defer gs.storeMutex.Unlock()

	for pubKey, content := range data {
		gsData, ok := content.(core.GenericSignatureData)
		if !ok {
			log.Warn(ctx, "data is not of GenericSignatureData type", nil, z.Any("data", content))
			continue
		}

		pkMap, ok := gs.store[pubKey]
		if !ok {
			gs.store[pubKey] = make(map[[32]byte]core.Signature)
			pkMap = gs.store[pubKey]
		}

		pkMap[gsData.Hash] = gsData.Sig
	}

	return nil
}

func (gs *GenericSignature) StorePartialSignature(rw http.ResponseWriter, r *http.Request) {
	var data core.GenericSignatureData
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		hErr(rw, err, http.StatusBadRequest)
		return
	}

	if data.ValidatorPubkey == "" {
		hErr(rw, errors.New("validator pubkey is empty"), http.StatusBadGateway)
		return
	}

	if data.Hash == [32]byte{} {
		hErr(rw, errors.New("hash is empty"), http.StatusBadGateway)
		return
	}

	if len(data.Sig) == 0 {
		hErr(rw, errors.New("signature is empty"), http.StatusBadGateway)
		return
	}

	ctx := r.Context()

	if err := gs.parsigDBStoreInternal(ctx, core.Duty{
		Slot: gs.getSlot().Slot,
		Type: core.DutyGenericSignature,
	}, core.ParSignedDataSet{
		data.ValidatorPubkey: core.ParSignedData{
			SignedData: data,
			ShareIdx:   gs.shareIdx,
		},
	}); err != nil {
		log.Error(ctx, "can't push partial generic signature to parsigdb", err)
		hErr(rw, err, http.StatusInternalServerError)
		return
	}
}

func (gs *GenericSignature) GetFullSignature(rw http.ResponseWriter, r *http.Request) {
	gs.storeMutex.RLock()
	defer gs.storeMutex.RUnlock()

	// TODO(gsora): get Authorization header, validator pubkey, hash from path
	// check k1Sig(validator pubkey+hash) comes from the configured Charon identity key
	// check that there's data for gs.store[validator pubkey][hash]
	// if yes, return a fullSignature object with that inside
	// Keep in mind this thing is executed from within gorilla/mux

	vars := mux.Vars(r)

	valPubkey := vars["validator_pubkey"]
	hash := vars["hash"]

	rawValPubkeyBytes, err := hexStrToBytes(valPubkey)
	if err != nil {
		hErr(rw, errors.Wrap(err, "malformed validator pubkey"), http.StatusBadRequest)
		return
	}

	valPubkeyBytes, err := core.PubKeyFromBytes(rawValPubkeyBytes)
	if err != nil {
		hErr(rw, errors.Wrap(err, "malformed validator pubkey"), http.StatusBadRequest)
		return
	}

	rawHashBytes, err := hexStrToBytes(hash)
	if err != nil {
		hErr(rw, errors.Wrap(err, "malformed hash"), http.StatusBadRequest)
		return
	}

	if len(rawHashBytes) != 32 {
		hErr(rw, errors.New("hash length is not 32"), http.StatusBadRequest)
		return
	}

	hashBytes := [32]byte(rawHashBytes)

	gs.storeMutex.RLock()
	defer gs.storeMutex.RUnlock()

	found, ok := gs.store[valPubkeyBytes][hashBytes]
	if !ok {
		rw.WriteHeader(http.StatusNotFound)
		return
	}

	if err := json.NewEncoder(rw).Encode(fullSignature{Signature: found}); err != nil {
		hErr(rw, errors.Wrap(err, "can't encode signature"), http.StatusInternalServerError)
		return
	}
}

// getSlot returns the current slot, plus two whole epochs in advance
// Why: deadliner will have this expire enough time in the future to allow for aggregation and download
// of the aggregated signature.
func (gs *GenericSignature) getSlot() core.Slot {
	gs.currSlotMutex.RLock()
	defer gs.currSlotMutex.RUnlock()

	slot := gs.currSlot

	slot.Slot += slot.SlotsPerEpoch * 2

	return slot
}

type httpError struct {
	Inner      error `json:"error"`
	StatusCode int   `json:"-"`
}

func (h httpError) MarshalJSON() ([]byte, error) {
	ret := struct {
		Error      string `json:"error"`
		StatusCode string `json:"status_code"`
	}{
		Error:      h.Inner.Error(),
		StatusCode: http.StatusText(h.StatusCode),
	}

	return json.Marshal(ret)
}

func hErr(rw http.ResponseWriter, err error, statusCode int) {
	e := httpError{
		Inner:      err,
		StatusCode: statusCode,
	}

	if err := json.NewEncoder(rw).Encode(e); err != nil {
		panic(errors.New("can't encode http error", z.Err(err)))
	}
}
