// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapimock

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/gorilla/mux"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/obolapi"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/deposit"
	"github.com/obolnetwork/charon/tbls"
)

const (
	submitPartialDepositTmpl = "/deposit_data/partial_deposits/" + lockHashPath + "/" + shareIndexPath
	fetchFullDepositTmpl     = "/deposit_data/" + lockHashPath + "/" + valPubkeyPath
)

// depositBlob represents an Obol API DepositBlob with its share index.
type depositBlob struct {
	obolapi.FullDepositResponse

	shareIdx uint64
}

func (ts *testServer) HandleSubmitPartialDeposit(writer http.ResponseWriter, request *http.Request) {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	vars := mux.Vars(request)

	var data obolapi.PartialDepositRequest

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

	// check that data has been signed with ShareIdx-th identity key
	if shareIndex == 0 || shareIndex > uint64(len(lock.Operators)) {
		writeErr(writer, http.StatusBadRequest, "invalid share index")
		return
	}

	network, err := eth2util.ForkVersionToNetwork(lock.ForkVersion)
	if err != nil {
		writeErr(writer, http.StatusBadRequest, "invalid network")
		return
	}

	for _, depositData := range data.PartialDepositData {
		signedDepositsRoot, err := deposit.GetMessageSigningRoot(eth2p0.DepositMessage{
			PublicKey:             depositData.PublicKey,
			WithdrawalCredentials: depositData.WithdrawalCredentials,
			Amount:                depositData.Amount,
		}, network)
		if err != nil {
			writeErr(writer, http.StatusInternalServerError, "cannot calculate hash tree root for provided signed exits")
			return
		}

		publicKeyShare := tbls.PublicKey{}
		for _, v := range lock.Validators {
			if v.PublicKeyHex() == depositData.PublicKey.String() {
				publicKeyShare, err = v.PublicShare(int(shareIndex) - 1)
				if err != nil {
					writeErr(writer, http.StatusBadRequest, "cannot fetch public share: "+err.Error())
					return
				}
			}
		}

		if len(publicKeyShare) == 0 {
			writeErr(writer, http.StatusBadRequest, "cannot find public key in lock file: "+err.Error())
			return
		}

		if err := tbls.Verify(publicKeyShare, signedDepositsRoot[:], tbls.Signature(depositData.Signature)); err != nil {
			writeErr(writer, http.StatusBadRequest, "cannot verify signature: "+err.Error())
			return
		}

		existingDeposit, ok := ts.partialDeposits[depositData.PublicKey.String()]

		amounts := []obolapi.Amount{}
		if ok {
			amounts = existingDeposit.Amounts
		}

		amtFound := false

		for idx, amt := range amounts {
			if amt.Amount == strconv.FormatUint(uint64(depositData.Amount), 10) {
				amt.Partials = append(amt.Partials, obolapi.Partial{
					PartialDepositSignature: depositData.Signature.String(),
					PartialPublicKey:        "",
				})
				amounts[idx] = amt
				amtFound = true
			}
		}

		existingDeposit.Amounts = amounts

		if !amtFound {
			amounts = append(amounts, obolapi.Amount{
				Amount: strconv.FormatUint(uint64(depositData.Amount), 10),
				Partials: []obolapi.Partial{
					{
						PartialDepositSignature: depositData.Signature.String(),
						PartialPublicKey:        "",
					},
				},
			})

			ts.partialDeposits[depositData.PublicKey.String()] = depositBlob{
				FullDepositResponse: obolapi.FullDepositResponse{
					PublicKey:             depositData.PublicKey.String(),
					WithdrawalCredentials: hex.EncodeToString(depositData.WithdrawalCredentials),
					Amounts:               amounts,
				},
				shareIdx: shareIndex,
			}
		}
	}

	writer.WriteHeader(http.StatusCreated)
}

func (ts *testServer) HandleGetFullDeposit(writer http.ResponseWriter, request *http.Request) {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	vars := mux.Vars(request)

	valPubkey := vars[cleanTmpl(valPubkeyPath)]
	lockHash := vars[cleanTmpl(lockHashPath)]

	lock, ok := ts.lockFiles[lockHash]
	if !ok {
		writeErr(writer, http.StatusNotFound, "lock not found")
		return
	}

	partialDeposits, ok := ts.partialDeposits[valPubkey]
	if !ok {
		writeErr(writer, http.StatusNotFound, "validator not found")
		return
	}

	amountsWithEnoughPartials := []obolapi.Amount{}

	for _, pd := range partialDeposits.Amounts {
		if len(pd.Partials) >= lock.Threshold {
			amountsWithEnoughPartials = append(amountsWithEnoughPartials, pd)
		}
	}

	if len(amountsWithEnoughPartials) == 0 {
		writeErr(writer, http.StatusUnauthorized, "not enough partial deposits for any amount")
		return
	}

	depositResponseData := obolapi.FullDepositResponse{
		PublicKey:             partialDeposits.PublicKey,
		WithdrawalCredentials: partialDeposits.WithdrawalCredentials,
		Amounts:               amountsWithEnoughPartials,
	}

	if err := json.NewEncoder(writer).Encode(depositResponseData); err != nil {
		writeErr(writer, http.StatusInternalServerError, errors.Wrap(err, "cannot marshal exit message").Error())
		return
	}
}
