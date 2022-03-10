// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package validatormock provides mock validator client functionality.
package validatormock

import (
	"context"
	"fmt"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/dB2510/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/prysmaticlabs/go-bitfield"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core/validatorapi"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

// Eth2AttProvider defines the eth2 beacon api providers required to perform attestations.
type Eth2AttProvider interface {
	eth2client.AttestationDataProvider
	eth2client.AttestationsSubmitter
	eth2client.AttesterDutiesProvider
	eth2client.DomainProvider
	eth2client.SlotsPerEpochProvider
	eth2client.SpecProvider
	eth2client.ValidatorsProvider
	// Above sorted alphabetically.
}

// SignFunc abstract signing done by the validator client.
type SignFunc func(context.Context, eth2p0.BLSPubKey, eth2p0.SigningData) (eth2p0.BLSSignature, error)

// Attest performs attestation duties for the provided slot and pubkeys (validators).
func Attest(ctx context.Context, eth2Cl Eth2AttProvider, signFunc SignFunc,
	slot eth2p0.Slot, pubkeys ...eth2p0.BLSPubKey,
) error {
	slotsPerEpoch, err := eth2Cl.SlotsPerEpoch(ctx)
	if err != nil {
		return err
	}

	epoch := eth2p0.Epoch(uint64(slot) / slotsPerEpoch)

	domain, err := validatorapi.GetDomain(ctx, eth2Cl, validatorapi.DomainBeaconAttester, epoch)
	if err != nil {
		return err
	}

	valMap, err := eth2Cl.ValidatorsByPubKey(ctx, fmt.Sprint(slot), pubkeys)
	if err != nil {
		return err
	}

	var indexes []eth2p0.ValidatorIndex
	for index, val := range valMap {
		if !val.Status.IsActive() {
			continue
		}
		indexes = append(indexes, index)
	}

	duties, err := eth2Cl.AttesterDuties(ctx, epoch, indexes)
	if err != nil {
		return err
	}

	var atts []*eth2p0.Attestation
	for _, duty := range duties {
		if duty.Slot != slot {
			continue
		}

		data, err := eth2Cl.AttestationData(ctx, duty.Slot, duty.CommitteeIndex)
		if err != nil {
			return err
		}

		root, err := data.HashTreeRoot()
		if err != nil {
			return errors.Wrap(err, "hash attestation")
		}

		sig, err := signFunc(ctx, duty.PubKey, eth2p0.SigningData{
			ObjectRoot: root,
			Domain:     domain,
		})
		if err != nil {
			return err
		}

		aggBits := bitfield.NewBitlist(duty.CommitteeLength)
		aggBits.SetBitAt(duty.ValidatorCommitteeIndex, true)

		atts = append(atts, &eth2p0.Attestation{
			AggregationBits: aggBits,
			Data:            data,
			Signature:       sig,
		})
	}

	return eth2Cl.SubmitAttestations(ctx, atts)
}

// NewSigner returns a singing function supporting the provided private keys.
func NewSigner(secrets ...*bls_sig.SecretKey) SignFunc {
	return func(ctx context.Context, pubkey eth2p0.BLSPubKey, data eth2p0.SigningData) (eth2p0.BLSSignature, error) {
		secret, err := getSecret(secrets, pubkey)
		if err != nil {
			return eth2p0.BLSSignature{}, err
		}

		msg, err := data.MarshalSSZ()
		if err != nil {
			return eth2p0.BLSSignature{}, errors.Wrap(err, "marshal signing data")
		}

		sig, err := tbls.Sign(secret, msg)
		if err != nil {
			return eth2p0.BLSSignature{}, err
		}

		return tblsconv.SigToETH2(sig), nil
	}
}

func getSecret(secrets []*bls_sig.SecretKey, pubkey eth2p0.BLSPubKey) (*bls_sig.SecretKey, error) {
	for _, secret := range secrets {
		pk, err := secret.GetPublicKey()
		if err != nil {
			return nil, errors.Wrap(err, "get pubkey")
		}

		eth2Pubkey, err := tblsconv.KeyToETH2(pk)
		if err != nil {
			return nil, err
		}

		if eth2Pubkey == pubkey {
			return secret, nil
		}
	}

	return nil, errors.New("private key not found")
}
