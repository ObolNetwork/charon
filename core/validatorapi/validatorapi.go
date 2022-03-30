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

package validatorapi

import (
	"context"
	"fmt"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

type eth2Provider interface {
	eth2client.AttesterDutiesProvider
	eth2client.DomainProvider
	eth2client.SlotsPerEpochProvider
	eth2client.SpecProvider
	eth2client.ValidatorsProvider
	// Above sorted alphabetically
}

// PubShareFunc abstracts the mapping of validator root public key to tbls public share.
type PubShareFunc func(pubkey core.PubKey, shareIdx int) (*bls_sig.PublicKey, error)

// NewComponentInsecure returns a new instance of the validator API core workflow component
// that does not perform signature verification.
func NewComponentInsecure(eth2Svc eth2client.Service, shareIdx int) (*Component, error) {
	eth2Cl, ok := eth2Svc.(eth2Provider)
	if !ok {
		return nil, errors.New("invalid eth2 service")
	}

	return &Component{
		skipVerify: true,
		eth2Cl:     eth2Cl,
		shareIdx:   shareIdx,
	}, nil
}

// NewComponent returns a new instance of the validator API core workflow component.
func NewComponent(eth2Svc eth2client.Service, pubShareByKey map[*bls_sig.PublicKey]*bls_sig.PublicKey, shareIdx int) (*Component, error) {
	eth2Cl, ok := eth2Svc.(eth2Provider)
	if !ok {
		return nil, errors.New("invalid eth2 service")
	}

	// Create pubkey mappings.
	var (
		sharesByKey     = make(map[eth2p0.BLSPubKey]eth2p0.BLSPubKey)
		keysByShare     = make(map[eth2p0.BLSPubKey]eth2p0.BLSPubKey)
		sharesByCoreKey = make(map[core.PubKey]*bls_sig.PublicKey)
	)

	for pubkey, pubshare := range pubShareByKey {
		coreKey, err := tblsconv.KeyToCore(pubkey)
		if err != nil {
			return nil, err
		}
		key, err := tblsconv.KeyToETH2(pubkey)
		if err != nil {
			return nil, err
		}
		share, err := tblsconv.KeyToETH2(pubshare)
		if err != nil {
			return nil, err
		}
		sharesByCoreKey[coreKey] = pubshare
		sharesByKey[key] = share
		keysByShare[share] = key
	}

	getVerifyShareFunc := func(pubkey core.PubKey) (*bls_sig.PublicKey, error) {
		pubshare, ok := sharesByCoreKey[pubkey]
		if !ok {
			return nil, errors.New("unknown public key")
		}

		return pubshare, nil
	}

	getPubShareFunc := func(pubkey eth2p0.BLSPubKey) (eth2p0.BLSPubKey, error) {
		share, ok := sharesByKey[pubkey]
		if !ok {
			return eth2p0.BLSPubKey{}, errors.New("unknown public key")
		}

		return share, nil
	}

	getPubKeyFunc := func(share eth2p0.BLSPubKey) (eth2p0.BLSPubKey, error) {
		key, ok := keysByShare[share]
		if !ok {
			return eth2p0.BLSPubKey{}, errors.New("unknown public share")
		}

		return key, nil
	}

	return &Component{
		getVerifyShareFunc: getVerifyShareFunc,
		getPubShareFunc:    getPubShareFunc,
		getPubKeyFunc:      getPubKeyFunc,
		eth2Cl:             eth2Cl,
		shareIdx:           shareIdx,
	}, nil
}

type Component struct {
	eth2Cl     eth2Provider
	shareIdx   int
	skipVerify bool

	// Mapping public shares (what the VC thinks as its public key) to public keys (the DV root public key)

	getVerifyShareFunc func(core.PubKey) (*bls_sig.PublicKey, error)
	getPubShareFunc    func(eth2p0.BLSPubKey) (eth2p0.BLSPubKey, error)
	getPubKeyFunc      func(eth2p0.BLSPubKey) (eth2p0.BLSPubKey, error)

	// Registered input functions

	pubKeyByAttFunc func(ctx context.Context, slot, commIdx, valCommIdx int64) (core.PubKey, error)
	awaitAttFunc    func(ctx context.Context, slot, commIdx int64) (*eth2p0.AttestationData, error)
	parSigDBFuncs   []func(context.Context, core.Duty, core.ParSignedDataSet) error
}

func (*Component) ProposerDuties(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error) {
	return []*eth2v1.ProposerDuty{}, nil // No proposer duties for now.
}

// RegisterAwaitAttestation registers a function to query attestation data.
// It only supports a single function, since it is an input of the component.
func (c *Component) RegisterAwaitAttestation(fn func(ctx context.Context, slot, commIdx int64) (*eth2p0.AttestationData, error)) {
	c.awaitAttFunc = fn
}

// RegisterPubKeyByAttestation registers a function to query pubkeys by attestation.
// It only supports a single function, since it is an input of the component.
func (c *Component) RegisterPubKeyByAttestation(fn func(ctx context.Context, slot, commIdx, valCommIdx int64) (core.PubKey, error)) {
	c.pubKeyByAttFunc = fn
}

// RegisterParSigDB registers a partial signed data set store function.
// It supports functions multiple since it is the output of the component.
func (c *Component) RegisterParSigDB(fn func(context.Context, core.Duty, core.ParSignedDataSet) error) {
	c.parSigDBFuncs = append(c.parSigDBFuncs, fn)
}

// AttestationData implements the eth2client.AttesterDutiesProvider for the router.
func (c Component) AttestationData(ctx context.Context, slot eth2p0.Slot, committeeIndex eth2p0.CommitteeIndex) (*eth2p0.AttestationData, error) {
	return c.awaitAttFunc(ctx, int64(slot), int64(committeeIndex))
}

// SubmitAttestations implements the eth2client.AttestationsSubmitter for the router.
func (c Component) SubmitAttestations(ctx context.Context, attestations []*eth2p0.Attestation) error {
	setsBySlot := make(map[int64]core.ParSignedDataSet)

	for _, att := range attestations {
		slot := int64(att.Data.Slot)

		// Determine the validator that sent this by mapping values from original AttestationDuty via the dutyDB
		indices := att.AggregationBits.BitIndices()
		if len(indices) != 1 {
			return errors.New("unexpected number of aggregation bits",
				z.Str("aggbits", fmt.Sprintf("%#x", []byte(att.AggregationBits))))
		}

		pubkey, err := c.pubKeyByAttFunc(ctx, slot, int64(att.Data.Index), int64(indices[0]))
		if err != nil {
			return err
		}

		// Verify signature
		sigRoot, err := att.Data.HashTreeRoot()
		if err != nil {
			return errors.Wrap(err, "hash attestation data")
		}

		if err := c.verifyParSig(ctx, core.DutyAttester, att.Data.Target.Epoch, pubkey, sigRoot, att.Signature); err != nil {
			return err
		}

		// Encode partial signed data and add to a set
		set, ok := setsBySlot[slot]
		if !ok {
			set = make(core.ParSignedDataSet)
			setsBySlot[slot] = set
		}

		signedData, err := core.EncodeAttestationParSignedData(att, c.shareIdx)
		if err != nil {
			return err
		}

		set[pubkey] = signedData
	}

	// Send sets to subscriptions.
	for slot, set := range setsBySlot {
		duty := core.Duty{
			Slot: slot,
			Type: core.DutyAttester,
		}

		log.Debug(ctx, "Attestation submitted by VC", z.I64("slot", slot))

		for _, dbFunc := range c.parSigDBFuncs {
			err := dbFunc(ctx, duty, set)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (Component) BeaconBlockProposal(_ context.Context, _ eth2p0.Slot, _ eth2p0.BLSSignature, _ []byte) (*spec.VersionedBeaconBlock, error) {
	return nil, errors.New("not implemented")
}

// verifyParSig verifies the partial signature against the root and validator.
func (c Component) verifyParSig(ctx context.Context, typ core.DutyType, epoch eth2p0.Epoch,
	pubkey core.PubKey, sigRoot eth2p0.Root, sig eth2p0.BLSSignature,
) error {
	if c.skipVerify {
		return nil
	}

	// Wrap the signing root with the domain and serialise it.
	sigData, err := prepSigningData(ctx, c.eth2Cl, typ, epoch, sigRoot)
	if err != nil {
		return err
	}

	// Convert the signature
	s, err := tblsconv.SigFromETH2(sig)
	if err != nil {
		return errors.Wrap(err, "convert signature")
	}

	// Verify using public share
	pubshare, err := c.getVerifyShareFunc(pubkey)
	if err != nil {
		return err
	}

	ok, err := tbls.Verify(pubshare, sigData[:], s)
	if err != nil {
		return err
	} else if !ok {
		return errors.New("invalid signature")
	}

	return nil
}

func (c Component) AttesterDuties(ctx context.Context, epoch eth2p0.Epoch, validatorIndices []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, error) {
	duties, err := c.eth2Cl.AttesterDuties(ctx, epoch, validatorIndices)
	if err != nil {
		return nil, err
	}

	// Replace root public keys with public shares.
	for i := 0; i < len(duties); i++ {
		pubshare, err := c.getPubShareFunc(duties[i].PubKey)
		if err != nil {
			return nil, err
		}
		duties[i].PubKey = pubshare
	}

	return duties, nil
}

func (c Component) Validators(ctx context.Context, stateID string, validatorIndices []eth2p0.ValidatorIndex) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error) {
	vals, err := c.eth2Cl.Validators(ctx, stateID, validatorIndices)
	if err != nil {
		return nil, err
	}

	return c.convertValidators(vals)
}

func (c Component) ValidatorsByPubKey(ctx context.Context, stateID string, pubshares []eth2p0.BLSPubKey) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error) {
	// Map from public shares to public keys before querying the beacon node.
	var pubkeys []eth2p0.BLSPubKey
	for _, pubshare := range pubshares {
		pubkey, err := c.getPubKeyFunc(pubshare)
		if err != nil {
			return nil, err
		}

		pubkeys = append(pubkeys, pubkey)
	}

	valMap, err := c.eth2Cl.ValidatorsByPubKey(ctx, stateID, pubkeys)
	if err != nil {
		return nil, err
	}

	// Then convert back.
	return c.convertValidators(valMap)
}

// convertValidators returns the validator map with all root public keys replaced by public shares.
func (c Component) convertValidators(vals map[eth2p0.ValidatorIndex]*eth2v1.Validator) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error) {
	resp := make(map[eth2p0.ValidatorIndex]*eth2v1.Validator)
	for vIdx, val := range vals {
		var err error
		val.Validator.PublicKey, err = c.getPubShareFunc(val.Validator.PublicKey)
		if err != nil {
			return nil, err
		}
		resp[vIdx] = val
	}

	return resp, nil
}
