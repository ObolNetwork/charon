// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

package validatorapi

import (
	"context"
	"fmt"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"go.opentelemetry.io/otel/trace"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/tracer"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

type eth2Provider interface {
	eth2client.AttesterDutiesProvider
	eth2client.BeaconBlockProposalProvider
	eth2client.BeaconBlockSubmitter
	eth2client.DomainProvider
	eth2client.ProposerDutiesProvider
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
	awaitBlockFunc  func(ctx context.Context, slot int64) (*spec.VersionedBeaconBlock, error)
	getDutyFunc     func(ctx context.Context, duty core.Duty) (core.FetchArgSet, error)
	parSigDBFuncs   []func(context.Context, core.Duty, core.ParSignedDataSet) error
}

func (c *Component) ProposerDuties(ctx context.Context, epoch eth2p0.Epoch, validatorIndices []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error) {
	duties, err := c.eth2Cl.ProposerDuties(ctx, epoch, validatorIndices)
	if err != nil {
		return nil, err
	}

	// Replace root public keys with public shares
	for i := 0; i < len(duties); i++ {
		pubshare, err := c.getPubShareFunc(duties[i].PubKey)
		if err != nil {
			// pubshare errors can be ignored since proposer duties are rare ones
			continue
		}
		duties[i].PubKey = pubshare
	}

	return duties, nil
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

// RegisterGetDutyFunc registers a function to query duty data by duty.
// It supports a single function, since it is an input of the component.
func (c *Component) RegisterGetDutyFunc(fn func(ctx context.Context, duty core.Duty) (core.FetchArgSet, error)) {
	c.getDutyFunc = fn
}

// RegisterParSigDB registers a partial signed data set store function.
// It supports multiple functions since it is the output of the component.
func (c *Component) RegisterParSigDB(fn func(context.Context, core.Duty, core.ParSignedDataSet) error) {
	c.parSigDBFuncs = append(c.parSigDBFuncs, fn)
}

// RegisterAwaitBeaconBlock registers a function to query unsigned block.
// It supports a single function, since it is an input of the component.
func (c *Component) RegisterAwaitBeaconBlock(fn func(ctx context.Context, slot int64) (*spec.VersionedBeaconBlock, error)) {
	c.awaitBlockFunc = fn
}

// AttestationData implements the eth2client.AttesterDutiesProvider for the router.
func (c Component) AttestationData(parent context.Context, slot eth2p0.Slot, committeeIndex eth2p0.CommitteeIndex) (*eth2p0.AttestationData, error) {
	ctx, span := core.StartDutyTrace(parent, core.NewAttesterDuty(int64(slot)), "core/validatorapi.AttestationData")
	defer span.End()

	return c.awaitAttFunc(ctx, int64(slot), int64(committeeIndex))
}

// SubmitAttestations implements the eth2client.AttestationsSubmitter for the router.
func (c Component) SubmitAttestations(ctx context.Context, attestations []*eth2p0.Attestation) error {
	if len(attestations) > 0 {
		// Pick the first attestation slot to use as trace root.
		duty := core.NewAttesterDuty(int64(attestations[0].Data.Slot))
		var span trace.Span
		ctx, span = core.StartDutyTrace(ctx, duty, "core/validatorapi.SubmitAttestations")
		defer span.End()
	}

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
		duty := core.NewAttesterDuty(slot)

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

// BeaconBlockProposal submits the randao for aggregation and inclusion in DutyProposer and then queries the dutyDB for an unsigned beacon block.
func (c Component) BeaconBlockProposal(ctx context.Context, slot eth2p0.Slot, randao eth2p0.BLSSignature, _ []byte) (*spec.VersionedBeaconBlock, error) {
	// Get proposer pubkey (this is a blocking query).
	pubkey, err := c.getProposerPubkey(ctx, slot)
	if err != nil {
		return nil, err
	}

	// Verify randao partial signature
	err = c.verifyRandaoParSig(ctx, pubkey, slot, randao)
	if err != nil {
		return nil, err
	}

	err = c.submitRandaoDuty(ctx, pubkey, slot, randao)
	if err != nil {
		return nil, err
	}

	// In the background, the following needs to happen before the
	// unsigned beacon block will be returned below:
	//  - Threshold number of VCs need to submit their partial randao reveals.
	//  - These signatures will be exchanged and aggregated.
	//  - The aggregated signature will be stored in AggSigDB.
	//  - Scheduler (in the mean time) will schedule a DutyProposer (to create a unsigned block).
	//  - Fetcher will then block waiting for an aggregated randao reveal.
	//  - Once it is found, Fetcher will fetch an unsigned block from the beacon
	//    node including the aggregated randao in the request.
	//  - Consensus will agree upon the unsigned block and insert the resulting block in the DutyDB.
	//  - Once inserted, the query below will return.

	// Query unsigned block (this is blocking).
	block, err := c.awaitBlockFunc(ctx, int64(slot))
	if err != nil {
		return nil, err
	}

	return block, nil
}

func (c Component) SubmitBeaconBlock(ctx context.Context, block *spec.VersionedSignedBeaconBlock) error {
	// Calculate slot epoch
	slot, err := block.Slot()
	if err != nil {
		return err
	}

	pubkey, err := c.getProposerPubkey(ctx, slot)
	if err != nil {
		return err
	}

	err = c.verifyBlockSignature(ctx, block, pubkey, slot)
	if err != nil {
		return err
	}

	// Save Partially Signed Block to ParSigDB
	duty := core.NewProposerDuty(int64(slot))
	signedData, err := core.EncodeBlockParSignedData(block, c.shareIdx)
	if err != nil {
		return err
	}
	set := core.ParSignedDataSet{pubkey: signedData}
	for _, dbFunc := range c.parSigDBFuncs {
		err = dbFunc(ctx, duty, set)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c Component) verifyBlockSignature(ctx context.Context, block *spec.VersionedSignedBeaconBlock, pubkey core.PubKey, slot eth2p0.Slot) error {
	epoch, err := c.epochFromSlot(ctx, slot)
	if err != nil {
		return err
	}

	var sig eth2p0.BLSSignature
	switch block.Version {
	case spec.DataVersionPhase0:
		if block.Phase0.Signature == sig {
			return errors.New("no phase0 signature")
		}
		sig = block.Phase0.Signature
	case spec.DataVersionAltair:
		if block.Altair.Signature == sig {
			return errors.New("no altair signature")
		}
		sig = block.Altair.Signature
	case spec.DataVersionBellatrix:
		if block.Bellatrix.Signature == sig {
			return errors.New("no bellatrix signature")
		}
		sig = block.Bellatrix.Signature
	}

	// Verify partial signature
	sigRoot, err := block.Root()
	if err != nil {
		return err
	}

	return c.verifyParSig(ctx, core.DutyProposer, epoch, pubkey, sigRoot, sig)
}

func (c Component) verifyRandaoParSig(ctx context.Context, pubKey core.PubKey, slot eth2p0.Slot, randao eth2p0.BLSSignature) error {
	// Calculate slot epoch
	epoch, err := c.epochFromSlot(ctx, slot)
	if err != nil {
		return err
	}

	// Randao signing root is the epoch.
	sigRoot, err := MerkleEpoch(epoch).HashTreeRoot()
	if err != nil {
		return err
	}

	return c.verifyParSig(ctx, core.DutyRandao, epoch, pubKey, sigRoot, randao)
}

// verifyParSig verifies the partial signature against the root and validator.
func (c Component) verifyParSig(parent context.Context, typ core.DutyType, epoch eth2p0.Epoch,
	pubkey core.PubKey, sigRoot eth2p0.Root, sig eth2p0.BLSSignature,
) error {
	if c.skipVerify {
		return nil
	}
	ctx, span := tracer.Start(parent, "core/validatorapi.VerifyParSig")
	defer span.End()

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

func (c Component) submitRandaoDuty(ctx context.Context, pubKey core.PubKey, slot eth2p0.Slot, randao eth2p0.BLSSignature) error {
	parsigSet := core.ParSignedDataSet{
		pubKey: core.EncodeRandaoParSignedData(randao, c.shareIdx),
	}

	for _, dbFunc := range c.parSigDBFuncs {
		err := dbFunc(ctx, core.NewRandaoDuty(int64(slot)), parsigSet)
		if err != nil {
			return err
		}
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

func (c Component) epochFromSlot(ctx context.Context, slot eth2p0.Slot) (eth2p0.Epoch, error) {
	slotsPerEpoch, err := c.eth2Cl.SlotsPerEpoch(ctx)
	if err != nil {
		return 0, errors.Wrap(err, "getting slots per epoch")
	}

	return eth2p0.Epoch(uint64(slot) / slotsPerEpoch), nil
}

func (c Component) getProposerPubkey(ctx context.Context, slot eth2p0.Slot) (core.PubKey, error) {
	// Get proposer pubkey (this is a blocking query).
	dutySet, err := c.getDutyFunc(ctx, core.Duty{Slot: int64(slot), Type: core.DutyProposer})
	if err != nil {
		return "", err
	} else if len(dutySet) != 1 {
		return "", errors.New("unexpected amount of proposer duties")
	}

	// There should be single duty proposer for the slot
	var pubkey core.PubKey
	for pk := range dutySet {
		pubkey = pk
	}

	return pubkey, nil
}
