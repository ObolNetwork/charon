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
	"testing"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"go.opentelemetry.io/otel/trace"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/signing"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

// PubShareFunc abstracts the mapping of validator root public key to tbls public share.
type PubShareFunc func(pubkey core.PubKey, shareIdx int) (*bls_sig.PublicKey, error)

// NewComponentInsecure returns a new instance of the validator API core workflow component
// that does not perform signature verification.
func NewComponentInsecure(_ *testing.T, eth2Cl eth2wrap.Client, shareIdx int) (*Component, error) {
	return &Component{
		eth2Cl:   eth2Cl,
		shareIdx: shareIdx,

		insecureTest: true,
	}, nil
}

// NewComponent returns a new instance of the validator API core workflow component.
func NewComponent(eth2Cl eth2wrap.Client, pubShareByKey map[*bls_sig.PublicKey]*bls_sig.PublicKey,
	shareIdx int, feeRecipient string,
) (*Component, error) {
	// Create pubkey mappings.
	var (
		sharesByKey     = make(map[eth2p0.BLSPubKey]eth2p0.BLSPubKey)
		keysByShare     = make(map[eth2p0.BLSPubKey]eth2p0.BLSPubKey)
		sharesByCoreKey = make(map[core.PubKey]*bls_sig.PublicKey)
		coreSharesByKey = make(map[core.PubKey]core.PubKey)
	)

	for pubkey, pubshare := range pubShareByKey {
		coreKey, err := tblsconv.KeyToCore(pubkey)
		if err != nil {
			return nil, err
		}
		coreShare, err := tblsconv.KeyToCore(pubshare)
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
		coreSharesByKey[coreKey] = coreShare
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

	getPubShareFunc := func(pubkey eth2p0.BLSPubKey) (eth2p0.BLSPubKey, bool) {
		share, ok := sharesByKey[pubkey]

		return share, ok
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
		sharesByKey:        coreSharesByKey,
		eth2Cl:             eth2Cl,
		shareIdx:           shareIdx,
		feeRecipient:       feeRecipient,
	}, nil
}

type Component struct {
	eth2Cl       eth2wrap.Client
	shareIdx     int
	insecureTest bool
	feeRecipient string

	// getVerifyShareFunc maps public shares (what the VC thinks as its public key)
	// to public keys (the DV root public key)
	getVerifyShareFunc func(core.PubKey) (*bls_sig.PublicKey, error)
	// getPubShareFunc return the public shares for a root public key.
	getPubShareFunc func(eth2p0.BLSPubKey) (eth2p0.BLSPubKey, bool)
	// getPubKeyFunc return the root public key for a public shares.
	getPubKeyFunc func(eth2p0.BLSPubKey) (eth2p0.BLSPubKey, error)
	// sharesByKey contains this nodes public shares (value) by root public (key)
	sharesByKey map[core.PubKey]core.PubKey

	// Registered input functions

	pubKeyByAttFunc       func(ctx context.Context, slot, commIdx, valCommIdx int64) (core.PubKey, error)
	awaitAttFunc          func(ctx context.Context, slot, commIdx int64) (*eth2p0.AttestationData, error)
	awaitBlockFunc        func(ctx context.Context, slot int64) (*spec.VersionedBeaconBlock, error)
	awaitBlindedBlockFunc func(ctx context.Context, slot int64) (*eth2api.VersionedBlindedBeaconBlock, error)
	dutyDefFunc           func(ctx context.Context, duty core.Duty) (core.DutyDefinitionSet, error)
	subs                  []func(context.Context, core.Duty, core.ParSignedDataSet) error
}

func (c *Component) ProposerDuties(ctx context.Context, epoch eth2p0.Epoch, validatorIndices []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error) {
	duties, err := c.eth2Cl.ProposerDuties(ctx, epoch, validatorIndices)
	if err != nil {
		return nil, err
	}

	// Replace root public keys with public shares
	for i := 0; i < len(duties); i++ {
		pubshare, ok := c.getPubShareFunc(duties[i].PubKey)
		if !ok {
			// Ignore unknown validators since ProposerDuties returns ALL proposers for the epoch if validatorIndices is empty.
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

// RegisterGetDutyDefinition registers a function to query duty definitions.
// It supports a single function, since it is an input of the component.
func (c *Component) RegisterGetDutyDefinition(fn func(ctx context.Context, duty core.Duty) (core.DutyDefinitionSet, error)) {
	c.dutyDefFunc = fn
}

// Subscribe registers a partial signed data set store function.
// It supports multiple functions since it is the output of the component.
func (c *Component) Subscribe(fn func(context.Context, core.Duty, core.ParSignedDataSet) error) {
	c.subs = append(c.subs, func(ctx context.Context, duty core.Duty, set core.ParSignedDataSet) error {
		// Clone before calling each subscriber.
		clone, err := set.Clone()
		if err != nil {
			return err
		}

		return fn(ctx, duty, clone)
	})
}

// RegisterAwaitBeaconBlock registers a function to query unsigned block.
// It supports a single function, since it is an input of the component.
func (c *Component) RegisterAwaitBeaconBlock(fn func(ctx context.Context, slot int64) (*spec.VersionedBeaconBlock, error)) {
	c.awaitBlockFunc = fn
}

// RegisterAwaitBlindedBeaconBlock registers a function to query unsigned blinded block.
// It supports a single function, since it is an input of the component.
func (c *Component) RegisterAwaitBlindedBeaconBlock(fn func(ctx context.Context, slot int64) (*eth2api.VersionedBlindedBeaconBlock, error)) {
	c.awaitBlindedBlockFunc = fn
}

// AttestationData implements the eth2client.AttesterDutiesProvider for the router.
func (c Component) AttestationData(parent context.Context, slot eth2p0.Slot, committeeIndex eth2p0.CommitteeIndex) (*eth2p0.AttestationData, error) {
	ctx, span := core.StartDutyTrace(parent, core.NewAttesterDuty(int64(slot)), "core/validatorapi.AttestationData")
	defer span.End()

	return c.awaitAttFunc(ctx, int64(slot), int64(committeeIndex))
}

// SubmitAttestations implements the eth2client.AttestationsSubmitter for the router.
func (c Component) SubmitAttestations(ctx context.Context, attestations []*eth2p0.Attestation) error {
	duty := core.NewAttesterDuty(int64(attestations[0].Data.Slot))
	if len(attestations) > 0 {
		// Pick the first attestation slot to use as trace root.
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

		// Verify attestation signature
		err = c.verifyPartialSig(pubkey, func(pubshare *bls_sig.PublicKey) error {
			return signing.VerifyAttestation(ctx, c.eth2Cl, pubshare, att)
		})
		if err != nil {
			return err
		}

		// Encode partial signed data and add to a set
		set, ok := setsBySlot[slot]
		if !ok {
			set = make(core.ParSignedDataSet)
			setsBySlot[slot] = set
		}

		set[pubkey] = core.NewPartialAttestation(att, c.shareIdx)
	}

	// Send sets to subscriptions.
	for slot, set := range setsBySlot {
		duty := core.NewAttesterDuty(slot)
		ctx := log.WithCtx(ctx, z.Any("duty", duty))

		log.Debug(ctx, "Attestation(s) submitted by validator client")

		for _, sub := range c.subs {
			// No need to clone since sub auto clones.
			err := sub(ctx, duty, set)
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
	pubkey, err := c.getProposerPubkey(ctx, core.NewProposerDuty(int64(slot)))
	if err != nil {
		return nil, err
	}

	epoch, err := c.epochFromSlot(ctx, slot)
	if err != nil {
		return nil, err
	}

	sigEpoch := eth2util.SignedEpoch{
		Epoch:     epoch,
		Signature: randao,
	}

	parSig := core.NewPartialSignedRandao(sigEpoch.Epoch, sigEpoch.Signature, c.shareIdx)

	// Verify randao signature
	err = c.verifyPartialSig(pubkey, func(pubshare *bls_sig.PublicKey) error {
		return signing.VerifyRandao(ctx, c.eth2Cl, pubshare, sigEpoch)
	})
	if err != nil {
		return nil, err
	}

	for _, sub := range c.subs {
		// No need to clone since sub auto clones.
		parsigSet := core.ParSignedDataSet{
			pubkey: parSig,
		}
		err := sub(ctx, core.NewRandaoDuty(int64(slot)), parsigSet)
		if err != nil {
			return nil, err
		}
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

	pubkey, err := c.getProposerPubkey(ctx, core.NewProposerDuty(int64(slot)))
	if err != nil {
		return err
	}

	// Save Partially Signed Block to ParSigDB
	duty := core.NewProposerDuty(int64(slot))
	ctx = log.WithCtx(ctx, z.Any("duty", duty))

	// Verify block signature
	err = c.verifyPartialSig(pubkey, func(pubshare *bls_sig.PublicKey) error {
		return signing.VerifyBlock(ctx, c.eth2Cl, pubshare, block)
	})
	if err != nil {
		return err
	}

	log.Debug(ctx, "Beacon block submitted by validator client")
	signedData, err := core.NewPartialVersionedSignedBeaconBlock(block, c.shareIdx)
	if err != nil {
		return err
	}

	set := core.ParSignedDataSet{pubkey: signedData}
	for _, sub := range c.subs {
		// No need to clone since sub auto clones.
		err = sub(ctx, duty, set)
		if err != nil {
			return err
		}
	}

	return nil
}

// BlindedBeaconBlockProposal submits the randao for aggregation and inclusion in DutyBuilderProposer and then queries the dutyDB for an unsigned blinded beacon block.
func (c Component) BlindedBeaconBlockProposal(ctx context.Context, slot eth2p0.Slot, randao eth2p0.BLSSignature, _ []byte) (*eth2api.VersionedBlindedBeaconBlock, error) {
	// Get proposer pubkey (this is a blocking query).
	pubkey, err := c.getProposerPubkey(ctx, core.NewBuilderProposerDuty(int64(slot)))
	if err != nil {
		return nil, err
	}

	epoch, err := c.epochFromSlot(ctx, slot)
	if err != nil {
		return nil, err
	}

	sigEpoch := eth2util.SignedEpoch{
		Epoch:     epoch,
		Signature: randao,
	}

	parSig := core.NewPartialSignedRandao(sigEpoch.Epoch, sigEpoch.Signature, c.shareIdx)

	// Verify randao signature
	err = c.verifyPartialSig(pubkey, func(pubshare *bls_sig.PublicKey) error {
		return signing.VerifyRandao(ctx, c.eth2Cl, pubshare, sigEpoch)
	})
	if err != nil {
		return nil, err
	}

	duty := core.NewRandaoDuty(int64(slot))

	for _, sub := range c.subs {
		// No need to clone since sub auto clones.
		parsigSet := core.ParSignedDataSet{
			pubkey: parSig,
		}
		err := sub(ctx, duty, parsigSet)
		if err != nil {
			return nil, err
		}
	}

	// In the background, the following needs to happen before the
	// unsigned blinded beacon block will be returned below:
	//  - Threshold number of VCs need to submit their partial randao reveals.
	//  - These signatures will be exchanged and aggregated.
	//  - The aggregated signature will be stored in AggSigDB.
	//  - Scheduler (in the mean time) will schedule a DutyBuilderProposer (to create a unsigned blinded block).
	//  - Fetcher will then block waiting for an aggregated randao reveal.
	//  - Once it is found, Fetcher will fetch an unsigned blinded block from the beacon
	//    node including the aggregated randao in the request.
	//  - Consensus will agree upon the unsigned blinded block and insert the resulting block in the DutyDB.
	//  - Once inserted, the query below will return.

	// Query unsigned block (this is blocking).
	block, err := c.awaitBlindedBlockFunc(ctx, int64(slot))
	if err != nil {
		return nil, err
	}

	return block, nil
}

func (c Component) SubmitBlindedBeaconBlock(ctx context.Context, block *eth2api.VersionedSignedBlindedBeaconBlock) error {
	// Calculate slot epoch
	slot, err := block.Slot()
	if err != nil {
		return err
	}

	pubkey, err := c.getProposerPubkey(ctx, core.NewBuilderProposerDuty(int64(slot)))
	if err != nil {
		return err
	}

	// Save Partially Signed Blinded Block to ParSigDB
	duty := core.NewBuilderProposerDuty(int64(slot))
	ctx = log.WithCtx(ctx, z.Any("duty", duty))

	// Verify Blinded block signature
	err = c.verifyPartialSig(pubkey, func(pubshare *bls_sig.PublicKey) error {
		return signing.VerifyBlindedBlock(ctx, c.eth2Cl, pubshare, block)
	})
	if err != nil {
		return err
	}

	log.Debug(ctx, "Blinded beacon block submitted by validator client")

	signedData, err := core.NewPartialVersionedSignedBlindedBeaconBlock(block, c.shareIdx)
	if err != nil {
		return err
	}

	set := core.ParSignedDataSet{pubkey: signedData}
	for _, sub := range c.subs {
		// No need to clone since sub auto clones.
		err = sub(ctx, duty, set)
		if err != nil {
			return err
		}
	}

	return nil
}

// submitRegistration receives the partially signed validator (builder) registration.
func (c Component) submitRegistration(ctx context.Context, registration *eth2api.VersionedSignedValidatorRegistration) error {
	timestamp, err := registration.Timestamp()
	if err != nil {
		return err
	}
	slot, err := c.slotFromTimestamp(ctx, timestamp)
	if err != nil {
		return err
	}

	// Note this is the group pubkey
	eth2Pubkey, err := registration.PubKey()
	if err != nil {
		return err
	}

	pubkey, err := core.PubKeyFromBytes(eth2Pubkey[:])
	if err != nil {
		return err
	}

	duty := core.NewBuilderRegistrationDuty(int64(slot))
	ctx = log.WithCtx(ctx, z.Any("duty", duty))

	err = c.verifyPartialSig(pubkey, func(pubshare *bls_sig.PublicKey) error {
		return signing.VerifyValidatorRegistration(ctx, c.eth2Cl, pubshare, registration)
	})
	if err != nil {
		return err
	}

	log.Debug(ctx, "Builder registration submitted by validator client")

	signedData, err := core.NewPartialVersionedSignedValidatorRegistration(registration, c.shareIdx)
	if err != nil {
		return err
	}

	// TODO(corver): Batch these for improved network performance
	set := core.ParSignedDataSet{pubkey: signedData}
	for _, sub := range c.subs {
		// No need to clone since sub auto clones.
		err = sub(ctx, duty, set)
		if err != nil {
			return err
		}
	}

	return nil
}

// SubmitValidatorRegistrations receives the partially signed validator (builder) registration.
func (c Component) SubmitValidatorRegistrations(ctx context.Context, registrations []*eth2api.VersionedSignedValidatorRegistration) error {
	for _, registration := range registrations {
		err := c.submitRegistration(ctx, registration)
		if err != nil {
			return err
		}
	}

	return nil
}

// SubmitVoluntaryExit receives the partially signed voluntary exit.
func (c Component) SubmitVoluntaryExit(ctx context.Context, exit *eth2p0.SignedVoluntaryExit) error {
	vals, err := c.eth2Cl.Validators(ctx, "head", []eth2p0.ValidatorIndex{exit.Message.ValidatorIndex})
	if err != nil {
		return err
	}

	validator, ok := vals[exit.Message.ValidatorIndex]
	if !ok {
		return errors.New("validator not found")
	}

	eth2Pubkey, err := validator.PubKey(ctx)
	if err != nil {
		return err
	}

	pubkey, err := core.PubKeyFromBytes(eth2Pubkey[:])
	if err != nil {
		return err
	}

	// Use 1st slot in exit epoch for duty.
	slotsPerEpoch, err := c.eth2Cl.SlotsPerEpoch(ctx)
	if err != nil {
		return err
	}

	duty := core.NewVoluntaryExit(int64(slotsPerEpoch) * int64(exit.Message.Epoch))
	ctx = log.WithCtx(ctx, z.Any("duty", duty))

	// Verify voluntary exit signature
	err = c.verifyPartialSig(pubkey, func(pubshare *bls_sig.PublicKey) error {
		return signing.VerifyVoluntaryExit(ctx, c.eth2Cl, pubshare, exit)
	})
	if err != nil {
		return err
	}

	log.Info(ctx, "Voluntary exit submitted by validator client")

	parSigData := core.NewPartialSignedVoluntaryExit(exit, c.shareIdx)
	for _, sub := range c.subs {
		// No need to clone since sub auto clones.
		err := sub(ctx, duty, core.ParSignedDataSet{pubkey: parSigData})
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
		pubshare, ok := c.getPubShareFunc(duties[i].PubKey)
		if !ok {
			return nil, errors.New("pubshare not found")
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
		var ok bool
		val.Validator.PublicKey, ok = c.getPubShareFunc(val.Validator.PublicKey)
		if !ok {
			return nil, errors.New("pubshare not found")
		}
		resp[vIdx] = val
	}

	return resp, nil
}

func (c Component) slotFromTimestamp(ctx context.Context, timestamp time.Time) (eth2p0.Slot, error) {
	genesis, err := c.eth2Cl.GenesisTime(ctx)
	if err != nil {
		return 0, err
	} else if timestamp.Before(genesis) {
		return 0, errors.New("registration timestamp before genesis")
	}

	slotDuration, err := c.eth2Cl.SlotDuration(ctx)
	if err != nil {
		return 0, err
	}

	delta := timestamp.Sub(genesis)

	return eth2p0.Slot(delta / slotDuration), nil
}

func (c Component) epochFromSlot(ctx context.Context, slot eth2p0.Slot) (eth2p0.Epoch, error) {
	slotsPerEpoch, err := c.eth2Cl.SlotsPerEpoch(ctx)
	if err != nil {
		return 0, errors.Wrap(err, "getting slots per epoch")
	}

	return eth2p0.Epoch(uint64(slot) / slotsPerEpoch), nil
}

func (c Component) getProposerPubkey(ctx context.Context, duty core.Duty) (core.PubKey, error) {
	// Get proposer pubkey (this is a blocking query).
	defSet, err := c.dutyDefFunc(ctx, duty)
	if err != nil {
		return "", err
	} else if len(defSet) != 1 {
		return "", errors.New("unexpected amount of proposer duties")
	}

	// There should be single duty proposer for the slot
	var pubkey core.PubKey
	for pk := range defSet {
		pubkey = pk
	}

	return pubkey, nil
}

func (c Component) verifyPartialSig(pubkey core.PubKey, verifyFunc func(pubshare *bls_sig.PublicKey) error) error {
	if c.insecureTest {
		return nil
	}

	pubshare, err := c.getVerifyShareFunc(pubkey)
	if err != nil {
		return err
	}

	return verifyFunc(pubshare)
}
