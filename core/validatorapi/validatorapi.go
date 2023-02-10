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
	"runtime"
	"testing"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"go.opentelemetry.io/otel/trace"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/eth2exp"
	"github.com/obolnetwork/charon/eth2util/signing"
	tblsv2 "github.com/obolnetwork/charon/tbls/v2"
	tblsconv2 "github.com/obolnetwork/charon/tbls/v2/tblsconv"
)

// NewComponentInsecure returns a new instance of the validator API core workflow component
// that does not perform signature verification.
func NewComponentInsecure(_ *testing.T, eth2Cl eth2wrap.Client, shareIdx int) (*Component, error) {
	return &Component{
		eth2Cl:         eth2Cl,
		shareIdx:       shareIdx,
		builderEnabled: func(int64) bool { return false },
		insecureTest:   true,
	}, nil
}

// NewComponent returns a new instance of the validator API core workflow component.
func NewComponent(eth2Cl eth2wrap.Client, allPubSharesByKey map[core.PubKey]map[int]tblsv2.PublicKey,
	shareIdx int, feeRecipientFunc func(core.PubKey) string, builderEnabled core.BuilderEnabled, seenPubkeys func(core.PubKey),
) (*Component, error) {
	var (
		sharesByKey     = make(map[eth2p0.BLSPubKey]eth2p0.BLSPubKey)
		keysByShare     = make(map[eth2p0.BLSPubKey]eth2p0.BLSPubKey)
		sharesByCoreKey = make(map[core.PubKey]tblsv2.PublicKey)
		coreSharesByKey = make(map[core.PubKey]core.PubKey)
	)
	for corePubkey, shares := range allPubSharesByKey {
		pubshare := shares[shareIdx]
		coreShare, err := core.PubKeyFromBytes(pubshare[:])
		if err != nil {
			return nil, err
		}

		cpBytes, err := corePubkey.Bytes()
		if err != nil {
			return nil, err
		}
		pubkey, err := tblsconv2.PubkeyFromBytes(cpBytes)
		if err != nil {
			return nil, err
		}
		eth2Pubkey := eth2p0.BLSPubKey(pubkey)

		eth2Share := eth2p0.BLSPubKey(pubshare)
		sharesByCoreKey[corePubkey] = pubshare
		coreSharesByKey[corePubkey] = coreShare
		sharesByKey[eth2Pubkey] = eth2Share
		keysByShare[eth2Share] = eth2Pubkey
	}

	getVerifyShareFunc := func(pubkey core.PubKey) (tblsv2.PublicKey, error) {
		pubshare, ok := sharesByCoreKey[pubkey]
		if !ok {
			return tblsv2.PublicKey{}, errors.New("unknown public key")
		}

		return pubshare, nil
	}

	getPubShareFunc := func(pubkey eth2p0.BLSPubKey) (eth2p0.BLSPubKey, bool) {
		share, ok := sharesByKey[pubkey]

		if seenPubkeys != nil {
			seenPubkeys(core.PubKeyFrom48Bytes(pubkey))
		}

		return share, ok
	}

	getPubKeyFunc := func(share eth2p0.BLSPubKey) (eth2p0.BLSPubKey, error) {
		key, ok := keysByShare[share]
		if !ok {
			for _, shares := range allPubSharesByKey {
				for keyshareIdx, pubshare := range shares {
					if eth2p0.BLSPubKey(pubshare) == share {
						return eth2p0.BLSPubKey{}, errors.New("mismatching validator client key share index, Mth key share submitted to Nth charon peer",
							z.Int("key_share_index", keyshareIdx-1), z.Int("charon_peer_index", shareIdx-1)) // 0-indexed
					}
				}
			}

			return eth2p0.BLSPubKey{}, errors.New("unknown public key")
		}

		if seenPubkeys != nil {
			seenPubkeys(core.PubKeyFrom48Bytes(key))
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
		feeRecipientFunc:   feeRecipientFunc,
		builderEnabled:     builderEnabled,
	}, nil
}

type Component struct {
	eth2Cl           eth2wrap.Client
	shareIdx         int
	insecureTest     bool
	feeRecipientFunc func(core.PubKey) string
	builderEnabled   core.BuilderEnabled

	// getVerifyShareFunc maps public shares (what the VC thinks as its public key)
	// to public keys (the DV root public key)
	getVerifyShareFunc func(core.PubKey) (tblsv2.PublicKey, error)
	// getPubShareFunc returns the public share for a root public key.
	getPubShareFunc func(eth2p0.BLSPubKey) (eth2p0.BLSPubKey, bool)
	// getPubKeyFunc returns the root public key for a public share.
	getPubKeyFunc func(eth2p0.BLSPubKey) (eth2p0.BLSPubKey, error)
	// sharesByKey contains this node's public shares (value) by root public (key)
	sharesByKey map[core.PubKey]core.PubKey

	// Registered input functions

	pubKeyByAttFunc           func(ctx context.Context, slot, commIdx, valCommIdx int64) (core.PubKey, error)
	awaitAttFunc              func(ctx context.Context, slot, commIdx int64) (*eth2p0.AttestationData, error)
	awaitBlockFunc            func(ctx context.Context, slot int64) (*eth2spec.VersionedBeaconBlock, error)
	awaitBlindedBlockFunc     func(ctx context.Context, slot int64) (*eth2api.VersionedBlindedBeaconBlock, error)
	awaitSyncContributionFunc func(ctx context.Context, slot, subcommIdx int64, beaconBlockRoot eth2p0.Root) (*altair.SyncCommitteeContribution, error)
	awaitAggAttFunc           func(ctx context.Context, slot int64, attestationRoot eth2p0.Root) (*eth2p0.Attestation, error)
	awaitAggSigDBFunc         func(context.Context, core.Duty, core.PubKey) (core.SignedData, error)
	dutyDefFunc               func(ctx context.Context, duty core.Duty) (core.DutyDefinitionSet, error)
	subs                      []func(context.Context, core.Duty, core.ParSignedDataSet) error
}

// RegisterAwaitBeaconBlock registers a function to query unsigned beacon block.
// It supports a single function, since it is an input of the component.
func (c *Component) RegisterAwaitBeaconBlock(fn func(ctx context.Context, slot int64) (*eth2spec.VersionedBeaconBlock, error)) {
	c.awaitBlockFunc = fn
}

// RegisterAwaitBlindedBeaconBlock registers a function to query unsigned blinded beacon block.
// It supports a single function, since it is an input of the component.
func (c *Component) RegisterAwaitBlindedBeaconBlock(fn func(ctx context.Context, slot int64) (*eth2api.VersionedBlindedBeaconBlock, error)) {
	c.awaitBlindedBlockFunc = fn
}

// RegisterAwaitAttestation registers a function to query attestation data.
// It only supports a single function, since it is an input of the component.
func (c *Component) RegisterAwaitAttestation(fn func(ctx context.Context, slot, commIdx int64) (*eth2p0.AttestationData, error)) {
	c.awaitAttFunc = fn
}

// RegisterAwaitSyncContribution registers a function to query sync contribution data.
// It only supports a single function, since it is an input of the component.
func (c *Component) RegisterAwaitSyncContribution(fn func(ctx context.Context, slot, subcommIdx int64, beaconBlockRoot eth2p0.Root) (*altair.SyncCommitteeContribution, error)) {
	c.awaitSyncContributionFunc = fn
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

// RegisterAwaitAggAttestation registers a function to query an aggregated attestation.
// It supports a single function, since it is an input of the component.
func (c *Component) RegisterAwaitAggAttestation(fn func(ctx context.Context, slot int64, attestationRoot eth2p0.Root) (*eth2p0.Attestation, error)) {
	c.awaitAggAttFunc = fn
}

// RegisterAwaitAggSigDB registers a function to query aggregated signed data from aggSigDB.
func (c *Component) RegisterAwaitAggSigDB(fn func(context.Context, core.Duty, core.PubKey) (core.SignedData, error)) {
	c.awaitAggSigDBFunc = fn
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

		parSigData := core.NewPartialAttestation(att, c.shareIdx)

		// Verify attestation signature
		err = c.verifyPartialSig(ctx, parSigData, pubkey)
		if err != nil {
			return err
		}

		// Encode partial signed data and add to a set
		set, ok := setsBySlot[slot]
		if !ok {
			set = make(core.ParSignedDataSet)
			setsBySlot[slot] = set
		}

		set[pubkey] = parSigData
	}

	// Send sets to subscriptions.
	for slot, set := range setsBySlot {
		duty := core.NewAttesterDuty(slot)
		ctx := log.WithCtx(ctx, z.Any("duty", duty))

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
func (c Component) BeaconBlockProposal(ctx context.Context, slot eth2p0.Slot, randao eth2p0.BLSSignature, _ []byte) (*eth2spec.VersionedBeaconBlock, error) {
	// Get proposer pubkey (this is a blocking query).
	pubkey, err := c.getProposerPubkey(ctx, core.NewProposerDuty(int64(slot)))
	if err != nil {
		return nil, err
	}

	epoch, err := eth2util.EpochFromSlot(ctx, c.eth2Cl, slot)
	if err != nil {
		return nil, err
	}

	sigEpoch := eth2util.SignedEpoch{
		Epoch:     epoch,
		Signature: randao,
	}

	duty := core.NewRandaoDuty(int64(slot))
	parSig := core.NewPartialSignedRandao(sigEpoch.Epoch, sigEpoch.Signature, c.shareIdx)

	// Verify randao signature
	err = c.verifyPartialSig(ctx, parSig, pubkey)
	if err != nil {
		return nil, err
	}

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
	// unsigned beacon block will be returned below:
	//  - Threshold number of VCs need to submit their partial randao reveals.
	//  - These signatures will be exchanged and aggregated.
	//  - The aggregated signature will be stored in AggSigDB.
	//  - Scheduler (in the meantime) will schedule a DutyProposer (to create a unsigned block).
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

func (c Component) SubmitBeaconBlock(ctx context.Context, block *eth2spec.VersionedSignedBeaconBlock) error {
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

	signedData, err := core.NewPartialVersionedSignedBeaconBlock(block, c.shareIdx)
	if err != nil {
		return err
	}

	// Verify block signature
	err = c.verifyPartialSig(ctx, signedData, pubkey)
	if err != nil {
		return err
	}

	log.Debug(ctx, "Beacon block submitted by validator client", z.Str("block_version", block.Version.String()))

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

	epoch, err := eth2util.EpochFromSlot(ctx, c.eth2Cl, slot)
	if err != nil {
		return nil, err
	}

	sigEpoch := eth2util.SignedEpoch{
		Epoch:     epoch,
		Signature: randao,
	}

	duty := core.NewRandaoDuty(int64(slot))
	parSig := core.NewPartialSignedRandao(sigEpoch.Epoch, sigEpoch.Signature, c.shareIdx)

	// Verify randao signature
	err = c.verifyPartialSig(ctx, parSig, pubkey)
	if err != nil {
		return nil, err
	}

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
	//  - Scheduler (in the meantime) will schedule a DutyBuilderProposer (to create a unsigned blinded block).
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

	signedData, err := core.NewPartialVersionedSignedBlindedBeaconBlock(block, c.shareIdx)
	if err != nil {
		return err
	}

	// Verify Blinded block signature
	err = c.verifyPartialSig(ctx, signedData, pubkey)
	if err != nil {
		return err
	}

	log.Debug(ctx, "Blinded beacon block submitted by validator client")

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

	signedData, err := core.NewPartialVersionedSignedValidatorRegistration(registration, c.shareIdx)
	if err != nil {
		return err
	}

	// Verify registration signature.
	err = c.verifyPartialSig(ctx, signedData, pubkey)
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
	if len(registrations) == 0 {
		return nil // Nothing to do
	}

	slot, err := c.slotFromTimestamp(ctx, time.Now())
	if err != nil {
		return err
	}

	// Swallow unexpected validator registrations from VCs (for ex: vouch)
	if !c.builderEnabled(int64(slot)) {
		return nil
	}

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

	parSigData := core.NewPartialSignedVoluntaryExit(exit, c.shareIdx)

	// Verify voluntary exit signature
	err = c.verifyPartialSig(ctx, parSigData, pubkey)
	if err != nil {
		return err
	}

	log.Info(ctx, "Voluntary exit submitted by validator client")

	for _, sub := range c.subs {
		// No need to clone since sub auto clones.
		err := sub(ctx, duty, core.ParSignedDataSet{pubkey: parSigData})
		if err != nil {
			return err
		}
	}

	return nil
}

// AggregateBeaconCommitteeSelections returns aggregate beacon committee selection proofs.
func (c Component) AggregateBeaconCommitteeSelections(ctx context.Context, selections []*eth2exp.BeaconCommitteeSelection) ([]*eth2exp.BeaconCommitteeSelection, error) {
	var valIdxs []eth2p0.ValidatorIndex
	for _, selection := range selections {
		valIdxs = append(valIdxs, selection.ValidatorIndex)
	}

	vals, err := c.eth2Cl.Validators(ctx, "head", valIdxs)
	if err != nil {
		return nil, err
	}

	psigsBySlot := make(map[eth2p0.Slot]core.ParSignedDataSet)
	for _, selection := range selections {
		eth2Pubkey, err := vals[selection.ValidatorIndex].PubKey(ctx)
		if err != nil {
			return nil, err
		}

		pubkey, err := core.PubKeyFromBytes(eth2Pubkey[:])
		if err != nil {
			return nil, err
		}

		parSigData := core.NewPartialSignedBeaconCommitteeSelection(selection, c.shareIdx)

		// Verify slot signature.
		err = c.verifyPartialSig(ctx, parSigData, pubkey)
		if err != nil {
			return nil, err
		}

		_, ok := psigsBySlot[selection.Slot]
		if !ok {
			psigsBySlot[selection.Slot] = make(core.ParSignedDataSet)
		}

		psigsBySlot[selection.Slot][pubkey] = parSigData
	}

	for slot, data := range psigsBySlot {
		duty := core.NewPrepareAggregatorDuty(int64(slot))
		for _, sub := range c.subs {
			err = sub(ctx, duty, data)
			if err != nil {
				return nil, err
			}
		}
	}

	return c.getAggregateBeaconCommSelection(ctx, psigsBySlot)
}

// AggregateAttestation returns the aggregate attestation for the given attestation root.
// It does a blocking query to DutyAggregator unsigned data from dutyDB.
func (c Component) AggregateAttestation(ctx context.Context, slot eth2p0.Slot, attestationDataRoot eth2p0.Root) (*eth2p0.Attestation, error) {
	return c.awaitAggAttFunc(ctx, int64(slot), attestationDataRoot)
}

// SubmitAggregateAttestations receives partially signed aggregateAndProofs.
// - It verifies partial signature on AggregateAndProof.
// - It then calls all the subscribers for further steps on partially signed aggregate and proof.
func (c Component) SubmitAggregateAttestations(ctx context.Context, aggregateAndProofs []*eth2p0.SignedAggregateAndProof) error {
	var valIdxs []eth2p0.ValidatorIndex
	for _, agg := range aggregateAndProofs {
		valIdxs = append(valIdxs, agg.Message.AggregatorIndex)
	}

	vals, err := c.eth2Cl.Validators(ctx, "head", valIdxs)
	if err != nil {
		return err
	}

	psigsBySlot := make(map[eth2p0.Slot]core.ParSignedDataSet)
	for _, agg := range aggregateAndProofs {
		slot := agg.Message.Aggregate.Data.Slot
		eth2Pubkey, err := vals[agg.Message.AggregatorIndex].PubKey(ctx)
		if err != nil {
			return err
		}

		pk, err := core.PubKeyFromBytes(eth2Pubkey[:])
		if err != nil {
			return err
		}

		// Verify inner selection proof (outcome of DutyPrepareAggregator).
		if !c.insecureTest {
			err = signing.VerifyAggregateAndProofSelection(ctx, c.eth2Cl, tblsv2.PublicKey(eth2Pubkey), agg.Message)
			if err != nil {
				return err
			}
		}

		parSigData := core.NewPartialSignedAggregateAndProof(agg, c.shareIdx)

		// Verify outer partial signature.
		err = c.verifyPartialSig(ctx, parSigData, pk)
		if err != nil {
			return err
		}

		_, ok := psigsBySlot[slot]
		if !ok {
			psigsBySlot[slot] = make(core.ParSignedDataSet)
		}

		psigsBySlot[slot][pk] = parSigData
	}

	for slot, data := range psigsBySlot {
		duty := core.NewAggregatorDuty(int64(slot))
		for _, sub := range c.subs {
			err = sub(ctx, duty, data)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// SyncCommitteeContribution returns sync committee contribution data for the given subcommittee and beacon block root.
func (c Component) SyncCommitteeContribution(ctx context.Context, slot eth2p0.Slot, subcommitteeIndex uint64, beaconBlockRoot eth2p0.Root) (*altair.SyncCommitteeContribution, error) {
	return c.awaitSyncContributionFunc(ctx, int64(slot), int64(subcommitteeIndex), beaconBlockRoot)
}

// SubmitSyncCommitteeMessages receives the partially signed altair.SyncCommitteeMessage.
func (c Component) SubmitSyncCommitteeMessages(ctx context.Context, messages []*altair.SyncCommitteeMessage) error {
	var valIdxs []eth2p0.ValidatorIndex
	for _, msg := range messages {
		valIdxs = append(valIdxs, msg.ValidatorIndex)
	}

	vals, err := c.eth2Cl.Validators(ctx, "head", valIdxs)
	if err != nil {
		return err
	}

	psigsBySlot := make(map[eth2p0.Slot]core.ParSignedDataSet)
	for _, msg := range messages {
		slot := msg.Slot
		eth2Pubkey, err := vals[msg.ValidatorIndex].PubKey(ctx)
		if err != nil {
			return err
		}

		pk, err := core.PubKeyFromBytes(eth2Pubkey[:])
		if err != nil {
			return err
		}

		parSigData := core.NewPartialSignedSyncMessage(msg, c.shareIdx)
		err = c.verifyPartialSig(ctx, parSigData, pk)
		if err != nil {
			return err
		}

		_, ok := psigsBySlot[slot]
		if !ok {
			psigsBySlot[slot] = make(core.ParSignedDataSet)
		}

		psigsBySlot[slot][pk] = core.NewPartialSignedSyncMessage(msg, c.shareIdx)
	}

	for slot, data := range psigsBySlot {
		duty := core.NewSyncMessageDuty(int64(slot))
		for _, sub := range c.subs {
			err = sub(ctx, duty, data)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// SubmitSyncCommitteeContributions receives partially signed altair.SignedContributionAndProof.
// - It verifies partial signature on ContributionAndProof.
// - It then calls all the subscribers for further steps on partially signed contribution and proof.
func (c Component) SubmitSyncCommitteeContributions(ctx context.Context, contributionAndProofs []*altair.SignedContributionAndProof) error {
	var valIdxs []eth2p0.ValidatorIndex
	for _, c := range contributionAndProofs {
		valIdxs = append(valIdxs, c.Message.AggregatorIndex)
	}

	vals, err := c.eth2Cl.Validators(ctx, "head", valIdxs)
	if err != nil {
		return err
	}

	psigsBySlot := make(map[eth2p0.Slot]core.ParSignedDataSet)
	for _, contrib := range contributionAndProofs {
		var (
			slot = contrib.Message.Contribution.Slot
			vIdx = contrib.Message.AggregatorIndex
		)
		eth2Pubkey, err := vals[vIdx].PubKey(ctx)
		if err != nil {
			return err
		}

		pk, err := core.PubKeyFromBytes(eth2Pubkey[:])
		if err != nil {
			return err
		}

		// Verify inner selection proof.
		if !c.insecureTest {
			msg := core.NewSyncContributionAndProof(contrib.Message)
			err = core.VerifyEth2SignedData(ctx, c.eth2Cl, msg, tblsv2.PublicKey(eth2Pubkey))
			if err != nil {
				return err
			}
		}

		// Verify outer partial signature.
		parSigData := core.NewPartialSignedSyncContributionAndProof(contrib, c.shareIdx)
		err = c.verifyPartialSig(ctx, parSigData, pk)
		if err != nil {
			return err
		}

		_, ok := psigsBySlot[slot]
		if !ok {
			psigsBySlot[slot] = make(core.ParSignedDataSet)
		}

		psigsBySlot[slot][pk] = parSigData
	}

	for slot, data := range psigsBySlot {
		duty := core.NewSyncContributionDuty(int64(slot))
		for _, sub := range c.subs {
			err = sub(ctx, duty, data)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// AggregateSyncCommitteeSelections returns aggregate sync committee selection proofs.
func (c Component) AggregateSyncCommitteeSelections(ctx context.Context, partialSelections []*eth2exp.SyncCommitteeSelection) ([]*eth2exp.SyncCommitteeSelection, error) {
	var valIdxs []eth2p0.ValidatorIndex
	for _, selection := range partialSelections {
		valIdxs = append(valIdxs, selection.ValidatorIndex)
	}

	vals, err := c.eth2Cl.Validators(ctx, "head", valIdxs)
	if err != nil {
		return nil, err
	}

	psigsBySlot := make(map[eth2p0.Slot]core.ParSignedDataSet)
	for _, selection := range partialSelections {
		eth2Pubkey, err := vals[selection.ValidatorIndex].PubKey(ctx)
		if err != nil {
			return nil, err
		}

		pubkey, err := core.PubKeyFromBytes(eth2Pubkey[:])
		if err != nil {
			return nil, err
		}

		parSigData := core.NewPartialSignedSyncCommitteeSelection(selection, c.shareIdx)

		// Verify selection proof.
		err = c.verifyPartialSig(ctx, parSigData, pubkey)
		if err != nil {
			return nil, err
		}

		_, ok := psigsBySlot[selection.Slot]
		if !ok {
			psigsBySlot[selection.Slot] = make(core.ParSignedDataSet)
		}

		psigsBySlot[selection.Slot][pubkey] = parSigData
	}

	for slot, data := range psigsBySlot {
		duty := core.NewPrepareSyncContributionDuty(int64(slot))
		for _, sub := range c.subs {
			err = sub(ctx, duty, data)
			if err != nil {
				return nil, err
			}
		}
	}

	return c.getAggregateSyncCommSelection(ctx, psigsBySlot)
}

func (c Component) ProposerDuties(ctx context.Context, epoch eth2p0.Epoch, validatorIndices []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error) {
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

func (c Component) SyncCommitteeDuties(ctx context.Context, epoch eth2p0.Epoch, validatorIndices []eth2p0.ValidatorIndex) ([]*eth2v1.SyncCommitteeDuty, error) {
	duties, err := c.eth2Cl.SyncCommitteeDuties(ctx, epoch, validatorIndices)
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

// NodeVersion returns the current version of charon.
func (Component) NodeVersion(context.Context) (string, error) {
	commitSHA, _ := version.GitCommit()

	return fmt.Sprintf("obolnetwork/charon/%s-%s/%s-%s", version.Version, commitSHA, runtime.GOARCH, runtime.GOOS), nil
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

func (c Component) verifyPartialSig(ctx context.Context, parSig core.ParSignedData, pubkey core.PubKey) error {
	if c.insecureTest {
		return nil
	}

	pubshare, err := c.getVerifyShareFunc(pubkey)
	if err != nil {
		return err
	}

	eth2Signed, ok := parSig.SignedData.(core.Eth2SignedData)
	if !ok {
		return errors.New("invalid eth2 signed data")
	}

	return core.VerifyEth2SignedData(ctx, c.eth2Cl, eth2Signed, pubshare)
}

func (c Component) getAggregateBeaconCommSelection(ctx context.Context, psigsBySlot map[eth2p0.Slot]core.ParSignedDataSet) ([]*eth2exp.BeaconCommitteeSelection, error) {
	var resp []*eth2exp.BeaconCommitteeSelection
	for slot, data := range psigsBySlot {
		duty := core.NewPrepareAggregatorDuty(int64(slot))
		for pk := range data {
			// Query aggregated subscription from aggsigdb for each duty and public key (this is blocking).
			s, err := c.awaitAggSigDBFunc(ctx, duty, pk)
			if err != nil {
				return nil, err
			}

			sub, ok := s.(core.BeaconCommitteeSelection)
			if !ok {
				return nil, errors.New("invalid beacon committee selection")
			}

			resp = append(resp, &sub.BeaconCommitteeSelection)
		}
	}

	return resp, nil
}

func (c Component) getAggregateSyncCommSelection(ctx context.Context, psigsBySlot map[eth2p0.Slot]core.ParSignedDataSet) ([]*eth2exp.SyncCommitteeSelection, error) {
	var resp []*eth2exp.SyncCommitteeSelection
	for slot, data := range psigsBySlot {
		duty := core.NewPrepareSyncContributionDuty(int64(slot))
		for pk := range data {
			// Query aggregated sync committee selection from aggsigdb for each duty and public key (this is blocking).
			s, err := c.awaitAggSigDBFunc(ctx, duty, pk)
			if err != nil {
				return nil, err
			}

			sub, ok := s.(core.SyncCommitteeSelection)
			if !ok {
				return nil, errors.New("invalid sync committee selection")
			}

			resp = append(resp, &sub.SyncCommitteeSelection)
		}
	}

	return resp, nil
}
