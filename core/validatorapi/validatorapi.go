// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package validatorapi

import (
	"context"
	"fmt"
	"math/big"
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
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

const (
	gasLimit    = 30000000
	zeroAddress = "0x0000000000000000000000000000000000000000"
)

// SlotFromTimestamp returns the Ethereum slot associated to a timestamp, given the genesis configuration fetched
// from client.
func SlotFromTimestamp(ctx context.Context, client eth2wrap.Client, timestamp time.Time) (eth2p0.Slot, error) {
	genesis, err := client.GenesisTime(ctx)
	if err != nil {
		return 0, err
	} else if timestamp.Before(genesis) {
		// if timestamp is in the past (can happen in testing scenarios, there's no strict form of checking on it),  fall back on current timestamp.
		nextTimestamp := time.Now()

		log.Info(
			ctx,
			"timestamp before genesis, defaulting to current timestamp",
			z.I64("genesis_timestamp", genesis.Unix()),
			z.I64("overridden_timestamp", timestamp.Unix()),
			z.I64("new_timestamp", nextTimestamp.Unix()),
		)

		timestamp = nextTimestamp
	}

	eth2Resp, err := client.Spec(ctx, &eth2api.SpecOpts{})
	if err != nil {
		return 0, err
	}

	slotDuration, ok := eth2Resp.Data["SECONDS_PER_SLOT"].(time.Duration)
	if !ok {
		return 0, errors.New("fetch slot duration")
	}

	delta := timestamp.Sub(genesis)

	return eth2p0.Slot(delta / slotDuration), nil
}

// NewComponentInsecure returns a new instance of the validator API core workflow component
// that does not perform signature verification.
func NewComponentInsecure(_ *testing.T, eth2Cl eth2wrap.Client, shareIdx int) (*Component, error) {
	return &Component{
		eth2Cl:         eth2Cl,
		shareIdx:       shareIdx,
		builderEnabled: func(uint64) bool { return false },
		insecureTest:   true,
	}, nil
}

// NewComponent returns a new instance of the validator API core workflow component.
func NewComponent(eth2Cl eth2wrap.Client, allPubSharesByKey map[core.PubKey]map[int]tbls.PublicKey,
	shareIdx int, feeRecipientFunc func(core.PubKey) string, builderEnabled core.BuilderEnabled, seenPubkeys func(core.PubKey),
) (*Component, error) {
	var (
		sharesByKey     = make(map[eth2p0.BLSPubKey]eth2p0.BLSPubKey)
		keysByShare     = make(map[eth2p0.BLSPubKey]eth2p0.BLSPubKey)
		sharesByCoreKey = make(map[core.PubKey]tbls.PublicKey)
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
		pubkey, err := tblsconv.PubkeyFromBytes(cpBytes)
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

	getVerifyShareFunc := func(pubkey core.PubKey) (tbls.PublicKey, error) {
		pubshare, ok := sharesByCoreKey[pubkey]
		if !ok {
			return tbls.PublicKey{}, errors.New("unknown public key")
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
		swallowRegFilter:   log.Filter(),
	}, nil
}

type Component struct {
	eth2Cl           eth2wrap.Client
	shareIdx         int
	insecureTest     bool
	feeRecipientFunc func(core.PubKey) string
	builderEnabled   core.BuilderEnabled
	swallowRegFilter z.Field

	// getVerifyShareFunc maps public shares (what the VC thinks as its public key)
	// to public keys (the DV root public key)
	getVerifyShareFunc func(core.PubKey) (tbls.PublicKey, error)
	// getPubShareFunc returns the public share for a root public key.
	getPubShareFunc func(eth2p0.BLSPubKey) (eth2p0.BLSPubKey, bool)
	// getPubKeyFunc returns the root public key for a public share.
	getPubKeyFunc func(eth2p0.BLSPubKey) (eth2p0.BLSPubKey, error)
	// sharesByKey contains this node's public shares (value) by root public (key)
	sharesByKey map[core.PubKey]core.PubKey

	// Registered input functions

	pubKeyByAttFunc           func(ctx context.Context, slot, commIdx, valCommIdx uint64) (core.PubKey, error)
	awaitAttFunc              func(ctx context.Context, slot, commIdx uint64) (*eth2p0.AttestationData, error)
	awaitProposalFunc         func(ctx context.Context, slot uint64) (*eth2api.VersionedProposal, error)
	awaitSyncContributionFunc func(ctx context.Context, slot, subcommIdx uint64, beaconBlockRoot eth2p0.Root) (*altair.SyncCommitteeContribution, error)
	awaitAggAttFunc           func(ctx context.Context, slot uint64, attestationRoot eth2p0.Root) (*eth2p0.Attestation, error)
	awaitAggSigDBFunc         func(context.Context, core.Duty, core.PubKey) (core.SignedData, error)
	dutyDefFunc               func(ctx context.Context, duty core.Duty) (core.DutyDefinitionSet, error)
	subs                      []func(context.Context, core.Duty, core.ParSignedDataSet) error
}

// RegisterAwaitProposal registers a function to query unsigned beacon block proposals by providing necessary options.
// It supports a single function, since it is an input of the component.
func (c *Component) RegisterAwaitProposal(fn func(ctx context.Context, slot uint64) (*eth2api.VersionedProposal, error)) {
	c.awaitProposalFunc = fn
}

// RegisterAwaitAttestation registers a function to query attestation data.
// It only supports a single function, since it is an input of the component.
func (c *Component) RegisterAwaitAttestation(fn func(ctx context.Context, slot, commIdx uint64) (*eth2p0.AttestationData, error)) {
	c.awaitAttFunc = fn
}

// RegisterAwaitSyncContribution registers a function to query sync contribution data.
// It only supports a single function, since it is an input of the component.
func (c *Component) RegisterAwaitSyncContribution(fn func(ctx context.Context, slot, subcommIdx uint64, beaconBlockRoot eth2p0.Root) (*altair.SyncCommitteeContribution, error)) {
	c.awaitSyncContributionFunc = fn
}

// RegisterPubKeyByAttestation registers a function to query pubkeys by attestation.
// It only supports a single function, since it is an input of the component.
func (c *Component) RegisterPubKeyByAttestation(fn func(ctx context.Context, slot, commIdx, valCommIdx uint64) (core.PubKey, error)) {
	c.pubKeyByAttFunc = fn
}

// RegisterGetDutyDefinition registers a function to query duty definitions.
// It supports a single function, since it is an input of the component.
func (c *Component) RegisterGetDutyDefinition(fn func(ctx context.Context, duty core.Duty) (core.DutyDefinitionSet, error)) {
	c.dutyDefFunc = fn
}

// RegisterAwaitAggAttestation registers a function to query an aggregated attestation.
// It supports a single function, since it is an input of the component.
func (c *Component) RegisterAwaitAggAttestation(fn func(ctx context.Context, slot uint64, attestationRoot eth2p0.Root) (*eth2p0.Attestation, error)) {
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
func (c Component) AttestationData(parent context.Context, opts *eth2api.AttestationDataOpts) (*eth2api.Response[*eth2p0.AttestationData], error) {
	ctx, span := core.StartDutyTrace(parent, core.NewAttesterDuty(uint64(opts.Slot)), "core/validatorapi.AttestationData")
	defer span.End()

	att, err := c.awaitAttFunc(ctx, uint64(opts.Slot), uint64(opts.CommitteeIndex))
	if err != nil {
		return nil, err
	}

	return wrapResponse(att), nil
}

// SubmitAttestations implements the eth2client.AttestationsSubmitter for the router.
func (c Component) SubmitAttestations(ctx context.Context, attestations []*eth2p0.Attestation) error {
	duty := core.NewAttesterDuty(uint64(attestations[0].Data.Slot))
	if len(attestations) > 0 {
		// Pick the first attestation slot to use as trace root.
		var span trace.Span
		ctx, span = core.StartDutyTrace(ctx, duty, "core/validatorapi.SubmitAttestations")
		defer span.End()
	}

	setsBySlot := make(map[uint64]core.ParSignedDataSet)
	for _, att := range attestations {
		slot := uint64(att.Data.Slot)

		// Determine the validator that sent this by mapping values from original AttestationDuty via the dutyDB
		indices := att.AggregationBits.BitIndices()
		if len(indices) != 1 {
			return errors.New("unexpected number of aggregation bits",
				z.Str("aggbits", fmt.Sprintf("%#x", []byte(att.AggregationBits))))
		}

		pubkey, err := c.pubKeyByAttFunc(ctx, slot, uint64(att.Data.Index), uint64(indices[0]))
		if err != nil {
			return errors.Wrap(err, "failed to find pubkey", z.U64("slot", slot),
				z.Int("commIdx", int(att.Data.Index)), z.Int("valCommIdx", indices[0]))
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

func (c Component) Proposal(ctx context.Context, opts *eth2api.ProposalOpts) (*eth2api.Response[*eth2api.VersionedProposal], error) {
	// Get proposer pubkey (this is a blocking query).
	pubkey, err := c.getProposerPubkey(ctx, core.NewProposerDuty(uint64(opts.Slot)))
	if err != nil {
		return nil, err
	}

	epoch, err := eth2util.EpochFromSlot(ctx, c.eth2Cl, opts.Slot)
	if err != nil {
		return nil, err
	}

	sigEpoch := eth2util.SignedEpoch{
		Epoch:     epoch,
		Signature: opts.RandaoReveal,
	}

	duty := core.NewRandaoDuty(uint64(opts.Slot))
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

	// Query unsigned proposal (this is blocking).
	proposal, err := c.awaitProposalFunc(ctx, uint64(opts.Slot))
	if err != nil {
		return nil, err
	}

	// We do not persist this v3-specific data in the pipeline,
	// but to comply with the API, we need to return non-nil values,
	// and these should be unified across all nodes.
	proposal.ConsensusValue = big.NewInt(1)
	proposal.ExecutionValue = big.NewInt(1)

	return wrapResponse(proposal), nil
}

func (c Component) SubmitProposal(ctx context.Context, opts *eth2api.SubmitProposalOpts) error {
	slot, err := opts.Proposal.Slot()
	if err != nil {
		return err
	}

	pubkey, err := c.getProposerPubkey(ctx, core.NewProposerDuty(uint64(slot)))
	if err != nil {
		return err
	}

	// Save Partially Signed Block to ParSigDB
	duty := core.NewProposerDuty(uint64(slot))
	ctx = log.WithCtx(ctx, z.Any("duty", duty))

	signedData, err := core.NewPartialVersionedSignedProposal(opts.Proposal, c.shareIdx)
	if err != nil {
		return err
	}

	// Verify proposal signature
	err = c.verifyPartialSig(ctx, signedData, pubkey)
	if err != nil {
		return err
	}

	log.Debug(ctx, "Beacon proposal submitted by validator client", z.Str("block_version", opts.Proposal.Version.String()))

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

func (c Component) SubmitBlindedProposal(ctx context.Context, opts *eth2api.SubmitBlindedProposalOpts) error {
	slot, err := opts.Proposal.Slot()
	if err != nil {
		return err
	}

	pubkey, err := c.getProposerPubkey(ctx, core.NewProposerDuty(uint64(slot)))
	if err != nil {
		return err
	}

	// Save Partially Signed Blinded Block to ParSigDB
	duty := core.NewProposerDuty(uint64(slot))
	ctx = log.WithCtx(ctx, z.Any("duty", duty))

	// Translate old blinded block request to new VersionedSignedProposal universal type.

	signedBlock := new(eth2api.VersionedSignedProposal)
	signedBlock.Version = opts.Proposal.Version
	signedBlock.Blinded = true

	switch signedBlock.Version {
	case eth2spec.DataVersionBellatrix:
		signedBlock.BellatrixBlinded = opts.Proposal.Bellatrix
	case eth2spec.DataVersionCapella:
		signedBlock.CapellaBlinded = opts.Proposal.Capella
	case eth2spec.DataVersionDeneb:
		signedBlock.DenebBlinded = opts.Proposal.Deneb
	default:
		return errors.New("invalid blinded block")
	}

	signedData, err := core.NewPartialVersionedSignedProposal(signedBlock, c.shareIdx)
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
	// Note this should be the group pubkey
	eth2Pubkey, err := registration.PubKey()
	if err != nil {
		return err
	}

	pubkey, err := core.PubKeyFromBytes(eth2Pubkey[:])
	if err != nil {
		return err
	}

	if _, ok := c.getPubShareFunc(eth2Pubkey); !ok {
		log.Debug(ctx, "Swallowing non-dv registration, "+
			"this is a known limitation for many validator clients", z.Any("pubkey", pubkey), c.swallowRegFilter)

		return nil
	}

	timestamp, err := registration.Timestamp()
	if err != nil {
		return err
	}
	slot, err := SlotFromTimestamp(ctx, c.eth2Cl, timestamp)
	if err != nil {
		return err
	}

	duty := core.NewBuilderRegistrationDuty(uint64(slot))
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

	slot, err := SlotFromTimestamp(ctx, c.eth2Cl, time.Now())
	if err != nil {
		return err
	}

	// Swallow unexpected validator registrations from VCs (for ex: vouch)
	if !c.builderEnabled(uint64(slot)) {
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
	vals, err := c.eth2Cl.ActiveValidators(ctx)
	if err != nil {
		return err
	}

	eth2Pubkey, ok := vals[exit.Message.ValidatorIndex]
	if !ok {
		return errors.New("validator not found")
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

	duty := core.NewVoluntaryExit(slotsPerEpoch * uint64(exit.Message.Epoch))
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
	vals, err := c.eth2Cl.ActiveValidators(ctx)
	if err != nil {
		return nil, err
	}

	psigsBySlot := make(map[eth2p0.Slot]core.ParSignedDataSet)
	for _, selection := range selections {
		eth2Pubkey, ok := vals[selection.ValidatorIndex]
		if !ok {
			return nil, errors.New("validator not found", z.Any("provided", selection.ValidatorIndex), z.Any("expected", vals.Indices()))
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

		_, ok = psigsBySlot[selection.Slot]
		if !ok {
			psigsBySlot[selection.Slot] = make(core.ParSignedDataSet)
		}

		psigsBySlot[selection.Slot][pubkey] = parSigData
	}

	for slot, data := range psigsBySlot {
		duty := core.NewPrepareAggregatorDuty(uint64(slot))
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
func (c Component) AggregateAttestation(ctx context.Context, opts *eth2api.AggregateAttestationOpts) (*eth2api.Response[*eth2p0.Attestation], error) {
	aggAtt, err := c.awaitAggAttFunc(ctx, uint64(opts.Slot), opts.AttestationDataRoot)
	if err != nil {
		return nil, err
	}

	return wrapResponse(aggAtt), nil
}

// SubmitAggregateAttestations receives partially signed aggregateAndProofs.
// - It verifies partial signature on AggregateAndProof.
// - It then calls all the subscribers for further steps on partially signed aggregate and proof.
func (c Component) SubmitAggregateAttestations(ctx context.Context, aggregateAndProofs []*eth2p0.SignedAggregateAndProof) error {
	vals, err := c.eth2Cl.ActiveValidators(ctx)
	if err != nil {
		return err
	}

	psigsBySlot := make(map[eth2p0.Slot]core.ParSignedDataSet)
	for _, agg := range aggregateAndProofs {
		slot := agg.Message.Aggregate.Data.Slot
		eth2Pubkey, ok := vals[agg.Message.AggregatorIndex]
		if !ok {
			return errors.New("validator not found")
		}

		pk, err := core.PubKeyFromBytes(eth2Pubkey[:])
		if err != nil {
			return err
		}

		// Verify inner selection proof (outcome of DutyPrepareAggregator).
		if !c.insecureTest {
			err = signing.VerifyAggregateAndProofSelection(ctx, c.eth2Cl, tbls.PublicKey(eth2Pubkey), agg.Message)
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

		_, ok = psigsBySlot[slot]
		if !ok {
			psigsBySlot[slot] = make(core.ParSignedDataSet)
		}

		psigsBySlot[slot][pk] = parSigData
	}

	for slot, data := range psigsBySlot {
		duty := core.NewAggregatorDuty(uint64(slot))
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
func (c Component) SyncCommitteeContribution(ctx context.Context, opts *eth2api.SyncCommitteeContributionOpts) (*eth2api.Response[*altair.SyncCommitteeContribution], error) {
	contrib, err := c.awaitSyncContributionFunc(ctx, uint64(opts.Slot), opts.SubcommitteeIndex, opts.BeaconBlockRoot)
	if err != nil {
		return nil, err
	}

	return wrapResponse(contrib), nil
}

// SubmitSyncCommitteeMessages receives the partially signed altair.SyncCommitteeMessage.
func (c Component) SubmitSyncCommitteeMessages(ctx context.Context, messages []*altair.SyncCommitteeMessage) error {
	vals, err := c.eth2Cl.ActiveValidators(ctx)
	if err != nil {
		return err
	}

	psigsBySlot := make(map[eth2p0.Slot]core.ParSignedDataSet)
	for _, msg := range messages {
		slot := msg.Slot
		eth2Pubkey, ok := vals[msg.ValidatorIndex]
		if !ok {
			return errors.New("validator not found")
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

		_, ok = psigsBySlot[slot]
		if !ok {
			psigsBySlot[slot] = make(core.ParSignedDataSet)
		}

		psigsBySlot[slot][pk] = core.NewPartialSignedSyncMessage(msg, c.shareIdx)
	}

	for slot, data := range psigsBySlot {
		duty := core.NewSyncMessageDuty(uint64(slot))
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
	vals, err := c.eth2Cl.ActiveValidators(ctx)
	if err != nil {
		return err
	}

	psigsBySlot := make(map[eth2p0.Slot]core.ParSignedDataSet)
	for _, contrib := range contributionAndProofs {
		var (
			slot = contrib.Message.Contribution.Slot
			vIdx = contrib.Message.AggregatorIndex
		)
		eth2Pubkey, ok := vals[vIdx]
		if !ok {
			return errors.New("validator not found")
		}

		pk, err := core.PubKeyFromBytes(eth2Pubkey[:])
		if err != nil {
			return err
		}

		// Verify inner selection proof.
		if !c.insecureTest {
			msg := core.NewSyncContributionAndProof(contrib.Message)
			err = core.VerifyEth2SignedData(ctx, c.eth2Cl, msg, tbls.PublicKey(eth2Pubkey))
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

		_, ok = psigsBySlot[slot]
		if !ok {
			psigsBySlot[slot] = make(core.ParSignedDataSet)
		}

		psigsBySlot[slot][pk] = parSigData
	}

	for slot, data := range psigsBySlot {
		duty := core.NewSyncContributionDuty(uint64(slot))
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
	vals, err := c.eth2Cl.ActiveValidators(ctx)
	if err != nil {
		return nil, err
	}

	psigsBySlot := make(map[eth2p0.Slot]core.ParSignedDataSet)
	for _, selection := range partialSelections {
		eth2Pubkey, ok := vals[selection.ValidatorIndex]
		if !ok {
			return nil, errors.New("validator not found")
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

		_, ok = psigsBySlot[selection.Slot]
		if !ok {
			psigsBySlot[selection.Slot] = make(core.ParSignedDataSet)
		}

		psigsBySlot[selection.Slot][pubkey] = parSigData
	}

	for slot, data := range psigsBySlot {
		duty := core.NewPrepareSyncContributionDuty(uint64(slot))
		for _, sub := range c.subs {
			err = sub(ctx, duty, data)
			if err != nil {
				return nil, err
			}
		}
	}

	return c.getAggregateSyncCommSelection(ctx, psigsBySlot)
}

// ProposerDuties obtains proposer duties for the given options.
func (c Component) ProposerDuties(ctx context.Context, opts *eth2api.ProposerDutiesOpts) (*eth2api.Response[[]*eth2v1.ProposerDuty], error) {
	eth2Resp, err := c.eth2Cl.ProposerDuties(ctx, opts)
	if err != nil {
		return nil, err
	}
	duties := eth2Resp.Data

	// Replace root public keys with public shares
	for i := 0; i < len(duties); i++ {
		if duties[i] == nil {
			return nil, errors.New("proposer duty cannot be nil")
		}

		pubshare, ok := c.getPubShareFunc(duties[i].PubKey)
		if !ok {
			// Ignore unknown validators since ProposerDuties returns ALL proposers for the epoch if validatorIndices is empty.
			continue
		}
		duties[i].PubKey = pubshare
	}

	return wrapResponseWithMetadata(duties, eth2Resp.Metadata), nil
}

func (c Component) AttesterDuties(ctx context.Context, opts *eth2api.AttesterDutiesOpts) (*eth2api.Response[[]*eth2v1.AttesterDuty], error) {
	eth2Resp, err := c.eth2Cl.AttesterDuties(ctx, opts)
	if err != nil {
		return nil, err
	}
	duties := eth2Resp.Data

	// Replace root public keys with public shares.
	for i := 0; i < len(duties); i++ {
		if duties[i] == nil {
			return nil, errors.New("attester duty cannot be nil")
		}

		pubshare, ok := c.getPubShareFunc(duties[i].PubKey)
		if !ok {
			return nil, errors.New("pubshare not found")
		}
		duties[i].PubKey = pubshare
	}

	return wrapResponseWithMetadata(duties, eth2Resp.Metadata), nil
}

// SyncCommitteeDuties obtains sync committee duties. If validatorIndices is nil it will return all duties for the given epoch.
func (c Component) SyncCommitteeDuties(ctx context.Context, opts *eth2api.SyncCommitteeDutiesOpts) (*eth2api.Response[[]*eth2v1.SyncCommitteeDuty], error) {
	eth2Resp, err := c.eth2Cl.SyncCommitteeDuties(ctx, opts)
	if err != nil {
		return nil, err
	}
	duties := eth2Resp.Data

	// Replace root public keys with public shares.
	for i := 0; i < len(duties); i++ {
		if duties[i] == nil {
			return nil, errors.New("sync committee duty cannot be nil")
		}

		pubshare, ok := c.getPubShareFunc(duties[i].PubKey)
		if !ok {
			return nil, errors.New("pubshare not found")
		}
		duties[i].PubKey = pubshare
	}

	return wrapResponse(duties), nil
}

func (c Component) Validators(ctx context.Context, opts *eth2api.ValidatorsOpts) (*eth2api.Response[map[eth2p0.ValidatorIndex]*eth2v1.Validator], error) {
	if len(opts.PubKeys) == 0 && len(opts.Indices) == 0 {
		// fetch all validators
		eth2Resp, err := c.eth2Cl.Validators(ctx, opts)
		if err != nil {
			return nil, err
		}

		convertedVals, err := c.convertValidators(eth2Resp.Data, len(opts.Indices) == 0)
		if err != nil {
			return nil, err
		}

		return wrapResponse(convertedVals), nil
	}

	cachedValidators, err := c.eth2Cl.CompleteValidators(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "can't fetch complete validators cache")
	}

	// Match pubshares to the associated full validator public key
	var pubkeys []eth2p0.BLSPubKey
	for _, pubshare := range opts.PubKeys {
		pubkey, err := c.getPubKeyFunc(pubshare)
		if err != nil {
			return nil, err
		}

		pubkeys = append(pubkeys, pubkey)
	}

	var (
		nonCachedPubkeys []eth2p0.BLSPubKey
		ret              = make(map[eth2p0.ValidatorIndex]*eth2v1.Validator)
	)

	// Index cached validators by their pubkey for quicker lookup
	cvMap := make(map[eth2p0.BLSPubKey]eth2p0.ValidatorIndex)
	for vIdx, cpubkey := range cachedValidators {
		cvMap[cpubkey.Validator.PublicKey] = vIdx
	}

	// Check if any of the pubkeys passed as argument are already cached
	for _, ncVal := range pubkeys {
		vIdx, ok := cvMap[ncVal]
		if !ok {
			nonCachedPubkeys = append(nonCachedPubkeys, ncVal)
			continue
		}

		ret[vIdx] = cachedValidators[vIdx]
	}

	if len(nonCachedPubkeys) != 0 || len(opts.Indices) > 0 {
		log.Debug(ctx, "Requesting validators to upstream beacon node", z.Int("non_cached_pubkeys_amount", len(nonCachedPubkeys)), z.Int("indices", len(opts.Indices)))

		opts.PubKeys = nonCachedPubkeys

		eth2Resp, err := c.eth2Cl.Validators(ctx, opts)
		if err != nil {
			return nil, errors.Wrap(err, "fetching non-cached validators from BN")
		}
		for idx, val := range eth2Resp.Data {
			ret[idx] = val
		}
	} else {
		log.Debug(ctx, "All validators requested were cached", z.Int("amount_requested", len(opts.PubKeys)))
	}

	convertedVals, err := c.convertValidators(ret, len(opts.Indices) == 0)
	if err != nil {
		return nil, err
	}

	return wrapResponse(convertedVals), nil
}

// NodeVersion returns the current version of charon.
func (Component) NodeVersion(context.Context, *eth2api.NodeVersionOpts) (*eth2api.Response[string], error) {
	commitSHA, _ := version.GitCommit()
	charonVersion := fmt.Sprintf("obolnetwork/charon/%v-%s/%s-%s", version.Version, commitSHA, runtime.GOARCH, runtime.GOOS)

	return wrapResponse(charonVersion), nil
}

// convertValidators returns the validator map with root public keys replaced by public shares for all validators that are part of the cluster.
func (c Component) convertValidators(vals map[eth2p0.ValidatorIndex]*eth2v1.Validator, ignoreNotFound bool) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, error) {
	resp := make(map[eth2p0.ValidatorIndex]*eth2v1.Validator)
	for vIdx, rawVal := range vals {
		if rawVal == nil || rawVal.Validator == nil {
			return nil, errors.New("validator data cannot be nil")
		}

		innerVal := *rawVal.Validator

		pubshare, ok := c.getPubShareFunc(innerVal.PublicKey)
		if !ok && !ignoreNotFound {
			return nil, errors.New("pubshare not found")
		} else if ok {
			innerVal.PublicKey = pubshare
		}

		var val eth2v1.Validator
		val.Index = rawVal.Index
		val.Status = rawVal.Status
		val.Balance = rawVal.Balance
		val.Validator = &innerVal

		resp[vIdx] = &val
	}

	return resp, nil
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
		duty := core.NewPrepareAggregatorDuty(uint64(slot))
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
		duty := core.NewPrepareSyncContributionDuty(uint64(slot))
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

// ProposerConfig returns the proposer configuration for all validators.
func (c Component) ProposerConfig(ctx context.Context) (*eth2exp.ProposerConfigResponse, error) {
	resp := eth2exp.ProposerConfigResponse{
		Proposers: make(map[eth2p0.BLSPubKey]eth2exp.ProposerConfig),
		Default: eth2exp.ProposerConfig{ // Default doesn't make sense, disable for now.
			FeeRecipient: zeroAddress,
			Builder: eth2exp.Builder{
				Enabled:  false,
				GasLimit: gasLimit,
			},
		},
	}

	eth2Resp, err := c.eth2Cl.Spec(ctx, &eth2api.SpecOpts{})
	if err != nil {
		return nil, err
	}

	slotDuration, ok := eth2Resp.Data["SECONDS_PER_SLOT"].(time.Duration)
	if !ok {
		return nil, errors.New("fetch slot duration")
	}

	timestamp, err := c.eth2Cl.GenesisTime(ctx)
	if err != nil {
		return nil, err
	}
	timestamp = timestamp.Add(slotDuration) // Use slot 1 for timestamp to override pre-generated registrations.

	slot, err := SlotFromTimestamp(ctx, c.eth2Cl, time.Now())
	if err != nil {
		return nil, err
	}

	for pubkey, pubshare := range c.sharesByKey {
		eth2Share, err := pubshare.ToETH2()
		if err != nil {
			return nil, err
		}

		resp.Proposers[eth2Share] = eth2exp.ProposerConfig{
			FeeRecipient: c.feeRecipientFunc(pubkey),
			Builder: eth2exp.Builder{
				Enabled:  c.builderEnabled(uint64(slot)),
				GasLimit: gasLimit,
				Overrides: map[string]string{
					"timestamp":  fmt.Sprint(timestamp.Unix()),
					"public_key": string(pubkey),
				},
			},
		}
	}

	return &resp, nil
}

// wrapResponse wraps the provided data into an API Response and returns the response.
func wrapResponse[T any](data T) *eth2api.Response[T] {
	return &eth2api.Response[T]{Data: data}
}

// wrapResponseWithMetadata wraps the provided data and metadata into an API Response and returns the response.
func wrapResponseWithMetadata[T any](data T, metadata map[string]any) *eth2api.Response[T] {
	return &eth2api.Response[T]{Data: data, Metadata: metadata}
}
