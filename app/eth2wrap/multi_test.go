// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/eth2wrap/mocks"
)

func TestMulti_Name(t *testing.T) {
	client := mocks.NewClient(t)

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client}, nil)

	require.Equal(t, "eth2wrap.multi", m.Name())
}

func TestMulti_Address(t *testing.T) {
	client := mocks.NewClient(t)
	client.On("Address").Return("test").Once()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client}, nil)

	require.Equal(t, "test", m.Address())
}

func TestMulti_IsActive(t *testing.T) {
	client1 := mocks.NewClient(t)
	client1.On("IsActive").Return(false).Once()

	client2 := mocks.NewClient(t)
	client2.On("IsActive").Return(true).Once()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client1, client2}, nil)

	require.True(t, m.IsActive())
}

func TestMulti_IsSynced(t *testing.T) {
	client1 := mocks.NewClient(t)
	client1.On("IsSynced").Return(false).Once()

	client2 := mocks.NewClient(t)
	client2.On("IsSynced").Return(true).Once()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client1, client2}, nil)

	require.True(t, m.IsSynced())
}

func TestMulti_ActiveValidators(t *testing.T) {
	ctx := context.Background()
	vals := make(eth2wrap.ActiveValidators)

	client := mocks.NewClient(t)
	client.On("ActiveValidators", mock.Anything).Return(vals, nil).Once()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client}, nil)

	vals2, err := m.ActiveValidators(ctx)
	require.NoError(t, err)
	require.Equal(t, vals, vals2)

	expectedErr := errors.New("boo")
	client.On("ActiveValidators", mock.Anything).Return(nil, expectedErr).Once()

	_, err = m.ActiveValidators(ctx)
	require.ErrorIs(t, err, expectedErr)
}

func TestMulti_SetValidatorCache(t *testing.T) {
	valCache := func(context.Context) (eth2wrap.ActiveValidators, eth2wrap.CompleteValidators, error) {
		return nil, nil, nil
	}

	client := mocks.NewClient(t)
	client.On("SetValidatorCache", mock.Anything).Once()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client}, nil)
	m.SetValidatorCache(valCache)
}

func TestMulti_SetDutiesCache(t *testing.T) {
	proposerDutiesCache := func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) (eth2wrap.ProposerDutyWithMeta, error) {
		return eth2wrap.ProposerDutyWithMeta{}, nil
	}
	attesterDutiesCache := func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) (eth2wrap.AttesterDutyWithMeta, error) {
		return eth2wrap.AttesterDutyWithMeta{}, nil
	}
	syncDutiesCache := func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) (eth2wrap.SyncDutyWithMeta, error) {
		return eth2wrap.SyncDutyWithMeta{}, nil
	}

	client := mocks.NewClient(t)
	client.On("SetDutiesCache", mock.Anything, mock.Anything, mock.Anything).Once()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client}, nil)
	m.SetDutiesCache(proposerDutiesCache, attesterDutiesCache, syncDutiesCache)
}

func TestMulti_ProposerDutiesCache(t *testing.T) {
	ctx := context.Background()
	proposerDuties := eth2wrap.ProposerDutyWithMeta{Duties: []*eth2v1.ProposerDuty{}, Metadata: nil}

	client := mocks.NewClient(t)
	client.On("ProposerDutiesCache", mock.Anything, mock.Anything, mock.Anything).Return(proposerDuties, nil).Once()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client}, nil)

	proposerDuties2, err := m.ProposerDutiesCache(ctx, 0, []eth2p0.ValidatorIndex{})
	require.NoError(t, err)
	require.Equal(t, proposerDuties, proposerDuties2)
}

func TestMulti_AttesterDutiesCache(t *testing.T) {
	ctx := context.Background()
	attesterDuties := eth2wrap.AttesterDutyWithMeta{Duties: []*eth2v1.AttesterDuty{}, Metadata: nil}

	client := mocks.NewClient(t)
	client.On("AttesterDutiesCache", mock.Anything, mock.Anything, mock.Anything).Return(attesterDuties, nil).Once()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client}, nil)

	attesterDuties2, err := m.AttesterDutiesCache(ctx, 0, []eth2p0.ValidatorIndex{})
	require.NoError(t, err)
	require.Equal(t, attesterDuties, attesterDuties2)
}

func TestMulti_SyncDutiesCache(t *testing.T) {
	ctx := context.Background()
	syncDuties := eth2wrap.SyncDutyWithMeta{Duties: []*eth2v1.SyncCommitteeDuty{}, Metadata: nil}

	client := mocks.NewClient(t)
	client.On("SyncCommDutiesCache", mock.Anything, mock.Anything, mock.Anything).Return(syncDuties, nil).Once()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client}, nil)

	syncDuties2, err := m.SyncCommDutiesCache(ctx, 0, []eth2p0.ValidatorIndex{})
	require.NoError(t, err)
	require.Equal(t, syncDuties, syncDuties2)
}

func TestMulti_Proxy(t *testing.T) {
	client := mocks.NewClient(t)
	client.On("Proxy", mock.Anything, mock.Anything).Return(nil, nil).Once()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client}, nil)

	req, err := http.NewRequest(http.MethodGet, "", nil)
	require.NoError(t, err)

	_, err = m.Proxy(t.Context(), req)
	require.NoError(t, err)
}

func TestMulti_Proxy_ReadBody(t *testing.T) {
	cl1 := mocks.NewClient(t)
	cl1.On("Proxy", mock.Anything, mock.MatchedBy(func(req *http.Request) bool {
		_, err := io.ReadAll(req.Body)
		require.NoError(t, err)

		return true
	})).Return(nil, errors.New("syncing")).Once() // force fallback to also read body

	cl2 := mocks.NewClient(t)
	cl2.On("Proxy", mock.Anything, mock.MatchedBy(func(req *http.Request) bool {
		_, err := io.ReadAll(req.Body)
		require.NoError(t, err)

		return true
	})).Return(nil, nil).Once()

	// Two clients reading the same body should not error since the body is duplicated for each backend.
	m := eth2wrap.NewMultiForT([]eth2wrap.Client{cl1}, []eth2wrap.Client{cl2})
	bodyReader := strings.NewReader("foo")
	req, err := http.NewRequest(http.MethodPost, "", bodyReader)
	require.NoError(t, err)

	_, err = m.Proxy(t.Context(), req)
	require.NoError(t, err)
}

func TestMulti_ClientForAddress(t *testing.T) {
	client1 := mocks.NewClient(t)
	client1.On("Address").Return("http://bn1:5051").Maybe()

	client2 := mocks.NewClient(t)
	client2.On("Address").Return("http://bn2:5052").Maybe()

	fallback := mocks.NewClient(t)
	fallback.On("Address").Return("http://fallback:5053").Maybe()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client1, client2}, []eth2wrap.Client{fallback})

	t.Run("address found in primary clients", func(t *testing.T) {
		scoped := m.ClientForAddress("http://bn1:5051")
		require.NotNil(t, scoped)
		// The scoped client should only use the specified address
		require.Equal(t, "http://bn1:5051", scoped.Address())
	})

	t.Run("address found in fallback clients", func(t *testing.T) {
		scoped := m.ClientForAddress("http://fallback:5053")
		require.NotNil(t, scoped)
		require.Equal(t, "http://fallback:5053", scoped.Address())
	})

	t.Run("address not found", func(t *testing.T) {
		// Should return the original multi client
		scoped := m.ClientForAddress("http://unknown:5054")
		require.NotNil(t, scoped)
		// When address is not found, it returns the original multi client
		// which will use the first client's address
		require.Equal(t, "http://bn1:5051", scoped.Address())
	})

	t.Run("empty address", func(t *testing.T) {
		// Should return the original multi client
		scoped := m.ClientForAddress("")
		require.NotNil(t, scoped)
		require.Equal(t, "http://bn1:5051", scoped.Address())
	})
}

// testFeeRecipientHex is the hex form of bellatrix.ExecutionAddress{0xab, 0xcd} (used across the
// per-BN prep / fee-recipient validation tests below).
const testFeeRecipientHex = "0xabcd000000000000000000000000000000000000"

// proposalWithFeeRecipient builds a minimal Deneb proposal with the given fee recipient.
func proposalWithFeeRecipient(addr bellatrix.ExecutionAddress) *eth2api.Response[*eth2api.VersionedProposal] {
	return &eth2api.Response[*eth2api.VersionedProposal]{
		Data: &eth2api.VersionedProposal{
			Version: eth2spec.DataVersionDeneb,
			Deneb: &eth2deneb.BlockContents{
				Block: &deneb.BeaconBlock{
					Body: &deneb.BeaconBlockBody{
						ExecutionPayload: &deneb.ExecutionPayload{
							FeeRecipient: addr,
						},
					},
				},
			},
		},
	}
}

// TestMulti_SubmitProposalPreparations_FansOutAndTracks verifies that prep is sent to every BN
// (not first-success-wins) and that per-BN failures are recorded so the failing BN gets excluded
// from the next Proposal call. Regression test for #4477.
func TestMulti_SubmitProposalPreparations_FansOutAndTracks(t *testing.T) {
	ctx := t.Context()

	expected := bellatrix.ExecutionAddress{0xab, 0xcd}
	expectedHex := testFeeRecipientHex
	zero := bellatrix.ExecutionAddress{}

	good := mocks.NewClient(t)
	good.On("Address").Return("http://good:5051").Maybe()
	good.On("SubmitProposalPreparations", mock.Anything, mock.Anything).Return(nil).Once()
	good.On("Proposal", mock.Anything, mock.Anything).Return(proposalWithFeeRecipient(expected), nil).Maybe()

	bad := mocks.NewClient(t)
	bad.On("Address").Return("http://bad:5051").Maybe()
	bad.On("SubmitProposalPreparations", mock.Anything, mock.Anything).Return(errors.New("silent fail")).Once()
	// bad.Proposal must NOT be called once it has been recorded as unprepared. If it is, the test fails
	// because mockery rejects unexpected calls.
	bad.On("Proposal", mock.Anything, mock.Anything).Return(proposalWithFeeRecipient(zero), nil).Maybe()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{good, bad}, nil)

	// First, submit preparations. The good BN succeeds, the bad BN errors. Multi should still return
	// nil (≥1 succeeded) but record the failure per-BN.
	require.NoError(t, m.SubmitProposalPreparations(ctx, []*eth2v1.ProposalPreparation{
		{ValidatorIndex: 0, FeeRecipient: expected},
	}))

	// Now request a proposal with the expected fee recipient attached. The bad BN must be excluded.
	proposalCtx := eth2wrap.ContextWithExpectedFeeRecipient(ctx, expectedHex)
	resp, err := m.Proposal(proposalCtx, &eth2api.ProposalOpts{Slot: 1})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Data)

	// Confirm bad.Proposal was never called: the mock library's AssertExpectations (run via
	// NewClient(t) cleanup) verifies no unexpected calls beyond what was set as Maybe(). To make
	// the assertion stronger, count calls explicitly.
	badCalls := 0

	for _, call := range bad.Calls {
		if call.Method == "Proposal" {
			badCalls++
		}
	}

	require.Zero(t, badCalls, "unprepared BN should be excluded from Proposal calls")
}

// TestMulti_Proposal_RejectsMismatchedFeeRecipient verifies that even if a BN slips past the prep
// tracking (e.g. it ack'd prep but lost state on restart) and returns a proposal with the wrong
// fee recipient, multi.Proposal discards that response and returns one from another BN.
// Regression test for #4477.
func TestMulti_Proposal_RejectsMismatchedFeeRecipient(t *testing.T) {
	ctx := t.Context()

	expected := bellatrix.ExecutionAddress{0xab, 0xcd}
	expectedHex := testFeeRecipientHex
	zero := bellatrix.ExecutionAddress{}

	// Both BNs ack'd prep; one is misconfigured at proposal time.
	goodCalled := atomic.Bool{}

	good := mocks.NewClient(t)
	good.On("Address").Return("http://good:5051").Maybe()
	good.On("SubmitProposalPreparations", mock.Anything, mock.Anything).Return(nil).Once()
	good.On("Proposal", mock.Anything, mock.Anything).Run(func(_ mock.Arguments) {
		goodCalled.Store(true)
	}).Return(proposalWithFeeRecipient(expected), nil).Maybe()

	bad := mocks.NewClient(t)
	bad.On("Address").Return("http://bad:5051").Maybe()
	bad.On("SubmitProposalPreparations", mock.Anything, mock.Anything).Return(nil).Once()
	bad.On("Proposal", mock.Anything, mock.Anything).Return(proposalWithFeeRecipient(zero), nil).Maybe()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{good, bad}, nil)
	require.NoError(t, m.SubmitProposalPreparations(ctx, []*eth2v1.ProposalPreparation{
		{ValidatorIndex: 0, FeeRecipient: expected},
	}))

	proposalCtx := eth2wrap.ContextWithExpectedFeeRecipient(ctx, expectedHex)
	resp, err := m.Proposal(proposalCtx, &eth2api.ProposalOpts{Slot: 1})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Data)
	require.True(t, goodCalled.Load(), "good BN must have been queried")

	// The returned proposal must be the one with the correct fee recipient.
	require.Equal(t, expected, resp.Data.Deneb.Block.Body.ExecutionPayload.FeeRecipient)
}

// TestMulti_Proposal_AllMismatch_ReturnsError verifies that if every BN returns a proposal with
// the wrong fee recipient, multi.Proposal returns an error (so the duty fails loudly) instead of
// silently signing a zero-recipient block. Regression test for #4477.
func TestMulti_Proposal_AllMismatch_ReturnsError(t *testing.T) {
	ctx := t.Context()

	expectedHex := testFeeRecipientHex
	zero := bellatrix.ExecutionAddress{}

	bn1 := mocks.NewClient(t)
	bn1.On("Address").Return("http://bn1:5051").Maybe()
	bn1.On("Proposal", mock.Anything, mock.Anything).Return(proposalWithFeeRecipient(zero), nil).Maybe()

	bn2 := mocks.NewClient(t)
	bn2.On("Address").Return("http://bn2:5051").Maybe()
	bn2.On("Proposal", mock.Anything, mock.Anything).Return(proposalWithFeeRecipient(zero), nil).Maybe()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{bn1, bn2}, nil)

	proposalCtx := eth2wrap.ContextWithExpectedFeeRecipient(ctx, expectedHex)
	_, err := m.Proposal(proposalCtx, &eth2api.ProposalOpts{Slot: 1})
	require.Error(t, err)
}

// TestMulti_Proposal_NoExpectedFeeRecipient_AcceptsAny verifies that without an expected fee
// recipient attached to ctx, the Proposal call accepts any response (preserves prior behavior).
func TestMulti_Proposal_NoExpectedFeeRecipient_AcceptsAny(t *testing.T) {
	ctx := t.Context()

	zero := bellatrix.ExecutionAddress{}

	bn := mocks.NewClient(t)
	bn.On("Address").Return("http://bn:5051").Maybe()
	bn.On("Proposal", mock.Anything, mock.Anything).Return(proposalWithFeeRecipient(zero), nil).Once()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{bn}, nil)

	resp, err := m.Proposal(ctx, &eth2api.ProposalOpts{Slot: 1})
	require.NoError(t, err)
	require.NotNil(t, resp)
}

// TestMulti_Proposal_NoPrepYet_UsesAllClients verifies that before SubmitProposalPreparations has
// run (or if all BNs are currently unprepared), Proposal falls back to all clients rather than
// blocking — better to risk a mismatch (still detected by validation) than miss the slot entirely.
func TestMulti_Proposal_NoPrepYet_UsesAllClients(t *testing.T) {
	ctx := t.Context()

	expected := bellatrix.ExecutionAddress{0xab, 0xcd}

	bn := mocks.NewClient(t)
	bn.On("Address").Return("http://bn:5051").Maybe()
	bn.On("Proposal", mock.Anything, mock.Anything).Return(proposalWithFeeRecipient(expected), nil).Once()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{bn}, nil)

	resp, err := m.Proposal(ctx, &eth2api.ProposalOpts{Slot: 1})
	require.NoError(t, err)
	require.NotNil(t, resp)
}

// TestMulti_SubmitProposalPreparations_FansOutToFallbacks verifies that prep is also sent to
// fallback BNs — provide() may route a Proposal call to a fallback when all primaries fail, so
// fallbacks need to be prepared too.
func TestMulti_SubmitProposalPreparations_FansOutToFallbacks(t *testing.T) {
	ctx := t.Context()

	primary := mocks.NewClient(t)
	primary.On("Address").Return("http://primary:5051").Maybe()
	primary.On("SubmitProposalPreparations", mock.Anything, mock.Anything).Return(nil).Once()

	fallback := mocks.NewClient(t)
	fallback.On("Address").Return("http://fallback:5051").Maybe()
	fallback.On("SubmitProposalPreparations", mock.Anything, mock.Anything).Return(nil).Once()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{primary}, []eth2wrap.Client{fallback})

	require.NoError(t, m.SubmitProposalPreparations(ctx, []*eth2v1.ProposalPreparation{
		{ValidatorIndex: 0, FeeRecipient: bellatrix.ExecutionAddress{0xab, 0xcd}},
	}))
	// mocks.NewClient(t)'s cleanup asserts the .Once() expectations on both BNs.
}

// TestMulti_SubmitProposalPreparations_CtxCancelDoesNotPoisonState verifies that if the parent
// context is cancelled mid-flight, prepState is not updated with failures — BN state is unknown
// in that case, so excluding them on the next epoch would be incorrect.
func TestMulti_SubmitProposalPreparations_CtxCancelDoesNotPoisonState(t *testing.T) {
	expected := bellatrix.ExecutionAddress{0xab, 0xcd}
	expectedHex := testFeeRecipientHex

	bn := mocks.NewClient(t)
	bn.On("Address").Return("http://bn:5051").Maybe()
	// forkjoin may short-circuit before invoking the worker when ctx is already cancelled, so
	// SubmitProposalPreparations on the mock may or may not be called — Maybe() either way.
	bn.On("SubmitProposalPreparations", mock.Anything, mock.Anything).Return(context.Canceled).Maybe()
	// After cancellation, bn must still be considered prepared on the next slot.
	bn.On("Proposal", mock.Anything, mock.Anything).Return(proposalWithFeeRecipient(expected), nil).Once()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{bn}, nil)

	cancelledCtx, cancel := context.WithCancel(t.Context())
	cancel()

	// Prep will fail (context already cancelled). We don't care about the err — the assertion
	// is about prepState side effects.
	_ = m.SubmitProposalPreparations(cancelledCtx, []*eth2v1.ProposalPreparation{
		{ValidatorIndex: 0, FeeRecipient: expected},
	})

	// On the next slot, bn must still be queried (not excluded).
	proposalCtx := eth2wrap.ContextWithExpectedFeeRecipient(t.Context(), expectedHex)
	resp, err := m.Proposal(proposalCtx, &eth2api.ProposalOpts{Slot: 1})
	require.NoError(t, err)
	require.NotNil(t, resp)
}
