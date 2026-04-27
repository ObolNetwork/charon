// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	eth2api "github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/forkjoin"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

// NewMultiForT creates a new mutil client for testing.
func NewMultiForT(clients []Client, fallbacks []Client) Client {
	return &multi{
		clients:   clients,
		fallbacks: fallbacks,
		selector:  newBestSelector(bestPeriod),
		prep:      newPrepState(),
	}
}

func newMulti(clients []Client, fallbacks []Client) Client {
	return multi{
		clients:   clients,
		fallbacks: fallbacks,
		selector:  newBestSelector(bestPeriod),
		prep:      newPrepState(),
	}
}

// multi wraps multiple clients, calling them in parallel and returning the first successful
// response. Adds prometheus metrics, error wrapping, a "best client" selector, and retries
// failed requests against the configured fallback endpoints.
type multi struct {
	clients   []Client
	fallbacks []Client
	selector  *bestSelector
	prep      *prepState
}

func (m multi) SetForkVersion(forkVersion [4]byte) {
	for _, cl := range m.clients {
		cl.SetForkVersion(forkVersion)
	}
}

func (multi) Name() string {
	return "eth2wrap.multi"
}

func (m multi) Address() string {
	address, ok := m.selector.BestAddress()
	if !ok {
		return m.clients[0].Address()
	}

	return address
}

// ClientForAddress returns a scoped multi client that only queries the specified address.
// Returns the original multi client if addr is empty or not found, falling back to the
// normal multi-client selection strategy.
func (m multi) ClientForAddress(addr string) Client {
	if addr == "" {
		return m
	}

	// Find client matching the address
	for _, cl := range m.clients {
		if cl.Address() == addr {
			return multi{
				clients:   []Client{cl},
				fallbacks: m.fallbacks,
				selector:  m.selector,
				prep:      m.prep,
			}
		}
	}

	// Address not found in clients, check fallbacks
	for _, cl := range m.fallbacks {
		if cl.Address() == addr {
			return multi{
				clients:   []Client{cl},
				fallbacks: nil,
				selector:  m.selector,
				prep:      m.prep,
			}
		}
	}

	// Address not found, return original multi client
	return m
}

func (m multi) Headers() map[string]string {
	if len(m.clients) == 0 {
		return nil
	}

	return m.clients[0].Headers()
}

func (m multi) IsActive() bool {
	for _, cl := range m.clients {
		if cl.IsActive() {
			return true
		}
	}

	return false
}

func (m multi) IsSynced() bool {
	for _, cl := range m.clients {
		if cl.IsSynced() {
			return true
		}
	}

	return false
}

func (m multi) SetValidatorCache(valCache func(context.Context) (ActiveValidators, CompleteValidators, error)) {
	for _, cl := range m.clients {
		cl.SetValidatorCache(valCache)
	}
}

func (m multi) ActiveValidators(ctx context.Context) (ActiveValidators, error) {
	const label = "active_validators"
	// No latency since this is a cached endpoint.

	defer incRequest(label)

	res0, err := provide(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) (ActiveValidators, error) {
			return args.client.ActiveValidators(ctx)
		},
		nil, nil,
	)
	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res0, err
}

func (m multi) CompleteValidators(ctx context.Context) (CompleteValidators, error) {
	const label = "complete_validators"
	// No latency since this is a cached endpoint.

	defer incRequest(label)

	res0, err := provide(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) (CompleteValidators, error) {
			return args.client.CompleteValidators(ctx)
		},
		nil, nil,
	)
	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res0, err
}

func (m multi) SetDutiesCache(
	proposerDutiesCache func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) (ProposerDutyWithMeta, error),
	attesterDutiesCache func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) (AttesterDutyWithMeta, error),
	syncCommDutiesCache func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) (SyncDutyWithMeta, error),
) {
	for _, cl := range m.clients {
		cl.SetDutiesCache(proposerDutiesCache, attesterDutiesCache, syncCommDutiesCache)
	}
}

func (m multi) ProposerDutiesCache(ctx context.Context, epoch eth2p0.Epoch, vidxs []eth2p0.ValidatorIndex) (ProposerDutyWithMeta, error) {
	const label = "proposer_duties_cache"
	// No latency since this is a cached endpoint.

	defer incRequest(label)

	res0, err := provide(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) (ProposerDutyWithMeta, error) {
			return args.client.ProposerDutiesCache(ctx, epoch, vidxs)
		},
		nil, nil,
	)
	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res0, err
}

func (m multi) AttesterDutiesCache(ctx context.Context, epoch eth2p0.Epoch, vidxs []eth2p0.ValidatorIndex) (AttesterDutyWithMeta, error) {
	const label = "attester_duties_cache"
	// No latency since this is a cached endpoint.

	defer incRequest(label)

	res0, err := provide(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) (AttesterDutyWithMeta, error) {
			return args.client.AttesterDutiesCache(ctx, epoch, vidxs)
		},
		nil, nil,
	)
	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res0, err
}

func (m multi) SyncCommDutiesCache(ctx context.Context, epoch eth2p0.Epoch, vidxs []eth2p0.ValidatorIndex) (SyncDutyWithMeta, error) {
	const label = "sync_comm_duties_cache"
	// No latency since this is a cached endpoint.

	defer incRequest(label)

	res0, err := provide(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) (SyncDutyWithMeta, error) {
			return args.client.SyncCommDutiesCache(ctx, epoch, vidxs)
		},
		nil, nil,
	)
	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res0, err
}

func (m multi) Proxy(ctx context.Context, req *http.Request) (*http.Response, error) {
	// Duplicate the request body so each backend gets an independent reader
	// req.Clone(ctx) does NOT clone the body reader
	var (
		bodyBytes []byte
		hasBody   bool
	)

	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, errors.Wrap(err, "read request body")
		}
		// Close the original body
		_ = req.Body.Close()
		bodyBytes = b
		hasBody = true
		// Replace with reusable reader for safety
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		req.ContentLength = int64(len(bodyBytes))
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(bodyBytes)), nil
		}
	}

	res0, err := provide(ctx, m.clients, m.fallbacks,
		func(ctx context.Context, args provideArgs) (*http.Response, error) {
			cloned := req.Clone(ctx)
			if hasBody {
				cloned.Body = io.NopCloser(bytes.NewReader(bodyBytes))
				cloned.ContentLength = int64(len(bodyBytes))
				cloned.GetBody = func() (io.ReadCloser, error) {
					return io.NopCloser(bytes.NewReader(bodyBytes)), nil
				}
			} else {
				cloned.Body = nil
			}

			res, err := args.client.Proxy(ctx, cloned)

			return res, err
		},
		nil, nil,
	)

	return res0, err
}

// expectedFeeRecipientCtxKey is a context key for the expected fee recipient address
// of a Proposal call. multi.Proposal uses it to discard responses with a mismatched
// fee recipient so they don't end up signed and broadcast. See issue #4477.
type expectedFeeRecipientCtxKey struct{}

// ContextWithExpectedFeeRecipient returns ctx with addr attached as the expected fee
// recipient for any Proposal call made with the returned context. addr should be a hex
// string with 0x prefix; comparison is case-insensitive.
func ContextWithExpectedFeeRecipient(ctx context.Context, addr string) context.Context {
	return context.WithValue(ctx, expectedFeeRecipientCtxKey{}, addr)
}

// ExpectedFeeRecipient returns the expected fee recipient address attached to ctx by
// ContextWithExpectedFeeRecipient, or "" if none is attached.
func ExpectedFeeRecipient(ctx context.Context) string {
	v, ok := ctx.Value(expectedFeeRecipientCtxKey{}).(string)
	if !ok {
		return ""
	}

	return v
}

// ProposalFeeRecipient returns the fee recipient address as 0x-prefixed hex. The bool is false
// for pre-bellatrix forks, blinded proposals (builder's recipient, not validator's), and
// malformed responses with nil nested structs — BN input must not panic on partial data.
func ProposalFeeRecipient(proposal *eth2api.VersionedProposal) (string, bool) {
	if proposal == nil || proposal.Blinded {
		return "", false
	}

	switch proposal.Version {
	case eth2spec.DataVersionBellatrix:
		if proposal.Bellatrix == nil || proposal.Bellatrix.Body == nil || proposal.Bellatrix.Body.ExecutionPayload == nil {
			return "", false
		}

		return fmt.Sprintf("%#x", proposal.Bellatrix.Body.ExecutionPayload.FeeRecipient), true
	case eth2spec.DataVersionCapella:
		if proposal.Capella == nil || proposal.Capella.Body == nil || proposal.Capella.Body.ExecutionPayload == nil {
			return "", false
		}

		return fmt.Sprintf("%#x", proposal.Capella.Body.ExecutionPayload.FeeRecipient), true
	case eth2spec.DataVersionDeneb:
		if proposal.Deneb == nil || proposal.Deneb.Block == nil || proposal.Deneb.Block.Body == nil || proposal.Deneb.Block.Body.ExecutionPayload == nil {
			return "", false
		}

		return fmt.Sprintf("%#x", proposal.Deneb.Block.Body.ExecutionPayload.FeeRecipient), true
	case eth2spec.DataVersionElectra:
		if proposal.Electra == nil || proposal.Electra.Block == nil || proposal.Electra.Block.Body == nil || proposal.Electra.Block.Body.ExecutionPayload == nil {
			return "", false
		}

		return fmt.Sprintf("%#x", proposal.Electra.Block.Body.ExecutionPayload.FeeRecipient), true
	case eth2spec.DataVersionFulu:
		if proposal.Fulu == nil || proposal.Fulu.Block == nil || proposal.Fulu.Block.Body == nil || proposal.Fulu.Block.Body.ExecutionPayload == nil {
			return "", false
		}

		return fmt.Sprintf("%#x", proposal.Fulu.Block.Body.ExecutionPayload.FeeRecipient), true
	default:
		return "", false
	}
}

// proposalDecision is the outcome of validating a Proposal response against an expected fee
// recipient. Shared by isSuccess (inside provide) and the post-provide promotion check.
type proposalDecision int

const (
	decisionAccept          proposalDecision = iota // OK to use (recipient matches OR no recipient applicable)
	decisionRejectMismatch                          // unblinded bellatrix+ with the wrong recipient
	decisionRejectMalformed                         // nil response, missing nested fields, or unknown fork
)

// proposalIsRecipientExempt reports whether a proposal can legitimately skip fee recipient
// validation: blinded (builder's recipient) and known pre-bellatrix forks (no execution
// payload). Unknown forks are NOT exempt — they get treated as malformed.
func proposalIsRecipientExempt(p *eth2api.VersionedProposal) bool {
	if p == nil {
		return false
	}

	if p.Blinded {
		return true
	}

	switch p.Version {
	case eth2spec.DataVersionPhase0, eth2spec.DataVersionAltair:
		return true
	default:
		return false
	}
}

// classifyProposal decides whether a proposal response is acceptable. Returns the actual fee
// recipient hex when it could be extracted (useful for logging on mismatch).
func classifyProposal(p *eth2api.VersionedProposal, expected string) (proposalDecision, string) {
	if p == nil {
		return decisionRejectMalformed, ""
	}

	actual, ok := ProposalFeeRecipient(p)
	if ok {
		if strings.EqualFold(actual, expected) {
			return decisionAccept, actual
		}

		return decisionRejectMismatch, actual
	}

	// ProposalFeeRecipient returned ok=false. Accept only if validation is legitimately
	// inapplicable; otherwise (malformed payload or unknown fork) reject.
	if proposalIsRecipientExempt(p) {
		return decisionAccept, ""
	}

	return decisionRejectMalformed, ""
}

// Proposal fetches a proposal for signing. Hand-written (skipped by genwrap) to exclude BNs
// whose most recent prep failed (Solution A) and reject responses whose fee recipient doesn't
// match ctx's ContextWithExpectedFeeRecipient — also rejects malformed responses. See #4477.
func (m multi) Proposal(ctx context.Context, opts *eth2api.ProposalOpts) (*eth2api.Response[*eth2api.VersionedProposal], error) {
	const label = "proposal"
	defer latency(ctx, label, true)()
	defer incRequest(label)

	// Merge primaries and fallbacks into a single pool: provide()'s built-in fallback retry
	// only fires on transport errors, not content checks like a wrong fee recipient. Without
	// merging, a fallback can't rescue the duty when primaries return wrong-recipient blocks.
	primaries := m.prep.preparedClients(m.clients)
	fallbacks := m.prep.preparedClients(m.fallbacks)

	clients := make([]Client, 0, len(primaries)+len(fallbacks))
	clients = append(clients, primaries...)
	clients = append(clients, fallbacks...)

	expected := ExpectedFeeRecipient(ctx)

	var isSuccess func(*eth2api.Response[*eth2api.VersionedProposal]) bool
	if expected != "" {
		isSuccess = func(resp *eth2api.Response[*eth2api.VersionedProposal]) bool {
			// A misbehaving client could return (nil, nil); treat as non-success so provide
			// moves on rather than panicking on resp.Data.
			if resp == nil {
				return false
			}

			decision, actual := classifyProposal(resp.Data, expected)
			switch decision {
			case decisionAccept:
				return true
			case decisionRejectMismatch:
				log.Warn(ctx, "Discarded beacon node proposal with unexpected fee recipient", nil,
					z.Str("expected", expected), z.Str("actual", actual))

				return false
			case decisionRejectMalformed:
				log.Warn(ctx, "Discarded malformed beacon node proposal", nil)

				return false
			default:
				return false
			}
		}
	}

	res0, err := provide(ctx, clients, nil,
		func(ctx context.Context, args provideArgs) (*eth2api.Response[*eth2api.VersionedProposal], error) {
			return args.client.Proposal(ctx, opts)
		},
		isSuccess, m.selector,
	)

	// Defend against (nil, nil) from provide — caller dereferences eth2Resp.Data. Happens when
	// every backend returns (nil, nil), or all responses failed isSuccess via the nokResp path.
	if err == nil && res0 == nil {
		err = errors.New("all beacon node proposals returned nil response")
	}

	// provide returns the last non-success response with nil error when all responses fail
	// isSuccess. Promote that to a real error so we don't sign a bad block downstream;
	// classify directly rather than reusing isSuccess to avoid double-logging the warn line.
	if err == nil && expected != "" && res0 != nil {
		decision, _ := classifyProposal(res0.Data, expected)
		switch decision {
		case decisionRejectMismatch:
			err = errors.New("all beacon node proposals had an unexpected fee recipient")
		case decisionRejectMalformed:
			err = errors.New("all beacon node proposals were malformed")
		default:
			// decisionAccept — provide selected an acceptable response.
		}
	}

	if err != nil {
		incError(label)
		err = wrapError(ctx, err, label)
	}

	return res0, err
}

// SubmitProposalPreparations fans out to every BN (primaries+fallbacks) and records per-BN
// outcome in m.prep so failed BNs are excluded from subsequent Proposal calls. Returns success
// if any BN succeeded; per-BN failures are logged and counted for operator visibility. See #4477.
func (m multi) SubmitProposalPreparations(ctx context.Context, preparations []*apiv1.ProposalPreparation) error {
	const label = "submit_proposal_preparations"
	defer latency(ctx, label, true)()
	defer incRequest(label)

	all := make([]Client, 0, len(m.clients)+len(m.fallbacks))
	all = append(all, m.clients...)
	all = append(all, m.fallbacks...)

	work := func(ctx context.Context, cl Client) (struct{}, error) {
		return struct{}{}, cl.SubmitProposalPreparations(ctx, preparations)
	}

	fork, join, cancel := forkjoin.New(ctx, work,
		forkjoin.WithoutFailFast(),
		forkjoin.WithWorkers(len(all)),
	)
	defer cancel()

	for _, cl := range all {
		fork(cl)
	}

	var (
		successCount int
		lastErr      error
	)

	for res := range join() {
		addr := res.Input.Address()
		if res.Err == nil {
			m.prep.markSuccess(addr)

			successCount++

			continue
		}

		lastErr = res.Err

		// If the parent ctx was cancelled, BN state is unknown — don't poison prepState by
		// excluding BNs that may actually still be prepared.
		if ctx.Err() != nil {
			continue
		}

		m.prep.markFailure(addr)
		incError(label)

		log.Warn(ctx, "Failed to submit proposal preparations to beacon node, excluding from next Proposal call", res.Err,
			z.Str("address", addr))
	}

	if successCount > 0 {
		return nil
	}

	// If ctx was cancelled before any worker ran, lastErr is nil; surface ctx.Err() so the
	// returned error isn't a confusing wrapped-nil.
	if lastErr == nil {
		lastErr = ctx.Err()
	}

	return wrapError(ctx, lastErr, label)
}
