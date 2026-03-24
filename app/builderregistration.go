// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/fsnotify/fsnotify"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/obolapi"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util/registration"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

const (
	// fetchIntervalIncomplete is the fetch interval when some validators have incomplete registrations.
	fetchIntervalIncomplete = 1 * time.Hour
	// fetchIntervalComplete is the fetch interval when all registrations are fully signed.
	fetchIntervalComplete = 24 * time.Hour
)

// BuilderRegistrationService provides thread-safe access to current builder
// registrations and fee recipient addresses with runtime override support.
type BuilderRegistrationService interface {
	// Registrations returns the current effective builder registrations.
	Registrations() []*eth2api.VersionedSignedValidatorRegistration
	// FeeRecipient returns the current fee recipient address for the given pubkey.
	FeeRecipient(pubkey core.PubKey) string
	// Run watches the overrides file for changes, periodically fetches from the
	// Obol API, and reloads when either source is updated. It blocks until ctx is cancelled.
	Run(ctx context.Context)
}

// ValidatorCategories holds categorized validator public keys by registration status.
type ValidatorCategories struct {
	Complete   []string
	Incomplete []string
	NoReg      []string
}

// ProcessedValidators holds the results of processing the API response.
type ProcessedValidators struct {
	AggregatedRegs []*eth2api.VersionedSignedValidatorRegistration
	Categories     ValidatorCategories
	// PartialSigIndices maps validator pubkey to share indices that submitted.
	PartialSigIndices map[string][]int
	// QuorumMessages maps validator pubkey to the quorum registration message details.
	QuorumMessages map[string]*eth2v1.ValidatorRegistration
	// IncompleteMessages maps validator pubkey to the incomplete registration message
	// with the most partial signatures.
	IncompleteMessages map[string]*eth2v1.ValidatorRegistration
}

// AggregatePartialSignatures converts partial signatures into a full aggregated signature.
func AggregatePartialSignatures(partialSigs []obolapi.FeeRecipientPartialSig, pubkey string) (eth2p0.BLSSignature, error) {
	sigsMap := make(map[int]tbls.Signature)

	for _, ps := range partialSigs {
		sigsMap[ps.ShareIndex] = ps.Signature
	}

	fullSig, err := tbls.ThresholdAggregate(sigsMap)
	if err != nil {
		return eth2p0.BLSSignature{}, errors.Wrap(err, "aggregate partial signatures", z.Str("pubkey", pubkey))
	}

	return eth2p0.BLSSignature(fullSig), nil
}

// ProcessValidators aggregates signatures for validators with quorum and categorizes all validators by status.
func ProcessValidators(validators []obolapi.FeeRecipientValidator) (ProcessedValidators, error) {
	result := ProcessedValidators{
		PartialSigIndices:  make(map[string][]int),
		QuorumMessages:     make(map[string]*eth2v1.ValidatorRegistration),
		IncompleteMessages: make(map[string]*eth2v1.ValidatorRegistration),
	}

	for _, val := range validators {
		var hasQuorum, hasIncomplete bool

		for _, reg := range val.BuilderRegistrations {
			if reg.Quorum {
				hasQuorum = true

				fullSig, err := AggregatePartialSignatures(reg.PartialSignatures, val.Pubkey)
				if err != nil {
					return ProcessedValidators{}, err
				}

				result.AggregatedRegs = append(result.AggregatedRegs, &eth2api.VersionedSignedValidatorRegistration{
					Version: eth2spec.BuilderVersionV1,
					V1: &eth2v1.SignedValidatorRegistration{
						Message:   reg.Message,
						Signature: fullSig,
					},
				})

				result.QuorumMessages[val.Pubkey] = reg.Message
			} else {
				hasIncomplete = true

				if len(reg.PartialSignatures) > len(result.PartialSigIndices[val.Pubkey]) {
					indices := make([]int, 0, len(reg.PartialSignatures))
					for _, ps := range reg.PartialSignatures {
						indices = append(indices, ps.ShareIndex)
					}

					result.PartialSigIndices[val.Pubkey] = indices
					result.IncompleteMessages[val.Pubkey] = reg.Message
				}
			}
		}

		if hasQuorum {
			result.Categories.Complete = append(result.Categories.Complete, val.Pubkey)
		}

		if hasIncomplete {
			result.Categories.Incomplete = append(result.Categories.Incomplete, val.Pubkey)
		}

		if !hasQuorum && !hasIncomplete {
			result.Categories.NoReg = append(result.Categories.NoReg, val.Pubkey)
		}
	}

	return result, nil
}

// builderRegistrationService implements BuilderRegistrationService.
type builderRegistrationService struct {
	mu                sync.RWMutex
	path              string
	forkVersion       eth2p0.Version
	baseRegistrations []*eth2api.VersionedSignedValidatorRegistration
	baseFeeRecipients map[core.PubKey]string
	registrations     []*eth2api.VersionedSignedValidatorRegistration
	feeRecipients     map[core.PubKey]string

	// Fields for background API fetching.
	obolClient    *obolapi.Client
	lockHash      []byte
	fileOverrides []*eth2api.VersionedSignedValidatorRegistration
	apiOverrides  []*eth2api.VersionedSignedValidatorRegistration
}

// NewBuilderRegistrationService creates a new service that manages builder registrations.
// It loads and applies overrides from the given path on creation.
// When obolClient is non-nil, Run will periodically fetch registrations from the Obol API.
func NewBuilderRegistrationService(
	ctx context.Context,
	path string,
	forkVersion eth2p0.Version,
	baseRegistrations []*eth2api.VersionedSignedValidatorRegistration,
	baseFeeRecipients map[core.PubKey]string,
	obolClient *obolapi.Client,
	lockHash []byte,
) (BuilderRegistrationService, error) {
	svc := &builderRegistrationService{
		path:              path,
		forkVersion:       forkVersion,
		baseRegistrations: baseRegistrations,
		baseFeeRecipients: baseFeeRecipients,
		obolClient:        obolClient,
		lockHash:          lockHash,
	}

	// Apply initial file overrides if configured, otherwise just compute base state.
	if svc.path != "" {
		if err := svc.reloadFromFile(ctx); err != nil {
			return nil, err
		}
	} else {
		svc.recompute(ctx)
	}

	return svc, nil
}

// Registrations returns the current effective builder registrations.
func (s *builderRegistrationService) Registrations() []*eth2api.VersionedSignedValidatorRegistration {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.registrations
}

// FeeRecipient returns the current fee recipient address for the given pubkey.
func (s *builderRegistrationService) FeeRecipient(pubkey core.PubKey) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.feeRecipients[pubkey]
}

// Run watches the overrides file for changes, periodically fetches from the Obol API,
// and reloads when either source is updated. It blocks until ctx is cancelled.
func (s *builderRegistrationService) Run(ctx context.Context) {
	if s.path == "" && s.obolClient == nil {
		return
	}

	// Optional file watcher (nil channels if path == "").
	var (
		fileEvents <-chan fsnotify.Event
		fileErrors <-chan error
	)

	if s.path != "" {
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			log.Error(ctx, "Failed to create file watcher for builder registration overrides", err)
			return
		}
		defer watcher.Close()

		dir := filepath.Dir(s.path)
		if err := watcher.Add(dir); err != nil {
			log.Error(ctx, "Failed to watch directory for builder registration overrides", err, z.Str("dir", dir))
			return
		}

		fileEvents = watcher.Events
		fileErrors = watcher.Errors
	}

	// Optional API fetch timer (nil channel if obolClient == nil).
	var (
		fetchTimer *time.Timer
		fetchCh    <-chan time.Time
	)

	if s.obolClient != nil {
		fetchTimer = time.NewTimer(0) // Fire immediately on first iteration.
		defer fetchTimer.Stop()

		fetchCh = fetchTimer.C
	}

	baseName := filepath.Base(s.path)

	for {
		select {
		case <-ctx.Done():
			return

		case event, ok := <-fileEvents:
			if !ok {
				return
			}

			if filepath.Base(event.Name) != baseName {
				continue
			}

			if !event.Has(fsnotify.Write) && !event.Has(fsnotify.Create) {
				continue
			}

			if err := s.reloadFromFile(ctx); err != nil {
				log.Warn(ctx, "Failed to reload builder registration overrides", err)
			} else {
				log.Info(ctx, "Reloaded builder registration overrides from file", z.Str("path", s.path))
			}

			// File change also triggers an API fetch.
			if fetchTimer != nil {
				if !fetchTimer.Stop() {
					select {
					case <-fetchTimer.C:
					default:
					}
				}

				fetchTimer.Reset(0)
			}

		case err, ok := <-fileErrors:
			if !ok {
				return
			}

			log.Warn(ctx, "File watcher error for builder registration overrides", err)

		case <-fetchCh:
			hasIncomplete, err := s.fetchFromAPI(ctx)
			if err != nil {
				log.Warn(ctx, "Builder registration API fetch failed", err)
				fetchTimer.Reset(fetchIntervalIncomplete)
			} else if hasIncomplete {
				fetchTimer.Reset(fetchIntervalIncomplete)
			} else {
				fetchTimer.Reset(fetchIntervalComplete)
			}
		}
	}
}

// reloadFromFile reads the overrides file and stores file overrides, then recomputes.
func (s *builderRegistrationService) reloadFromFile(ctx context.Context) error {
	overrides, err := LoadBuilderRegistrationOverrides(s.path, s.forkVersion)
	if err != nil {
		return err
	}

	s.fileOverrides = overrides
	s.recompute(ctx)

	return nil
}

// fetchFromAPI calls the Obol API, processes the response, stores API overrides,
// and calls recompute. Returns true if any validators have incomplete registrations.
func (s *builderRegistrationService) fetchFromAPI(ctx context.Context) (bool, error) {
	resp, err := s.obolClient.PostFeeRecipientsFetch(ctx, s.lockHash, nil)
	if err != nil {
		return false, errors.Wrap(err, "fetch builder registrations from Obol API")
	}

	pv, err := ProcessValidators(resp.Validators)
	if err != nil {
		return false, errors.Wrap(err, "process fetched builder registrations")
	}

	if len(pv.AggregatedRegs) > 0 {
		// Verify signatures on aggregated registrations.
		if s.forkVersion != (eth2p0.Version{}) {
			var verified []*eth2api.VersionedSignedValidatorRegistration

			for _, reg := range pv.AggregatedRegs {
				if err := verifyRegistrationSignature(reg, s.forkVersion); err != nil {
					log.Warn(ctx, "Skipping fetched builder registration with invalid signature", err)
					continue
				}

				verified = append(verified, reg)
			}

			pv.AggregatedRegs = verified
		}

		log.Info(ctx, "Fetched builder registrations from Obol API",
			z.Int("fully_signed", len(pv.AggregatedRegs)),
			z.Int("incomplete", len(pv.Categories.Incomplete)),
		)
	}

	s.apiOverrides = pv.AggregatedRegs
	s.recompute(ctx)

	return len(pv.Categories.Incomplete) > 0, nil
}

// recompute merges file and API overrides, applies them against base registrations,
// and updates the effective registrations and fee recipients.
func (s *builderRegistrationService) recompute(ctx context.Context) {
	feeRecipients := maps.Clone(s.baseFeeRecipients)

	overrides := mergeOverrides(s.fileOverrides, s.apiOverrides)

	var regs []*eth2api.VersionedSignedValidatorRegistration
	if len(overrides) > 0 {
		regs = applyBuilderRegistrationOverrides(ctx, s.baseRegistrations, overrides, feeRecipients)
	} else {
		regs = s.baseRegistrations
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.registrations = regs
	s.feeRecipients = feeRecipients
}

// mergeOverrides combines two override slices, keeping the entry with the highest
// timestamp per pubkey.
func mergeOverrides(a, b []*eth2api.VersionedSignedValidatorRegistration) []*eth2api.VersionedSignedValidatorRegistration {
	if len(a) == 0 {
		return b
	}

	if len(b) == 0 {
		return a
	}

	byPubkey := make(map[string]*eth2api.VersionedSignedValidatorRegistration)

	for _, reg := range a {
		if reg == nil || reg.V1 == nil || reg.V1.Message == nil {
			continue
		}

		key := strings.ToLower(hex.EncodeToString(reg.V1.Message.Pubkey[:]))
		byPubkey[key] = reg
	}

	for _, reg := range b {
		if reg == nil || reg.V1 == nil || reg.V1.Message == nil {
			continue
		}

		key := strings.ToLower(hex.EncodeToString(reg.V1.Message.Pubkey[:]))

		existing, ok := byPubkey[key]
		if !ok || existing.V1 == nil || existing.V1.Message == nil || reg.V1.Message.Timestamp.After(existing.V1.Message.Timestamp) {
			byPubkey[key] = reg
		}
	}

	result := make([]*eth2api.VersionedSignedValidatorRegistration, 0, len(byPubkey))
	for _, reg := range byPubkey {
		result = append(result, reg)
	}

	return result
}

// LoadBuilderRegistrationOverrides reads builder registration overrides from the given JSON file.
// It returns nil if the file does not exist. When forkVersion is non-zero, each registration's
// BLS signature is verified against the validator pubkey embedded in the message.
func LoadBuilderRegistrationOverrides(path string, forkVersion eth2p0.Version) ([]*eth2api.VersionedSignedValidatorRegistration, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, errors.Wrap(err, "read builder registration overrides file", z.Str("path", path))
	}

	var regs []*eth2api.VersionedSignedValidatorRegistration
	if err := json.Unmarshal(data, &regs); err != nil {
		return nil, errors.Wrap(err, "unmarshal builder registration overrides file", z.Str("path", path))
	}

	if forkVersion != (eth2p0.Version{}) {
		for _, reg := range regs {
			if err := verifyRegistrationSignature(reg, forkVersion); err != nil {
				return nil, err
			}
		}
	}

	return regs, nil
}

// verifyRegistrationSignature verifies the BLS signature of a single builder registration.
func verifyRegistrationSignature(reg *eth2api.VersionedSignedValidatorRegistration, forkVersion eth2p0.Version) error {
	if reg == nil || reg.V1 == nil || reg.V1.Message == nil {
		return errors.New("invalid builder registration override: nil message")
	}

	sigRoot, err := registration.GetMessageSigningRoot(reg.V1.Message, forkVersion)
	if err != nil {
		return errors.Wrap(err, "get signing root for builder registration override")
	}

	pubkey, err := tblsconv.PubkeyFromBytes(reg.V1.Message.Pubkey[:])
	if err != nil {
		return errors.Wrap(err, "convert pubkey from builder registration override")
	}

	sig, err := tblsconv.SignatureFromBytes(reg.V1.Signature[:])
	if err != nil {
		return errors.Wrap(err, "convert signature from builder registration override")
	}

	if err := tbls.Verify(pubkey, sigRoot[:], sig); err != nil {
		return errors.Wrap(err, "verify builder registration override signature",
			z.Str("pubkey", hex.EncodeToString(reg.V1.Message.Pubkey[:])),
		)
	}

	return nil
}

// applyBuilderRegistrationOverrides replaces entries in builderRegs with overrides that have
// a strictly newer timestamp for the same validator pubkey. It also updates feeRecipientByPubkey
// for overridden validators.
func applyBuilderRegistrationOverrides(
	ctx context.Context,
	builderRegs []*eth2api.VersionedSignedValidatorRegistration,
	overrides []*eth2api.VersionedSignedValidatorRegistration,
	feeRecipientByPubkey map[core.PubKey]string,
) []*eth2api.VersionedSignedValidatorRegistration {
	// Build lookup from overrides keyed by lowercase pubkey hex.
	overrideByPubkey := make(map[string]*eth2api.VersionedSignedValidatorRegistration, len(overrides))
	for _, o := range overrides {
		if o == nil || o.V1 == nil || o.V1.Message == nil {
			continue
		}

		key := strings.ToLower(hex.EncodeToString(o.V1.Message.Pubkey[:]))
		overrideByPubkey[key] = o
	}

	result := make([]*eth2api.VersionedSignedValidatorRegistration, len(builderRegs))
	for i, reg := range builderRegs {
		result[i] = reg

		if reg == nil || reg.V1 == nil || reg.V1.Message == nil {
			continue
		}

		key := strings.ToLower(hex.EncodeToString(reg.V1.Message.Pubkey[:]))

		override, ok := overrideByPubkey[key]
		if !ok {
			continue
		}

		if !override.V1.Message.Timestamp.After(reg.V1.Message.Timestamp) {
			continue
		}

		result[i] = override

		corePubkey, err := core.PubKeyFromBytes(reg.V1.Message.Pubkey[:])
		if err != nil {
			continue
		}

		feeRecipientByPubkey[corePubkey] = "0x" + hex.EncodeToString(override.V1.Message.FeeRecipient[:])

		log.Info(ctx, "Applied builder registration override for 0x"+key, z.Str("fee_recipient", feeRecipientByPubkey[corePubkey]))
	}

	return result
}
