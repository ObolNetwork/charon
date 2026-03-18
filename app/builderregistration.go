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
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/fsnotify/fsnotify"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util/registration"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

const fileWatchDebounce = 500 * time.Millisecond

// BuilderRegistrationService provides thread-safe access to current builder
// registrations and fee recipient addresses with runtime override support.
type BuilderRegistrationService interface {
	// Registrations returns the current effective builder registrations.
	Registrations() []*eth2api.VersionedSignedValidatorRegistration
	// FeeRecipient returns the current fee recipient address for the given pubkey.
	FeeRecipient(pubkey core.PubKey) string
	// Run watches the overrides file for changes and reloads when modified.
	// It blocks until ctx is cancelled.
	Run(ctx context.Context)
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
}

// NewBuilderRegistrationService creates a new service that manages builder registrations.
// It loads and applies overrides from the given path on creation.
func NewBuilderRegistrationService(
	ctx context.Context,
	path string,
	forkVersion eth2p0.Version,
	baseRegistrations []*eth2api.VersionedSignedValidatorRegistration,
	baseFeeRecipients map[core.PubKey]string,
) (BuilderRegistrationService, error) {
	svc := &builderRegistrationService{
		path:              path,
		forkVersion:       forkVersion,
		baseRegistrations: baseRegistrations,
		baseFeeRecipients: baseFeeRecipients,
	}

	// Apply initial overrides.
	if err := svc.reload(ctx); err != nil {
		return nil, err
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

// Run watches the overrides file for changes and reloads when modified.
// It blocks until ctx is cancelled.
func (s *builderRegistrationService) Run(ctx context.Context) {
	if s.path == "" {
		return
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Error(ctx, "Failed to create file watcher for builder registration overrides", err)
		return
	}
	defer watcher.Close()

	// Watch the parent directory to catch file creation events.
	dir := filepath.Dir(s.path)
	if err := watcher.Add(dir); err != nil {
		log.Error(ctx, "Failed to watch directory for builder registration overrides", err, z.Str("dir", dir))

		return
	}

	baseName := filepath.Base(s.path)

	var debounce <-chan time.Time

	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}

			if filepath.Base(event.Name) != baseName {
				continue
			}

			if !event.Has(fsnotify.Write) && !event.Has(fsnotify.Create) {
				continue
			}

			// Debounce rapid events (editors may write multiple times).
			debounce = time.After(fileWatchDebounce)
		case <-debounce:
			if err := s.reload(ctx); err != nil {
				log.Warn(ctx, "Failed to reload builder registration overrides", err)
			} else {
				log.Info(ctx, "Reloaded builder registration overrides from file", z.Str("path", s.path))
			}

			debounce = nil
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}

			log.Warn(ctx, "File watcher error for builder registration overrides", err)
		}
	}
}

// reload reads the overrides file and re-applies overrides against base state.
func (s *builderRegistrationService) reload(ctx context.Context) error {
	feeRecipients := maps.Clone(s.baseFeeRecipients)

	if s.path == "" {
		s.mu.Lock()
		defer s.mu.Unlock()

		s.registrations = s.baseRegistrations
		s.feeRecipients = feeRecipients

		return nil
	}

	overrides, err := LoadBuilderRegistrationOverrides(s.path, s.forkVersion)
	if err != nil {
		return err
	}

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

	return nil
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
