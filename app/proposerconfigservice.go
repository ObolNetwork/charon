// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"bytes"
	"context"
	"strconv"
	"sync/atomic"

	"github.com/attestantio/go-eth2-client/spec/gloas"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/proposerconfig"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util"
)

// proposerConfigSnapshot is a document with the values derived from it, swapped atomically on reload.
type proposerConfigSnapshot struct {
	doc      proposerconfig.Document
	hash     [32]byte
	gasLimit uint64
	builder  *gloas.BuilderConfig
	hosts    []string
	// verified is false for a file served on start although it fails verification, which any verified file replaces.
	verified bool
}

// proposerConfigService serves the current proposer config document and reloads it when the file changes.
type proposerConfigService struct {
	current atomic.Pointer[proposerConfigSnapshot]
	lock    cluster.Lock
	nodeIdx cluster.NodeIdx
	path    string
	// changes receives the file changes to reload, nil without a watcher.
	changes <-chan struct{}
	// reloads counts the file changes attempted to reload.
	reloads atomic.Int64
}

// Document returns the current document.
func (s *proposerConfigService) Document() proposerconfig.Document {
	return s.current.Load().doc
}

// Hash returns the current revision hash.
func (s *proposerConfigService) Hash() []byte {
	hash := s.current.Load().hash

	return hash[:]
}

// FeeRecipient returns the current fee recipient of the validator.
func (s *proposerConfigService) FeeRecipient(pubkey core.PubKey) string {
	return s.current.Load().doc.Config.FeeRecipient(string(pubkey))
}

// GasLimit returns the current default gas limit.
func (s *proposerConfigService) GasLimit() uint64 {
	return s.current.Load().gasLimit
}

// BuilderConfig returns the current gloas builder configuration, never nil: without builders it is the default one with no entries.
func (s *proposerConfigService) BuilderConfig() *gloas.BuilderConfig {
	return s.current.Load().builder
}

// BuilderHosts returns the hosts of the current builders in order.
func (s *proposerConfigService) BuilderHosts() []string {
	return s.current.Load().hosts
}

// Run reloads the document on each file change until ctx is cancelled; it only waits without a watcher.
func (s *proposerConfigService) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case _, ok := <-s.changes:
			if !ok {
				return nil
			}

			s.reload(ctx)
		}
	}
}

// reload swaps in the file's document if it is valid and not older than the current one. A rejected file keeps
// the previous document and raises the invalid gauge: validator clients reading the file may follow it regardless,
// which the log says.
func (s *proposerConfigService) reload(ctx context.Context) {
	s.reloads.Add(1)

	ctx = log.WithCtx(ctx, z.Str("path", s.path))
	cur := s.current.Load()
	keeping := "keeping revision " + strconv.FormatUint(cur.doc.Revision, 10) + " while validator clients may use the file"

	reject := func(msg string, err error, fields ...z.Field) {
		setProposerConfigGauges(cur.doc, false)
		log.Error(ctx, msg, err, fields...)
	}

	doc, err := proposerconfig.Load(s.path, s.lock, s.nodeIdx)
	if err != nil {
		reject("Failed reloading proposer config, "+keeping, err)
		return
	}

	err = proposerconfig.Verify(doc, s.lock)
	if err != nil {
		reject("Invalid reloaded proposer config, "+keeping, err)
		return
	}

	// The current document guards against rollbacks and conflicting agreements only if it is verified itself.
	if cur.verified && doc.Revision < cur.doc.Revision {
		reject("Reloaded proposer config has a lower revision, "+keeping, nil, z.U64("revision", doc.Revision))
		return
	}

	snap, err := newProposerConfigSnapshot(doc, true)
	if err != nil {
		reject("Invalid reloaded proposer config, "+keeping, err)
		return
	}

	if cur.verified && bytes.Equal(snap.hash[:], cur.hash[:]) {
		setProposerConfigGauges(cur.doc, true)
		return
	}

	// A signed revision is agreed once, the same revision with other content is another agreement.
	if cur.verified && doc.Revision > 0 && doc.Revision == cur.doc.Revision {
		reject("Reloaded proposer config has the current revision with other content, "+keeping, nil,
			z.Hex("revision_hash", snap.hash[:]), z.Hex("current_revision_hash", cur.hash[:]))

		return
	}

	setProposerConfigGauges(doc, true)
	initBuilderConfigMetrics(snap.builder)
	s.current.Store(snap)
	log.Info(ctx, "Proposer config reloaded", revisionFields(doc)...)
}

// newProposerConfigSnapshot derives the values consumers read from the document.
func newProposerConfigSnapshot(doc proposerconfig.Document, verified bool) (*proposerConfigSnapshot, error) {
	hash, err := doc.Hash()
	if err != nil {
		return nil, err
	}

	gasLimit, err := doc.Config.GasLimit()
	if err != nil {
		return nil, err
	}

	builder, err := toBuilderConfig(doc.Config.DefaultConfig.Builder)
	if err != nil {
		return nil, err
	}

	var hosts []string

	if b := doc.Config.DefaultConfig.Builder; b != nil {
		for _, entry := range b.Builders {
			host, err := eth2util.BuilderAuthData(entry.URL)
			if err != nil {
				return nil, err
			}

			hosts = append(hosts, string(host))
		}
	}

	return &proposerConfigSnapshot{doc: doc, hash: hash, gasLimit: gasLimit, builder: builder, hosts: hosts, verified: verified}, nil
}

// toBuilderConfig returns the gloas builder configuration of the document's builder, the default without builders if
// there is none. Each builder is a direct entry without auth, which the fetcher adds per proposal, carrying the
// default values: the file allows no per-builder overrides.
func toBuilderConfig(b *proposerconfig.Builder) (*gloas.BuilderConfig, error) {
	if b == nil {
		// The EPBS proposal request requires a builder config, so no builders is the default one.
		return &gloas.BuilderConfig{BuilderBoostFactor: proposerconfig.DefaultBuilderBoostFactor, Builders: []*gloas.BuilderEntry{}}, nil
	}

	minBid, err := parseBuilderField("min_bid", b.MinBid)
	if err != nil {
		return nil, err
	}

	boost, err := parseBuilderField("builder_boost_factor", b.BuilderBoostFactor)
	if err != nil {
		return nil, err
	}

	maxPayment, err := parseBuilderField("max_execution_payment", b.MaxExecutionPayment)
	if err != nil {
		return nil, err
	}

	builders := make([]*gloas.BuilderEntry, 0, len(b.Builders))
	for _, entry := range b.Builders {
		builders = append(builders, &gloas.BuilderEntry{
			URL:                 []byte(entry.URL),
			BuilderPubkeys:      []eth2p0.BLSPubKey{},
			MaxExecutionPayment: eth2p0.Gwei(maxPayment),
			MinBid:              eth2p0.Gwei(minBid),
			BuilderBoostFactor:  boost,
		})
	}

	return &gloas.BuilderConfig{
		MinBid:             eth2p0.Gwei(minBid),
		BuilderBoostFactor: boost,
		Builders:           builders,
	}, nil
}

// parseBuilderField parses a decimal builder setting.
func parseBuilderField(name, value string) (uint64, error) {
	v, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, errors.Wrap(err, "parse builder "+name, z.Str("value", value))
	}

	return v, nil
}
