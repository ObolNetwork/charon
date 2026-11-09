// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"bytes"
	"context"
	"path/filepath"
	"strconv"
	"sync/atomic"

	"github.com/attestantio/go-eth2-client/spec/gloas"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/fsnotify/fsnotify"

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
}

// proposerConfigHolder holds the current proposer config document and reloads it when the file changes.
type proposerConfigHolder struct {
	current atomic.Pointer[proposerConfigSnapshot]
	lock    cluster.Lock
	nodeIdx cluster.NodeIdx
	path    string
	// reloads counts the file changes attempted to reload.
	reloads atomic.Int64
}

// newProposerConfigHolder returns a holder of the document loaded from path and sets the builder gauges.
func newProposerConfigHolder(doc proposerconfig.Document, lock cluster.Lock, nodeIdx cluster.NodeIdx, path string) (*proposerConfigHolder, error) {
	snap, err := newProposerConfigSnapshot(doc)
	if err != nil {
		return nil, err
	}

	h := &proposerConfigHolder{lock: lock, nodeIdx: nodeIdx, path: path}
	h.current.Store(snap)
	initBuilderConfigMetrics(doc.Content.DefaultConfig.Builder)

	return h, nil
}

// Document returns the current document.
func (h *proposerConfigHolder) Document() proposerconfig.Document {
	return h.current.Load().doc
}

// Hash returns the current revision hash.
func (h *proposerConfigHolder) Hash() []byte {
	hash := h.current.Load().hash

	return hash[:]
}

// FeeRecipient returns the current fee recipient of the validator.
func (h *proposerConfigHolder) FeeRecipient(pubkey core.PubKey) string {
	return h.current.Load().doc.Content.FeeRecipient(string(pubkey))
}

// GasLimit returns the current default gas limit.
func (h *proposerConfigHolder) GasLimit() uint64 {
	return h.current.Load().gasLimit
}

// BuilderConfig returns the current gloas builder configuration, never nil: without builders it is the default one with no entries.
func (h *proposerConfigHolder) BuilderConfig() *gloas.BuilderConfig {
	return h.current.Load().builder
}

// BuilderHosts returns the hosts of the current builders in order.
func (h *proposerConfigHolder) BuilderHosts() []string {
	return h.current.Load().hosts
}

// Run reloads the document when its file changes, until ctx is cancelled.
func (h *proposerConfigHolder) Run(ctx context.Context) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Error(ctx, "Failed creating proposer config file watcher, changes need a restart", err)
		return nil
	}
	defer watcher.Close()

	dir := filepath.Dir(h.path)

	err = watcher.Add(dir)
	if err != nil {
		log.Error(ctx, "Failed watching proposer config directory, changes need a restart", err, z.Str("dir", dir))
		return nil
	}

	baseName := filepath.Base(h.path)

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-watcher.Errors:
			log.Warn(ctx, "Proposer config file watcher error", err)
		case event := <-watcher.Events:
			if filepath.Base(event.Name) != baseName {
				continue
			}

			if !event.Has(fsnotify.Create) && !event.Has(fsnotify.Write) && !event.Has(fsnotify.Rename) {
				continue
			}

			h.reload(ctx)
		}
	}
}

// reload swaps in the file's document if it is valid and not older than the current one. A rejected file
// keeps the previous document and raises the invalid gauge, since validator clients read the file.
func (h *proposerConfigHolder) reload(ctx context.Context) {
	h.reloads.Add(1)

	ctx = log.WithCtx(ctx, z.Str("path", h.path))
	cur := h.current.Load()
	keeping := "keeping revision " + strconv.FormatUint(cur.doc.Revision, 10)

	reject := func(msg string, err error, fields ...z.Field) {
		setProposerConfigGauges(cur.doc, false)
		log.Error(ctx, msg, err, fields...)
	}

	doc, err := proposerconfig.Load(h.path, h.lock, h.nodeIdx)
	if err != nil {
		reject("Failed reloading proposer config, "+keeping, err)
		return
	}

	err = proposerconfig.Verify(doc, h.lock)
	if err != nil {
		reject("Invalid reloaded proposer config, "+keeping, err)
		return
	}

	if doc.Revision < cur.doc.Revision {
		reject("Reloaded proposer config has a lower revision, "+keeping, nil, z.U64("revision", doc.Revision))
		return
	}

	snap, err := newProposerConfigSnapshot(doc)
	if err != nil {
		reject("Invalid reloaded proposer config, "+keeping, err)
		return
	}

	if bytes.Equal(snap.hash[:], cur.hash[:]) {
		setProposerConfigGauges(cur.doc, true)
		return
	}

	setProposerConfigGauges(doc, true)
	initBuilderConfigMetrics(doc.Content.DefaultConfig.Builder)
	h.current.Store(snap)
	log.Info(ctx, "Proposer config reloaded", revisionFields(doc)...)
}

// newProposerConfigSnapshot derives the values consumers read from the document.
func newProposerConfigSnapshot(doc proposerconfig.Document) (*proposerConfigSnapshot, error) {
	hash, err := doc.Hash()
	if err != nil {
		return nil, err
	}

	gasLimit, err := doc.Content.GasLimit()
	if err != nil {
		return nil, err
	}

	builder, err := toBuilderConfig(doc.Content.DefaultConfig.Builder)
	if err != nil {
		return nil, err
	}

	var hosts []string

	if b := doc.Content.DefaultConfig.Builder; b != nil {
		for _, entry := range b.Builders {
			host, err := eth2util.BuilderAuthData(entry.URL)
			if err != nil {
				return nil, err
			}

			hosts = append(hosts, string(host))
		}
	}

	return &proposerConfigSnapshot{doc: doc, hash: hash, gasLimit: gasLimit, builder: builder, hosts: hosts}, nil
}

// toBuilderConfig returns the gloas builder configuration of the document's builder, the default without builders if there is none.
// Each builder is a direct entry without auth, which the fetcher adds per proposal; entry fields
// override the defaults.
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
		e := &gloas.BuilderEntry{
			URL:                 []byte(entry.URL),
			BuilderPubkeys:      []eth2p0.BLSPubKey{},
			MaxExecutionPayment: eth2p0.Gwei(maxPayment),
			MinBid:              eth2p0.Gwei(minBid),
			BuilderBoostFactor:  boost,
		}

		if entry.MinBid != "" {
			v, err := parseBuilderField("min_bid", entry.MinBid)
			if err != nil {
				return nil, err
			}

			e.MinBid = eth2p0.Gwei(v)
		}

		if entry.BuilderBoostFactor != "" {
			e.BuilderBoostFactor, err = parseBuilderField("builder_boost_factor", entry.BuilderBoostFactor)
			if err != nil {
				return nil, err
			}
		}

		if entry.MaxExecutionPayment != "" {
			v, err := parseBuilderField("max_execution_payment", entry.MaxExecutionPayment)
			if err != nil {
				return nil, err
			}

			e.MaxExecutionPayment = eth2p0.Gwei(v)
		}

		builders = append(builders, e)
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
