// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package proposerconfig defines the revisioned, operator-signed proposer configuration document
// consumed by validator clients, and its canonical revision hash.
package proposerconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util"
)

const (
	// Version is the proposer config file schema version.
	Version = "v1.0.0"
	// DefaultGasLimit is the default proposer gas limit.
	DefaultGasLimit uint64 = 200_000_000
	// DefaultBuilderBoostFactor is the default builder bid boost factor percentage.
	DefaultBuilderBoostFactor uint64 = 100
)

// Settings holds one validator's proposer settings. All fields are set on default_config;
// a proposer_config entry only carries the fields diverging from it.
type Settings struct {
	FeeRecipient string   `json:"fee_recipient,omitempty"`
	GasLimit     string   `json:"gas_limit,omitempty"`
	Builder      *Builder `json:"builder,omitempty"`
}

// Builder holds the builder configuration defaults; each entry in Builders may override them.
type Builder struct {
	// MinBid is the minimum bid value in gwei.
	MinBid string `json:"min_bid"`
	// BuilderBoostFactor is the percentage multiplier applied to builder bid values.
	BuilderBoostFactor string `json:"builder_boost_factor"`
	// MaxExecutionPayment is the maximum execution layer payment in gwei counted when valuing a bid.
	MaxExecutionPayment string `json:"max_execution_payment"`
	// Builders lists the builders to request execution payload bids from directly.
	Builders []BuilderEntry `json:"builders"`
}

// BuilderEntry is one builder; the optional fields override the enclosing Builder values.
type BuilderEntry struct {
	URL                 string `json:"url"`
	MinBid              string `json:"min_bid,omitempty"`
	BuilderBoostFactor  string `json:"builder_boost_factor,omitempty"`
	MaxExecutionPayment string `json:"max_execution_payment,omitempty"`
}

// Content is the signed part of the document. ProposerConfig is keyed by lowercase 0x DV public key
// and only holds validators diverging from DefaultConfig.
type Content struct {
	DefaultConfig  Settings            `json:"default_config"`
	ProposerConfig map[string]Settings `json:"proposer_config"`
}

// Signature is an operator's signature of the revision hash.
type Signature struct {
	Operator  int `json:"operator"`
	Signature []byte
}

// Document is a revisioned proposer config. Signatures and StoredHash are not part of the revision hash.
type Document struct {
	Version    string
	LockHash   []byte
	Revision   uint64
	Content    Content
	Signatures []Signature
	StoredHash []byte
}

// preimage is the canonical hashed form of a Document, field order is part of the format.
type preimage struct {
	Version        string              `json:"version"`
	LockHash       string              `json:"lock_hash"`
	Revision       string              `json:"revision"`
	DefaultConfig  Settings            `json:"default_config"`
	ProposerConfig map[string]Settings `json:"proposer_config"`
}

func newPreimage(d Document) preimage {
	proposerConfig := make(map[string]Settings, len(d.Content.ProposerConfig))
	for k, v := range d.Content.ProposerConfig {
		proposerConfig[k] = canonicalSettings(v)
	}

	return preimage{
		Version:        d.Version,
		LockHash:       "0x" + hex.EncodeToString(d.LockHash),
		Revision:       strconv.FormatUint(d.Revision, 10),
		DefaultConfig:  canonicalSettings(d.Content.DefaultConfig),
		ProposerConfig: proposerConfig,
	}
}

// canonicalSettings returns a copy with a nil builders list as an empty one, so nil and empty hash equal.
func canonicalSettings(s Settings) Settings {
	if s.Builder != nil && s.Builder.Builders == nil {
		b := *s.Builder
		b.Builders = []BuilderEntry{}
		s.Builder = &b
	}

	return s
}

// Hash returns the revision hash: sha256 over the canonical JSON of the hashed fields.
func (d Document) Hash() ([32]byte, error) {
	b, err := json.Marshal(newPreimage(d))
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "marshal proposer config preimage")
	}

	return sha256.Sum256(b), nil
}

// NewContent returns the content for the lock with one fee recipient per lock validator. The default
// config holds the majority fee recipient (ties go to the first validator holding it) and the gas limit
// and builder; entries only exist for validators diverging from the majority. An empty fee recipient,
// as in v1.0 and v1.1 locks, means none: it emits no entry.
func NewContent(lock cluster.Lock, feeRecipients []string, gasLimit uint64, builder *Builder) (Content, error) {
	if len(feeRecipients) != len(lock.Validators) {
		return Content{}, errors.New("fee recipient count mismatch", z.Int("fee_recipients", len(feeRecipients)), z.Int("validators", len(lock.Validators)))
	}

	fees := make([]string, len(feeRecipients))
	counts := make(map[string]int)

	for i, addr := range feeRecipients {
		if addr == "" {
			counts[""]++
			continue
		}

		fee, err := normaliseAddress(addr)
		if err != nil {
			return Content{}, errors.Wrap(err, "fee recipient", z.Int("validator", i))
		}

		fees[i] = fee
		counts[fee]++
	}

	var defaultFee string

	for _, fee := range fees {
		if counts[fee] > counts[defaultFee] {
			defaultFee = fee
		}
	}

	content := Content{
		DefaultConfig: Settings{
			FeeRecipient: defaultFee,
			GasLimit:     strconv.FormatUint(gasLimit, 10),
			Builder:      builder,
		},
		ProposerConfig: make(map[string]Settings),
	}

	for i, val := range lock.Validators {
		if fees[i] != "" && fees[i] != defaultFee {
			content.ProposerConfig[pubkeyHex(val.PubKey)] = Settings{FeeRecipient: fees[i]}
		}
	}

	return content, nil
}

// FeeRecipient returns the validator's fee recipient, falling back to the default config.
func (c Content) FeeRecipient(pubkey string) string {
	if s, ok := c.ProposerConfig[strings.ToLower(pubkey)]; ok && s.FeeRecipient != "" {
		return s.FeeRecipient
	}

	return c.DefaultConfig.FeeRecipient
}

// FeeRecipients returns the fee recipient of each lock validator, in lock order.
func (c Content) FeeRecipients(lock cluster.Lock) []string {
	res := make([]string, 0, len(lock.Validators))
	for _, val := range lock.Validators {
		res = append(res, c.FeeRecipient(pubkeyHex(val.PubKey)))
	}

	return res
}

// GasLimit returns the default config's gas limit.
func (c Content) GasLimit() (uint64, error) {
	gas, err := strconv.ParseUint(c.DefaultConfig.GasLimit, 10, 64)
	if err != nil {
		return 0, errors.Wrap(err, "parse gas limit", z.Str("gas_limit", c.DefaultConfig.GasLimit))
	}

	return gas, nil
}

func pubkeyHex(pubkey []byte) string {
	return "0x" + hex.EncodeToString(pubkey)
}

// normaliseAddress validates an Ethereum address (EIP-55 checksum when mixed case) and returns it lowercased.
func normaliseAddress(addr string) (string, error) {
	checksummed, err := eth2util.ValidateChecksumAddress(addr)
	if err != nil {
		return "", errors.Wrap(err, "validate address", z.Str("address", addr))
	}

	return strings.ToLower(checksummed), nil
}

// Normalise returns a copy of c with fee recipients lowercased after EIP-55 validation and
// proposer_config keys lowercased. Empty fee recipients are kept.
func Normalise(c Content) (Content, error) {
	norm := func(s Settings) (Settings, error) {
		if s.FeeRecipient == "" {
			return s, nil
		}

		fee, err := normaliseAddress(s.FeeRecipient)
		if err != nil {
			return Settings{}, err
		}

		s.FeeRecipient = fee

		return s, nil
	}

	def, err := norm(c.DefaultConfig)
	if err != nil {
		return Content{}, errors.Wrap(err, "default config")
	}

	res := Content{DefaultConfig: def, ProposerConfig: make(map[string]Settings, len(c.ProposerConfig))}

	for k, v := range c.ProposerConfig {
		s, err := norm(v)
		if err != nil {
			return Content{}, errors.Wrap(err, "proposer config entry", z.Str("pubkey", k))
		}

		res.ProposerConfig[strings.ToLower(k)] = s
	}

	return res, nil
}
