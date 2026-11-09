// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package proposerconfig

import (
	"encoding/hex"
	"encoding/json"
	"math/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/testutil"
)

const (
	addrA = "0x000000000000000000000000000000000000000a"
	addrB = "0x000000000000000000000000000000000000000b"
)

func testLock(t *testing.T, vals int) cluster.Lock {
	t.Helper()

	lock, _, _ := cluster.NewForT(t, vals, 3, 4, 7, rand.New(rand.NewSource(7)), func(d *cluster.Definition) {
		d.Timestamp = "2026-01-01T00:00:00Z"
	})

	return lock
}

func TestHashGolden(t *testing.T) {
	lock := testLock(t, 2)

	builder := &Builder{
		MinBid:              "0",
		BuilderBoostFactor:  "100",
		MaxExecutionPayment: "0",
		Builders:            []BuilderEntry{{URL: "https://b1.example"}, {URL: "https://b2.example"}},
	}

	content, err := NewContent(lock, []string{addrA, addrB}, DefaultGasLimit, builder)
	require.NoError(t, err)

	doc := Document{Version: Version, LockHash: lock.LockHash, Revision: 1, Content: content}

	hash, err := doc.Hash()
	require.NoError(t, err)
	testutil.RequireGoldenJSON(t, "0x"+hex.EncodeToString(hash[:]))

	// The preimage has the five hashed fields in order and no whitespace.
	b, err := json.Marshal(newPreimage(doc))
	require.NoError(t, err)
	testutil.RequireGoldenBytes(t, b, testutil.WithFilename("TestHashGolden_preimage.golden"))

	s := string(b)
	last := -1

	for _, k := range []string{"version", "lock_hash", "revision", "default_config", "proposer_config"} {
		idx := strings.Index(s, `"`+k+`":`)
		require.Greater(t, idx, last, k)
		last = idx
	}

	require.NotContains(t, s, " ")
}

func TestHashIgnoresSignatures(t *testing.T) {
	lock := testLock(t, 1)
	content, err := NewContent(lock, []string{addrA}, DefaultGasLimit, nil)
	require.NoError(t, err)

	doc := Document{Version: Version, LockHash: lock.LockHash, Revision: 1, Content: content}
	h1, err := doc.Hash()
	require.NoError(t, err)

	doc.Signatures = []Signature{{Operator: 1, Signature: []byte{1}}}
	doc.StoredHash = []byte{2}
	h2, err := doc.Hash()
	require.NoError(t, err)
	require.Equal(t, h1, h2)
}

func TestHashCaseInsensitiveInputs(t *testing.T) {
	lock := testLock(t, 1)
	checksummed := "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"

	c1, err := NewContent(lock, []string{checksummed}, DefaultGasLimit, nil)
	require.NoError(t, err)
	c2, err := NewContent(lock, []string{strings.ToLower(checksummed)}, DefaultGasLimit, nil)
	require.NoError(t, err)

	h1, err := Document{Version: Version, LockHash: lock.LockHash, Revision: 1, Content: c1}.Hash()
	require.NoError(t, err)
	h2, err := Document{Version: Version, LockHash: lock.LockHash, Revision: 1, Content: c2}.Hash()
	require.NoError(t, err)
	require.Equal(t, h1, h2)
}

func TestNewContentMajority(t *testing.T) {
	lock := testLock(t, 3)
	pk := func(i int) string { return "0x" + hex.EncodeToString(lock.Validators[i].PubKey) }

	c, err := NewContent(lock, []string{addrA, addrB, addrB}, DefaultGasLimit, nil)
	require.NoError(t, err)
	require.Equal(t, addrB, c.DefaultConfig.FeeRecipient)
	require.Equal(t, "200000000", c.DefaultConfig.GasLimit)
	require.Len(t, c.ProposerConfig, 1)
	require.Equal(t, Settings{FeeRecipient: addrA}, c.ProposerConfig[pk(0)])
	require.Equal(t, []string{addrA, addrB, addrB}, c.FeeRecipients(lock))
	require.Equal(t, addrA, c.FeeRecipient(pk(0)))
	require.Equal(t, addrB, c.FeeRecipient(pk(1)))

	gas, err := c.GasLimit()
	require.NoError(t, err)
	require.Equal(t, DefaultGasLimit, gas)

	// Tie: the first validator wins.
	lock2 := testLock(t, 2)
	c, err = NewContent(lock2, []string{addrA, addrB}, DefaultGasLimit, nil)
	require.NoError(t, err)
	require.Equal(t, addrA, c.DefaultConfig.FeeRecipient)
	require.Len(t, c.ProposerConfig, 1)
}

func TestNewContentErrors(t *testing.T) {
	lock := testLock(t, 2)

	_, err := NewContent(lock, []string{addrA}, DefaultGasLimit, nil)
	require.Error(t, err)

	_, err = NewContent(lock, []string{addrA, "0x1234"}, DefaultGasLimit, nil)
	require.Error(t, err)

	_, err = NewContent(lock, []string{addrA, "nothex"}, DefaultGasLimit, nil)
	require.Error(t, err)
}

func TestNewContentEmptyLockFeeRecipients(t *testing.T) {
	lock := testLock(t, 3)
	pk := func(i int) string { return "0x" + hex.EncodeToString(lock.Validators[i].PubKey) }

	// A v1.0/v1.1 lock may have no fee recipients, empty means none.
	c, err := NewContent(lock, []string{"", "", addrA}, DefaultGasLimit, nil)
	require.NoError(t, err)
	require.Empty(t, c.DefaultConfig.FeeRecipient)
	require.Equal(t, map[string]Settings{pk(2): {FeeRecipient: addrA}}, c.ProposerConfig)
	require.Equal(t, []string{"", "", addrA}, c.FeeRecipients(lock))

	// A minority empty fee recipient emits no entry and falls back to the default.
	c, err = NewContent(lock, []string{addrA, "", addrA}, DefaultGasLimit, nil)
	require.NoError(t, err)
	require.Equal(t, addrA, c.DefaultConfig.FeeRecipient)
	require.Empty(t, c.ProposerConfig)
}

func TestNewContentAddressValidation(t *testing.T) {
	lock := testLock(t, 1)
	good := "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"

	for _, addr := range []string{
		"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD", // Wrong checksum.
		"0X" + good[2:],
		good[2:],
	} {
		_, err := NewContent(lock, []string{addr}, DefaultGasLimit, nil)
		require.Error(t, err, addr)
	}

	var hashes [][32]byte

	for _, addr := range []string{good, strings.ToLower(good)} {
		c, err := NewContent(lock, []string{addr}, DefaultGasLimit, nil)
		require.NoError(t, err)

		h, err := Document{Version: Version, LockHash: lock.LockHash, Content: c}.Hash()
		require.NoError(t, err)

		hashes = append(hashes, h)
	}

	require.Equal(t, hashes[0], hashes[1])
}

func TestHashNilEmptyBuilders(t *testing.T) {
	lock := testLock(t, 1)

	hash := func(builders []BuilderEntry) [32]byte {
		c, err := NewContent(lock, []string{addrA}, DefaultGasLimit, &Builder{MinBid: "0", BuilderBoostFactor: "100", MaxExecutionPayment: "0", Builders: builders})
		require.NoError(t, err)

		h, err := Document{Version: Version, LockHash: lock.LockHash, Content: c}.Hash()
		require.NoError(t, err)

		return h
	}

	require.Equal(t, hash(nil), hash([]BuilderEntry{}))
}

func TestHashNilEmptyBuildersInEntry(t *testing.T) {
	lock := testLock(t, 1)

	hash := func(builders []BuilderEntry) [32]byte {
		c := Content{
			DefaultConfig: Settings{FeeRecipient: addrA},
			ProposerConfig: map[string]Settings{
				"0xaa": {Builder: &Builder{MinBid: "0", BuilderBoostFactor: "100", MaxExecutionPayment: "0", Builders: builders}},
			},
		}

		h, err := Document{Version: Version, LockHash: lock.LockHash, Content: c}.Hash()
		require.NoError(t, err)

		return h
	}

	require.Equal(t, hash(nil), hash([]BuilderEntry{}))
}
