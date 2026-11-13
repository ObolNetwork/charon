// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package proposerconfig

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
)

func TestDiff(t *testing.T) {
	lock := testLock(t, 2)
	a, err := NewConfig(lock, []string{addrA, addrA}, DefaultGasLimit, nil)
	require.NoError(t, err)
	b, err := NewConfig(lock, []string{addrA, addrB}, 5, nil)
	require.NoError(t, err)

	require.Equal(t, []string{
		"default.gas_limit: 200000000 -> 5",
		"validator " + pubkeyHex(lock.Validators[1].PubKey) + ".fee_recipient: " + addrA + " -> " + addrB,
	}, Diff(lock, a, b))

	require.Empty(t, Diff(lock, a, a))
}

func TestDiffBuilder(t *testing.T) {
	lock := testLock(t, 1)
	a, err := NewConfig(lock, []string{addrA}, DefaultGasLimit, nil)
	require.NoError(t, err)
	b, err := NewConfig(lock, []string{addrA}, DefaultGasLimit, testBuilder())
	require.NoError(t, err)

	require.Equal(t, []string{
		"default.builder.urls: none -> https://b1.example",
		"default.builder.min_bid: none -> 5",
		"default.builder.boost_factor: none -> 110",
		"default.builder.max_execution_payment: none -> 7",
	}, Diff(lock, a, b))
}

func TestDiffRedactsBuilderURLs(t *testing.T) {
	lock := testLock(t, 1)
	a, err := NewConfig(lock, []string{addrA}, DefaultGasLimit, testBuilder())
	require.NoError(t, err)

	builder := testBuilder()
	builder.Builders = []BuilderEntry{{URL: "https://user:secret@b2.example"}, {URL: "https://b3.example/key?token=secret"}, {URL: "https://user:pa,ss@b4.example"}}
	b, err := NewConfig(lock, []string{addrA}, DefaultGasLimit, builder)
	require.NoError(t, err)

	// A comma in a URL does not split it before redaction.
	require.Equal(t, []string{
		"default.builder.urls: https://b1.example -> https://user:xxxxx@b2.example,https://b3.example/xxxxx?token=xxxxx,https://user:xxxxx@b4.example",
	}, Diff(lock, a, b))

	// URLs differing only in redacted parts still differ.
	builder = testBuilder()
	builder.Builders = []BuilderEntry{{URL: "https://user:other@b2.example"}}
	c, err := NewConfig(lock, []string{addrA}, DefaultGasLimit, builder)
	require.NoError(t, err)
	require.Len(t, Diff(lock, b, c), 1)
}

func TestDiffLargeLock(t *testing.T) {
	const n = 5000

	var lock cluster.Lock

	feesA := make([]string, n)
	feesB := make([]string, n)

	for i := range n {
		pubkey := make([]byte, 48)
		binary.BigEndian.PutUint32(pubkey, uint32(i))
		lock.Validators = append(lock.Validators, cluster.DistValidator{PubKey: pubkey})

		// Alternating fee recipients give half the validators an entry in both configs.
		feesA[i], feesB[i] = addrA, addrB
		if i%2 == 0 {
			feesA[i], feesB[i] = addrB, addrC
		}
	}

	a, err := NewConfig(lock, feesA, DefaultGasLimit, nil)
	require.NoError(t, err)
	b, err := NewConfig(lock, feesB, DefaultGasLimit, nil)
	require.NoError(t, err)

	start := time.Now()
	diffs := Diff(lock, a, b)

	require.Less(t, time.Since(start), time.Second)
	// Every validator and the default fee recipient.
	require.Len(t, diffs, n+1)
}
