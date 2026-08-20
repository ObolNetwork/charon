// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cluster

import (
	"bytes"
	"encoding/hex"
	"testing"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pk910/dynamic-ssz/hasher"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/testutil"
)

const (
	testAddr1 = "0x1111111111111111111111111111111111111111"
	testAddr2 = "0x2222222222222222222222222222222222222222"
	testAddr3 = "0x3333333333333333333333333333333333333333"
	testFee   = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testWithd = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// baseDef returns a realistic 3-operator, 2-validator Definition for the given version.
// All validators share the same fee recipient and withdrawal address so that
// LegacyValidatorAddresses() succeeds for legacy/v1.3/v1.4 hash functions.
func baseDef(version string) Definition {
	return Definition{
		UUID:          "f4c00e58-1a54-4e55-8d76-2b2a6d4c3f9a",
		Name:          "test-cluster-3of4",
		Version:       version,
		Timestamp:     "2024-06-15T12:00:00Z",
		NumValidators: 2,
		Threshold:     3,
		DKGAlgorithm:  "default",
		ForkVersion:   []byte{0x00, 0x00, 0x10, 0x20},
		Operators: []Operator{
			{Address: testAddr1, ENR: "enr:-Iu4QNHNMf"},
			{Address: testAddr2, ENR: "enr:-Iu4QABCDef"},
			{Address: testAddr3, ENR: "enr:-Iu4QXYZghi"},
		},
		Creator: Creator{Address: testAddr1},
		ValidatorAddresses: []ValidatorAddresses{
			{FeeRecipientAddress: testFee, WithdrawalAddress: testWithd},
			{FeeRecipientAddress: testFee, WithdrawalAddress: testWithd},
		},
	}
}

// runHashDef calls the version-appropriate hashDefinition* function on a fresh
// ssz.HashWalker and returns the resulting HashRoot as a hex string.
func runHashDef(t *testing.T, d Definition, configOnly bool) string {
	t.Helper()

	fn, err := getDefinitionHashFunc(d.Version)
	require.NoError(t, err)

	hh := hasher.DefaultHasherPool.Get()
	defer hasher.DefaultHasherPool.Put(hh)

	require.NoError(t, fn(d, hh, configOnly))

	h, err := hh.HashRoot()
	require.NoError(t, err)

	return hex.EncodeToString(h[:])
}

func TestHashDefinitionLegacy(t *testing.T) {
	tests := []struct {
		name       string
		d          Definition
		configOnly bool
	}{
		{
			name: "v1.0_config_no_timestamp",
			d: func() Definition {
				d := baseDef(v1_0)
				d.Timestamp = "" // v1.0 had no timestamp

				return d
			}(),
			configOnly: true,
		},
		{
			name:       "v1.2_config",
			d:          baseDef(v1_2),
			configOnly: true,
		},
		{
			name:       "v1.2_definition",
			d:          baseDef(v1_2),
			configOnly: false,
		},
	}

	roots := make(map[string]string)
	for _, tt := range tests {
		roots[tt.name] = runHashDef(t, tt.d, tt.configOnly)
	}

	testutil.RequireGoldenJSON(t, roots)
}

func TestHashDefinitionV1x3or4(t *testing.T) {
	tests := []struct {
		name       string
		d          Definition
		configOnly bool
	}{
		{
			name:       "v1.3_config",
			d:          baseDef(v1_3),
			configOnly: true,
		},
		{
			name:       "v1.3_definition",
			d:          baseDef(v1_3),
			configOnly: false,
		},
		{
			name:       "v1.4_config",
			d:          baseDef(v1_4),
			configOnly: true,
		},
	}

	roots := make(map[string]string)
	for _, tt := range tests {
		roots[tt.name] = runHashDef(t, tt.d, tt.configOnly)
	}

	testutil.RequireGoldenJSON(t, roots)
}

func TestHashDefinitionV1x5to7(t *testing.T) {
	tests := []struct {
		name       string
		d          Definition
		configOnly bool
	}{
		{
			name:       "v1.5_config",
			d:          baseDef(v1_5),
			configOnly: true,
		},
		{
			name:       "v1.7_config",
			d:          baseDef(v1_7),
			configOnly: true,
		},
	}

	roots := make(map[string]string)
	for _, tt := range tests {
		roots[tt.name] = runHashDef(t, tt.d, tt.configOnly)
	}

	testutil.RequireGoldenJSON(t, roots)
}

func TestHashDefinitionV1x8(t *testing.T) {
	tests := []struct {
		name       string
		d          Definition
		configOnly bool
	}{
		{
			name: "v1.8_config_with_deposit",
			d: func() Definition {
				d := baseDef(v1_8)
				d.DepositAmounts = []eth2p0.Gwei{32000000000}

				return d
			}(),
			configOnly: true,
		},
	}

	roots := make(map[string]string)
	for _, tt := range tests {
		roots[tt.name] = runHashDef(t, tt.d, tt.configOnly)
	}

	testutil.RequireGoldenJSON(t, roots)
}

func TestHashDefinitionV1x9(t *testing.T) {
	tests := []struct {
		name       string
		d          Definition
		configOnly bool
	}{
		{
			name: "v1.9_config_with_consensus_protocol",
			d: func() Definition {
				d := baseDef(v1_9)
				d.DepositAmounts = []eth2p0.Gwei{32000000000}
				d.ConsensusProtocol = "abft"

				return d
			}(),
			configOnly: true,
		},
	}

	roots := make(map[string]string)
	for _, tt := range tests {
		roots[tt.name] = runHashDef(t, tt.d, tt.configOnly)
	}

	testutil.RequireGoldenJSON(t, roots)
}

func TestHashDefinitionV1x10(t *testing.T) {
	tests := []struct {
		name       string
		d          Definition
		configOnly bool
	}{
		{
			name: "v1.10_config_with_gas_and_compounding",
			d: func() Definition {
				d := baseDef(v1_10)
				d.DepositAmounts = []eth2p0.Gwei{32000000000}
				d.ConsensusProtocol = "abft"
				d.TargetGasLimit = 30000000
				d.Compounding = true

				return d
			}(),
			configOnly: true,
		},
	}

	roots := make(map[string]string)
	for _, tt := range tests {
		roots[tt.name] = runHashDef(t, tt.d, tt.configOnly)
	}

	testutil.RequireGoldenJSON(t, roots)
}

func TestHashDefinitionV1x11(t *testing.T) {
	tests := []struct {
		name       string
		d          Definition
		configOnly bool
	}{
		{
			name: "v1.11_config_empty_deposit_amounts",
			d: func() Definition {
				d := baseDef(v1_11)
				d.DepositAmounts = nil
				d.ConsensusProtocol = ""

				return d
			}(),
			configOnly: true,
		},
		{
			name: "v1.11_config_deposit_amounts_with_zero_element",
			d: func() Definition {
				d := baseDef(v1_11)
				d.DepositAmounts = []eth2p0.Gwei{32000000000, 1000000000, 0}
				d.ConsensusProtocol = "qbft"
				d.TargetGasLimit = 36000000
				d.Compounding = true

				return d
			}(),
			configOnly: true,
		},
		{
			name: "v1.11_full_empty_signatures",
			d: func() Definition {
				d := baseDef(v1_11)
				d.ConfigHash = bytes.Repeat([]byte{0x0f}, 32)

				return d
			}(),
			configOnly: false,
		},
		{
			name: "v1.11_full_with_signatures",
			d: func() Definition {
				d := baseDef(v1_11)

				d.ConfigHash = bytes.Repeat([]byte{0x0f}, 32)
				for i := range d.Operators {
					d.Operators[i].ConfigSignature = bytes.Repeat([]byte{byte(i + 1)}, 65)
					d.Operators[i].ENRSignature = bytes.Repeat([]byte{byte(i + 0x10)}, 65)
				}

				// Two concatenated K1 signatures to cover multi-element signature lists.
				d.Creator.ConfigSignature = bytes.Repeat([]byte{0xcc}, 130)

				return d
			}(),
			configOnly: false,
		},
	}

	roots := make(map[string]string)
	for _, tt := range tests {
		roots[tt.name] = runHashDef(t, tt.d, tt.configOnly)
	}

	testutil.RequireGoldenJSON(t, roots)
}

func TestHashBuilderRegistration(t *testing.T) {
	const network = "goerli"

	clusterReg := RandomRegistration(t, network)

	var feeRecipient bellatrix.ExecutionAddress
	copy(feeRecipient[:], clusterReg.Message.FeeRecipient)

	pubkey, err := core.PubKeyFromBytes(clusterReg.Message.PubKey)
	require.NoError(t, err)

	eth2Pubkey, err := pubkey.ToETH2()
	require.NoError(t, err)

	eth2Reg := &eth2v1.SignedValidatorRegistration{
		Message: &eth2v1.ValidatorRegistration{
			FeeRecipient: feeRecipient,
			Timestamp:    clusterReg.Message.Timestamp,
			GasLimit:     uint64(clusterReg.Message.GasLimit),
			Pubkey:       eth2Pubkey,
		},
	}

	eth2hash, err := eth2Reg.Message.HashTreeRoot()
	require.NoError(t, err)

	hh := hasher.DefaultHasherPool.Get()
	defer hasher.DefaultHasherPool.Put(hh)

	require.NoError(t, hashRegistration(clusterReg.Message, hh))
	clusterRegHash, err := hh.HashRoot()
	require.NoError(t, err)
	require.Equal(t, eth2hash, clusterRegHash)
}
