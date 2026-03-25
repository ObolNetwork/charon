// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cluster

import (
	"encoding/hex"
	"testing"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	ssz "github.com/ferranbt/fastssz"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
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

	hh := ssz.DefaultHasherPool.Get()
	defer ssz.DefaultHasherPool.Put(hh)

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
		expected   string
	}{
		{
			name: "v1.0_config_no_timestamp",
			d: func() Definition {
				d := baseDef(v1_0)
				d.Timestamp = "" // v1.0 had no timestamp
				return d
			}(),
			configOnly: true,
			expected:   "90336d34257fd9b1c2b6b119d008e7f0cff112e91455e24b0666e23aae480216",
		},
		{
			name:       "v1.2_config",
			d:          baseDef(v1_2),
			configOnly: true,
			expected:   "36e332cad485463ba6deb041fd5b3949fd7a09e3c1eb456bb3d9f97b8ae31673",
		},
		{
			name:       "v1.2_definition",
			d:          baseDef(v1_2),
			configOnly: false,
			expected:   "c81916384a24056a596f2d87daf6f2693c12f9df9601122436dfbce0c0e51ed2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, runHashDef(t, tt.d, tt.configOnly))
		})
	}
}

func TestHashDefinitionV1x3or4(t *testing.T) {
	tests := []struct {
		name       string
		d          Definition
		configOnly bool
		expected   string
	}{
		{
			name:       "v1.3_config",
			d:          baseDef(v1_3),
			configOnly: true,
			expected:   "e314abc0c7bc2dbf22a4c6c044481880675e47eed15bf7b734ce2a275dfbf81a",
		},
		{
			name:       "v1.3_definition",
			d:          baseDef(v1_3),
			configOnly: false,
			expected:   "6fb8988d9ecfc3abab94b79e1abd07564004a1da3b59a84d3158b2a001ee2fd5",
		},
		{
			name:       "v1.4_config",
			d:          baseDef(v1_4),
			configOnly: true,
			expected:   "068e5c2c4262e4fef6f99f858a3d7ceb2243bc411d9523d445a38752da68dec7",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, runHashDef(t, tt.d, tt.configOnly))
		})
	}
}

func TestHashDefinitionV1x5to7(t *testing.T) {
	tests := []struct {
		name       string
		d          Definition
		configOnly bool
		expected   string
	}{
		{
			name:       "v1.5_config",
			d:          baseDef(v1_5),
			configOnly: true,
			expected:   "16612ab44e0e3605ab74f2d711afe6db71ab673967aa3be4ee565f3aa64415a9",
		},
		{
			name:       "v1.7_config",
			d:          baseDef(v1_7),
			configOnly: true,
			expected:   "c0ade8b834d7731f4076d364472be55974a9cb23ed97cc828bf5661b1df1c564",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, runHashDef(t, tt.d, tt.configOnly))
		})
	}
}

func TestHashDefinitionV1x8(t *testing.T) {
	tests := []struct {
		name       string
		d          Definition
		configOnly bool
		expected   string
	}{
		{
			name: "v1.8_config_with_deposit",
			d: func() Definition {
				d := baseDef(v1_8)
				d.DepositAmounts = []eth2p0.Gwei{32000000000}
				return d
			}(),
			configOnly: true,
			expected:   "cbdb72b363a735e1f469cbd7983734d524001a68dcf3ab71153d69892fa0e36c",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, runHashDef(t, tt.d, tt.configOnly))
		})
	}
}

func TestHashDefinitionV1x9(t *testing.T) {
	tests := []struct {
		name       string
		d          Definition
		configOnly bool
		expected   string
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
			expected:   "8c55a5a65d8f8dbecaf6fbd39a11c2e701ce3aba1dd7fdd212a35c2e196db34f",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, runHashDef(t, tt.d, tt.configOnly))
		})
	}
}

func TestHashDefinitionV1x10(t *testing.T) {
	tests := []struct {
		name       string
		d          Definition
		configOnly bool
		expected   string
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
			expected:   "5e16fdd44a25d37ebce15ea9d2069ec9d0930ce8d3a0e9091f82edae5969b306",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, runHashDef(t, tt.d, tt.configOnly))
		})
	}
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

	hh := ssz.DefaultHasherPool.Get()
	defer ssz.DefaultHasherPool.Put(hh)

	require.NoError(t, hashRegistration(clusterReg.Message, hh))
	clusterRegHash, err := hh.HashRoot()
	require.NoError(t, err)
	require.Equal(t, eth2hash, clusterRegHash)
}
