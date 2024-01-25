// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cluster

import (
	"fmt"
	"math/rand"
	"testing"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/testutil"
)

func TestDefinitionVerify(t *testing.T) {
	var err error

	secret0, op0 := randomOperator(t)
	secret1, op1 := randomOperator(t)
	secret3, creator := randomCreator(t)

	t.Run("verify definition v1.5 solo", func(t *testing.T) {
		definition := randomDefinition(t, creator, Operator{}, Operator{},
			WithVersion(v1_5),
		)

		definition, err = signCreator(secret3, definition)
		require.NoError(t, err)

		err = definition.VerifySignatures()
		require.NoError(t, err)
	})

	t.Run("verify definition v1.5", func(t *testing.T) {
		definition := randomDefinition(t, creator, op0, op1,
			WithVersion(v1_5),
		)

		definition, err = signCreator(secret3, definition)
		require.NoError(t, err)

		definition.Operators[0], err = signOperator(secret0, definition, op0)
		require.NoError(t, err)

		definition.Operators[1], err = signOperator(secret1, definition, op1)
		require.NoError(t, err)

		err = definition.VerifySignatures()
		require.NoError(t, err)
	})

	t.Run("verify definition v1.4", func(t *testing.T) {
		definition := randomDefinition(t, creator, op0, op1,
			WithVersion(v1_4),
			WithLegacyVAddrs(testutil.RandomETHAddress(), testutil.RandomETHAddress()),
		)

		definition, err = signCreator(secret3, definition)
		require.NoError(t, err)

		definition.Operators[0], err = signOperator(secret0, definition, op0)
		require.NoError(t, err)

		definition.Operators[1], err = signOperator(secret1, definition, op1)
		require.NoError(t, err)

		err = definition.VerifySignatures()
		require.NoError(t, err)
	})

	t.Run("verify definition v1.3", func(t *testing.T) {
		definition := randomDefinition(t, Creator{}, op0, op1,
			WithVersion(v1_3),
			WithLegacyVAddrs(testutil.RandomETHAddress(), testutil.RandomETHAddress()),
		)

		definition.Operators[0], err = signOperator(secret0, definition, op0)
		require.NoError(t, err)

		definition.Operators[1], err = signOperator(secret1, definition, op1)
		require.NoError(t, err)

		err = definition.VerifySignatures()
		require.NoError(t, err)
	})

	t.Run("verify definition v1.2 or lower", func(t *testing.T) {
		def := randomDefinition(t, Creator{}, op0, op1,
			WithVersion(v1_2),
			WithLegacyVAddrs(testutil.RandomETHAddress(), testutil.RandomETHAddress()),
		)
		require.NoError(t, def.VerifySignatures())

		def = randomDefinition(t, Creator{}, op0, op1,
			WithVersion(v1_0),
			WithLegacyVAddrs(testutil.RandomETHAddress(), testutil.RandomETHAddress()),
		)
		require.NoError(t, def.VerifySignatures())
	})

	t.Run("unsigned creator and operators", func(t *testing.T) {
		def := randomDefinition(t, creator, op0, op1)
		def.Creator = Creator{}
		def.Operators = []Operator{{}, {}}

		require.NoError(t, def.VerifySignatures())
	})

	t.Run("unsigned operators v1.3", func(t *testing.T) {
		def := randomDefinition(t, creator, op0, op1,
			WithVersion(v1_3),
			WithLegacyVAddrs(testutil.RandomETHAddress(), testutil.RandomETHAddress()),
		)

		def.Operators = []Operator{{}, {}}

		require.NoError(t, def.VerifySignatures())
	})

	t.Run("empty operator signatures", func(t *testing.T) {
		def := randomDefinition(t, creator, op0, op1)

		// Empty ENR sig
		err := def.VerifySignatures()
		require.Error(t, err)
		require.ErrorContains(t, err, "empty operator enr signature")

		// Empty Config sig
		def.Operators[0].ENRSignature = []byte{1, 2, 3}
		err = def.VerifySignatures()
		require.Error(t, err)
		require.ErrorContains(t, err, "empty operator config signature")
	})

	t.Run("some operators didn't sign", func(t *testing.T) {
		definition := randomDefinition(t, creator, op0, op1)
		definition.Operators[0] = Operator{} // Operator with no address, enr sig or config sig

		// Only operator 1 signed.
		definition.Operators[1], err = signOperator(secret1, definition, op1)
		require.NoError(t, err)

		err = definition.VerifySignatures()
		require.Error(t, err)
		require.ErrorContains(t, err, "some operators signed while others didn't")
	})

	t.Run("no operators no creator", func(t *testing.T) {
		definition := randomDefinition(t, Creator{}, Operator{}, Operator{})

		err = definition.VerifySignatures()
		require.NoError(t, err)
	})

	t.Run("creator didn't sign", func(t *testing.T) {
		definition := randomDefinition(t, creator, op0, op1)
		definition.Operators[0], err = signOperator(secret0, definition, op0)
		require.NoError(t, err)

		definition.Operators[1], err = signOperator(secret1, definition, op1)
		require.NoError(t, err)

		err = definition.VerifySignatures()
		require.Error(t, err)
		require.ErrorContains(t, err, "empty creator config signature")
	})

	t.Run("solo flow definition empty operators slice", func(t *testing.T) {
		definition := randomDefinition(t, creator, Operator{}, Operator{}, func(def *Definition) {
			def.Operators = []Operator{}
		})

		definition, err = signCreator(secret3, definition)
		require.NoError(t, err)

		definition, err = definition.SetDefinitionHashes()
		require.NoError(t, err)

		err = definition.VerifyHashes()
		require.NoError(t, err)

		err = definition.VerifySignatures()
		require.NoError(t, err)
	})

	t.Run("solo flow definition empty operator structs", func(t *testing.T) {
		definition := randomDefinition(t, creator, Operator{}, Operator{}, func(definition *Definition) {
			definition.Name = "solo flow"
		})

		definition, err = signCreator(secret3, definition)
		require.NoError(t, err)

		definition, err = definition.SetDefinitionHashes()
		require.NoError(t, err)

		err = definition.VerifyHashes()
		require.NoError(t, err)

		err = definition.VerifySignatures()
		require.NoError(t, err)
	})
}

// randomOperator returns a random ETH1 private key and populated creator struct (excluding config signature).
func randomCreator(t *testing.T) (*k1.PrivateKey, Creator) {
	t.Helper()

	secret, err := k1.GeneratePrivateKey()
	require.NoError(t, err)

	addr := eth2util.PublicKeyToAddress(secret.PubKey())

	return secret, Creator{
		Address: addr,
	}
}

// randomOperator returns a random ETH1 private key and populated operator struct (excluding config signature).
func randomOperator(t *testing.T) (*k1.PrivateKey, Operator) {
	t.Helper()

	secret, err := k1.GeneratePrivateKey()
	require.NoError(t, err)

	addr := eth2util.PublicKeyToAddress(secret.PubKey())

	return secret, Operator{
		Address: addr,
		ENR:     fmt.Sprintf("enr://%x", testutil.RandomBytes32()),
	}
}

// randomDefinition returns a test cluster definition with version set to v1.4.0.
func randomDefinition(t *testing.T, cr Creator, op0, op1 Operator, opts ...func(*Definition)) Definition {
	t.Helper()

	const (
		numVals   = 2
		threshold = 2
	)

	var feeRecipientAddrs, withdrawalAddrs []string
	for i := 0; i < numVals; i++ {
		feeRecipientAddrs = append(feeRecipientAddrs, testutil.RandomETHAddress())
		withdrawalAddrs = append(withdrawalAddrs, testutil.RandomETHAddress())
	}

	definition, err := NewDefinition("test definition", numVals, threshold,
		feeRecipientAddrs, withdrawalAddrs, eth2util.Sepolia.GenesisForkVersionHex, cr, []Operator{op0, op1},
		rand.New(rand.NewSource(1)), opts...)
	require.NoError(t, err)

	return definition
}

func TestSupportEIP712Sigs(t *testing.T) {
	var (
		unsupported = v1_2
		supported   = v1_3
	)
	require.False(t, supportEIP712Sigs(unsupported))
	require.True(t, supportEIP712Sigs(supported))
}

func RandomDepositData() DepositData {
	amount := rand.Intn(31000000000) + 1000000000

	return DepositData{
		PubKey:                testutil.RandomBytes48(),
		WithdrawalCredentials: testutil.RandomBytes32(),
		Amount:                amount,
		Signature:             testutil.RandomBytes96(),
	}
}
