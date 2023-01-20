package herumi

import (
	"encoding/hex"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/obolnetwork/charon/tbls/taketwo"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestHerumi_GenerateSecretKey(t *testing.T) {
	var impl taketwo.Implementation = Herumi{}

	secret, err := impl.GenerateSecretKey()
	require.NoError(t, err)
	require.NotEmpty(t, secret)
}

func TestHerumi_SecretToPublicKey(t *testing.T) {
	var impl taketwo.Implementation = Herumi{}

	secret, err := impl.GenerateSecretKey()
	require.NoError(t, err)
	require.NotEmpty(t, secret)

	pubk, err := impl.SecretToPublicKey(secret)
	require.NoError(t, err)
	require.NotEmpty(t, pubk)
}

func TestHerumi_ThresholdSplit(t *testing.T) {
	var impl taketwo.Implementation = Herumi{}

	secret, err := impl.GenerateSecretKey()
	require.NoError(t, err)
	require.NotEmpty(t, secret)

	shares, err := impl.ThresholdSplit(secret, 5, 3)
	require.NoError(t, err)
	require.NotEmpty(t, shares)
}

func TestHerumi_RecoverSecret(t *testing.T) {
	var impl taketwo.Implementation = Herumi{}

	secret, err := impl.GenerateSecretKey()
	require.NoError(t, err)
	require.NotEmpty(t, secret)

	shares, err := impl.ThresholdSplit(secret, 5, 3)
	require.NoError(t, err)

	recovered, err := impl.RecoverSecret(shares, 5, 3)
	require.NoError(t, err)

	require.Equal(t, secret, recovered)
}

func TestHerumi_ThresholdAggregate(t *testing.T) {
	var impl taketwo.Implementation = Herumi{}

	data := []byte("hello obol!")

	secret, err := impl.GenerateSecretKey()
	require.NoError(t, err)
	require.NotEmpty(t, secret)

	totalOGSig, err := impl.Sign(secret, data)
	require.NoError(t, err)

	shares, err := impl.ThresholdSplit(secret, 5, 3)
	require.NoError(t, err)

	signatures := map[int]taketwo.Signature{}

	for idx, key := range shares {
		p := bls.SecretKey{}

		require.NoError(t, p.SetHexString(hex.EncodeToString(key)))

		signature := p.SignByte(data)
		signatures[idx] = signature.Serialize()
	}

	totalSig, err := impl.ThresholdAggregate(signatures)
	require.NoError(t, err)

	require.Equal(t, totalOGSig, totalSig)
}

func TestHerumi_Verify(t *testing.T) {
	var impl taketwo.Implementation = Herumi{}

	data := []byte("hello obol!")

	secret, err := impl.GenerateSecretKey()
	require.NoError(t, err)
	require.NotEmpty(t, secret)

	signature, err := impl.Sign(secret, data)
	require.NoError(t, err)
	require.NotEmpty(t, signature)

	pubkey, err := impl.SecretToPublicKey(secret)
	require.NoError(t, err)
	require.NotEmpty(t, pubkey)

	require.NoError(t, impl.Verify(pubkey, data, signature))
}

func TestHerumi_Sign(t *testing.T) {
	var impl taketwo.Implementation = Herumi{}

	data := []byte("hello obol!")

	secret, err := impl.GenerateSecretKey()
	require.NoError(t, err)
	require.NotEmpty(t, secret)

	signature, err := impl.Sign(secret, data)
	require.NoError(t, err)
	require.NotEmpty(t, signature)
}
