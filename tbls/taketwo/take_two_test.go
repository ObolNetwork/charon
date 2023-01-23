package taketwo_test

import (
	"github.com/obolnetwork/charon/tbls/taketwo"
	herumiImpl "github.com/obolnetwork/charon/tbls/taketwo/herumi"
	"github.com/obolnetwork/charon/tbls/taketwo/kryptology"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"testing"
)

type TestSuite struct {
	suite.Suite

	impl taketwo.Implementation
}

func NewTestSuite(implementation taketwo.Implementation) TestSuite {
	return TestSuite{
		impl: implementation,
	}
}

func (ts *TestSuite) SetupTest() {
	taketwo.SetImplementation(ts.impl)
}

func (ts *TestSuite) Test_GenerateSecretKey() {
	secret, err := ts.impl.GenerateSecretKey()
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), secret)
}

func (ts *TestSuite) Test_SecretToPublicKey() {
	secret, err := ts.impl.GenerateSecretKey()
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), secret)

	pubk, err := ts.impl.SecretToPublicKey(secret)
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), pubk)
}

func (ts *TestSuite) Test_ThresholdSplit() {
	secret, err := ts.impl.GenerateSecretKey()
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), secret)

	shares, err := ts.impl.ThresholdSplit(secret, 5, 3)
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), shares)
}

func (ts *TestSuite) Test_RecoverSecret() {
	secret, err := ts.impl.GenerateSecretKey()
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), secret)

	shares, err := ts.impl.ThresholdSplit(secret, 5, 3)
	require.NoError(ts.T(), err)

	recovered, err := ts.impl.RecoverSecret(shares, 5, 3)
	require.NoError(ts.T(), err)

	require.Equal(ts.T(), secret, recovered)
}

func (ts *TestSuite) Test_ThresholdAggregate() {
	data := []byte("hello obol!")

	secret, err := ts.impl.GenerateSecretKey()
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), secret)

	totalOGSig, err := ts.impl.Sign(secret, data)
	require.NoError(ts.T(), err)

	shares, err := ts.impl.ThresholdSplit(secret, 5, 3)
	require.NoError(ts.T(), err)

	signatures := map[int]taketwo.Signature{}

	for idx, key := range shares {
		signature, err := ts.impl.Sign(key, data)
		require.NoError(ts.T(), err)
		signatures[idx] = signature
	}

	totalSig, err := ts.impl.ThresholdAggregate(signatures)
	require.NoError(ts.T(), err)

	require.Equal(ts.T(), totalOGSig, totalSig)
}

func (ts *TestSuite) Test_Verify() {
	data := []byte("hello obol!")

	secret, err := ts.impl.GenerateSecretKey()
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), secret)

	signature, err := ts.impl.Sign(secret, data)
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), signature)

	pubkey, err := ts.impl.SecretToPublicKey(secret)
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), pubkey)

	require.NoError(ts.T(), ts.impl.Verify(pubkey, data, signature))
}

func (ts *TestSuite) Test_Sign() {
	data := []byte("hello obol!")

	secret, err := ts.impl.GenerateSecretKey()
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), secret)

	signature, err := ts.impl.Sign(secret, data)
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), signature)
}

func runSuite(t *testing.T, i taketwo.Implementation) {
	ts := NewTestSuite(i)

	suite.Run(t, &ts)
}

func TestHerumiImplementation(t *testing.T) {
	runSuite(t, herumiImpl.Herumi{})
}

func TestKryptologyImplementation(t *testing.T) {
	runSuite(t, kryptology.Kryptology{})
}
