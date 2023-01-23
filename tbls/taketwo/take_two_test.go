package taketwo_test

import (
	"crypto/rand"
	"github.com/obolnetwork/charon/tbls/taketwo"
	herumiImpl "github.com/obolnetwork/charon/tbls/taketwo/herumi"
	"github.com/obolnetwork/charon/tbls/taketwo/kryptology"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"math/big"
	"testing"
)

type TestSuite struct {
	suite.Suite

	impl taketwo.Implementation
}

func NewTestSuite(implementations taketwo.Implementation) TestSuite {
	return TestSuite{
		impl: implementations,
	}
}

func (ts *TestSuite) SetupTest() {
	taketwo.SetImplementation(ts.impl)
}

func (ts *TestSuite) Test_GenerateSecretKey() {
	secret, err := taketwo.GenerateSecretKey()
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), secret)
}

func (ts *TestSuite) Test_SecretToPublicKey() {
	secret, err := taketwo.GenerateSecretKey()
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), secret)

	pubk, err := taketwo.SecretToPublicKey(secret)
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), pubk)
}

func (ts *TestSuite) Test_ThresholdSplit() {
	secret, err := taketwo.GenerateSecretKey()
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), secret)

	shares, err := taketwo.ThresholdSplit(secret, 5, 3)
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), shares)
}

func (ts *TestSuite) Test_RecoverSecret() {
	secret, err := taketwo.GenerateSecretKey()
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), secret)

	shares, err := taketwo.ThresholdSplit(secret, 5, 3)
	require.NoError(ts.T(), err)

	recovered, err := taketwo.RecoverSecret(shares, 5, 3)
	require.NoError(ts.T(), err)

	require.Equal(ts.T(), secret, recovered)
}

func (ts *TestSuite) Test_ThresholdAggregate() {
	data := []byte("hello obol!")

	secret, err := taketwo.GenerateSecretKey()
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), secret)

	totalOGSig, err := taketwo.Sign(secret, data)
	require.NoError(ts.T(), err)

	shares, err := taketwo.ThresholdSplit(secret, 5, 3)
	require.NoError(ts.T(), err)

	signatures := map[int]taketwo.Signature{}

	for idx, key := range shares {
		signature, err := taketwo.Sign(key, data)
		require.NoError(ts.T(), err)
		signatures[idx] = signature
	}

	totalSig, err := taketwo.ThresholdAggregate(signatures)
	require.NoError(ts.T(), err)

	require.Equal(ts.T(), totalOGSig, totalSig)
}

func (ts *TestSuite) Test_Verify() {
	data := []byte("hello obol!")

	secret, err := taketwo.GenerateSecretKey()
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), secret)

	signature, err := taketwo.Sign(secret, data)
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), signature)

	pubkey, err := taketwo.SecretToPublicKey(secret)
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), pubkey)

	require.NoError(ts.T(), taketwo.Verify(pubkey, data, signature))
}

func (ts *TestSuite) Test_Sign() {
	data := []byte("hello obol!")

	secret, err := taketwo.GenerateSecretKey()
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), secret)

	signature, err := taketwo.Sign(secret, data)
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

func TestRandomized(t *testing.T) {
	runSuite(t, randomizedImpl{
		implementations: []taketwo.Implementation{
			herumiImpl.Herumi{},
			kryptology.Kryptology{},
		},
	})
}

// randomizedImpl randomizes execution of each call by choosing a random element from
// the implementations slice.
// Useful to test whether two implementations are compatible.
type randomizedImpl struct {
	implementations []taketwo.Implementation
}

func (r randomizedImpl) selectImpl() (taketwo.Implementation, error) {
	blen := big.NewInt(int64(len(r.implementations)))

	// random number: [0, len(ts.impl))
	rawN, err := rand.Int(rand.Reader, blen)
	if err != nil {
		return nil, err
	}

	nativeN := int(rawN.Int64())

	return r.implementations[nativeN], nil
}

func (r randomizedImpl) GenerateSecretKey() (taketwo.PrivateKey, error) {
	impl, err := r.selectImpl()
	if err != nil {
		return nil, err
	}

	return impl.GenerateSecretKey()
}

func (r randomizedImpl) SecretToPublicKey(key taketwo.PrivateKey) (taketwo.PublicKey, error) {
	impl, err := r.selectImpl()
	if err != nil {
		return nil, err
	}

	return impl.SecretToPublicKey(key)
}

func (r randomizedImpl) ThresholdSplit(secret taketwo.PrivateKey, total uint, threshold uint) (map[int]taketwo.PrivateKey, error) {
	impl, err := r.selectImpl()
	if err != nil {
		return nil, err
	}

	return impl.ThresholdSplit(secret, total, threshold)
}

func (r randomizedImpl) RecoverSecret(shares map[int]taketwo.PrivateKey, total uint, threshold uint) (taketwo.PrivateKey, error) {
	impl, err := r.selectImpl()
	if err != nil {
		return nil, err
	}

	return impl.RecoverSecret(shares, total, threshold)
}

func (r randomizedImpl) ThresholdAggregate(partialSignaturesByIndex map[int]taketwo.Signature) (taketwo.Signature, error) {
	impl, err := r.selectImpl()
	if err != nil {
		return nil, err
	}

	return impl.ThresholdAggregate(partialSignaturesByIndex)
}

func (r randomizedImpl) Verify(compressedPublicKey taketwo.PublicKey, data []byte, signature taketwo.Signature) error {
	impl, err := r.selectImpl()
	if err != nil {
		return err
	}

	return impl.Verify(compressedPublicKey, data, signature)
}

func (r randomizedImpl) Sign(privateKey taketwo.PrivateKey, data []byte) (taketwo.Signature, error) {
	impl, err := r.selectImpl()
	if err != nil {
		return nil, err
	}

	return impl.Sign(privateKey, data)
}
