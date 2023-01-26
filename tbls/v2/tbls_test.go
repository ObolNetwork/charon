package v2_test

import (
	"crypto/rand"
	"math/big"
	"testing"

	v2 "github.com/obolnetwork/charon/tbls/v2"
	herumiImpl "github.com/obolnetwork/charon/tbls/v2/herumi"
	"github.com/obolnetwork/charon/tbls/v2/kryptology"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type TestSuite struct {
	suite.Suite

	impl v2.Implementation
}

func NewTestSuite(implementations v2.Implementation) TestSuite {
	return TestSuite{
		impl: implementations,
	}
}

func (ts *TestSuite) SetupTest() {
	v2.SetImplementation(ts.impl)
}

func (ts *TestSuite) Test_GenerateSecretKey() {
	secret, err := v2.GenerateSecretKey()
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), secret)
}

func (ts *TestSuite) Test_SecretToPublicKey() {
	secret, err := v2.GenerateSecretKey()
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), secret)

	pubk, err := v2.SecretToPublicKey(secret)
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), pubk)
}

func (ts *TestSuite) Test_ThresholdSplit() {
	secret, err := v2.GenerateSecretKey()
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), secret)

	shares, err := v2.ThresholdSplit(secret, 5, 3)
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), shares)
}

func (ts *TestSuite) Test_RecoverSecret() {
	secret, err := v2.GenerateSecretKey()
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), secret)

	shares, err := v2.ThresholdSplit(secret, 5, 3)
	require.NoError(ts.T(), err)

	recovered, err := v2.RecoverSecret(shares, 5, 3)
	require.NoError(ts.T(), err)

	require.ElementsMatch(ts.T(), secret, recovered)
}

func (ts *TestSuite) Test_ThresholdAggregate() {
	data := []byte("hello obol!")

	secret, err := v2.GenerateSecretKey()
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), secret)

	totalOGSig, err := v2.Sign(secret, data)
	require.NoError(ts.T(), err)

	shares, err := v2.ThresholdSplit(secret, 5, 3)
	require.NoError(ts.T(), err)

	signatures := map[int]v2.Signature{}

	for idx, key := range shares {
		signature, err := v2.Sign(key, data)
		require.NoError(ts.T(), err)
		signatures[idx] = signature
	}

	totalSig, err := v2.ThresholdAggregate(signatures)
	require.NoError(ts.T(), err)

	require.Equal(ts.T(), totalOGSig, totalSig)
}

func (ts *TestSuite) Test_Verify() {
	data := []byte("hello obol!")

	secret, err := v2.GenerateSecretKey()
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), secret)

	signature, err := v2.Sign(secret, data)
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), signature)

	pubkey, err := v2.SecretToPublicKey(secret)
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), pubkey)

	require.NoError(ts.T(), v2.Verify(pubkey, data, signature))
}

func (ts *TestSuite) Test_Sign() {
	data := []byte("hello obol!")

	secret, err := v2.GenerateSecretKey()
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), secret)

	signature, err := v2.Sign(secret, data)
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), signature)
}

func runSuite(t *testing.T, i v2.Implementation) {
	t.Helper()
	ts := NewTestSuite(i)

	suite.Run(t, &ts)
}

func TestHerumiImplementation(t *testing.T) {
	runSuite(t, herumiImpl.Herumi{})
}

func TestKryptologyImplementation(t *testing.T) {
	runSuite(t, kryptology.Kryptology{})
}

func runBenchmark(b *testing.B, impl v2.Implementation) {
	b.Helper()
	s := NewTestSuite(impl)
	t := &testing.T{}
	s.SetT(t)
	s.SetupTest()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// NOTE: we can't run suite.Run() here because testify doesn't allow us to pass testing.B in place of
		// testing.T.
		// So we're manually listing all the interface's methods here.
		// I'm sorry.
		s.Test_GenerateSecretKey()
		s.Test_SecretToPublicKey()
		s.Test_ThresholdSplit()
		s.Test_RecoverSecret()
		s.Test_ThresholdAggregate()
		s.Test_Verify()
		s.Test_Sign()
	}
}

func BenchmarkHerumiImplementation(b *testing.B) {
	runBenchmark(b, herumiImpl.Herumi{})
}

func BenchmarkKryptologyImplementation(b *testing.B) {
	runBenchmark(b, kryptology.Kryptology{})
}

func TestRandomized(t *testing.T) {
	runSuite(t, randomizedImpl{
		implementations: []v2.Implementation{
			herumiImpl.Herumi{},
			kryptology.Kryptology{},
		},
	})
}

// randomizedImpl randomizes execution of each call by choosing a random element from
// the implementations slice.
// Useful to test whether two implementations are compatible.
type randomizedImpl struct {
	implementations []v2.Implementation
}

func (r randomizedImpl) selectImpl() (v2.Implementation, error) {
	blen := big.NewInt(int64(len(r.implementations)))

	// random number: [0, len(ts.impl))
	rawN, err := rand.Int(rand.Reader, blen)
	if err != nil {
		//nolint:wrapcheck
		return nil, err
	}

	nativeN := int(rawN.Int64())

	return r.implementations[nativeN], nil
}

func (r randomizedImpl) GenerateSecretKey() (v2.PrivateKey, error) {
	impl, err := r.selectImpl()
	if err != nil {
		return v2.PrivateKey{}, err
	}

	return impl.GenerateSecretKey()
}

func (r randomizedImpl) SecretToPublicKey(key v2.PrivateKey) (v2.PublicKey, error) {
	impl, err := r.selectImpl()
	if err != nil {
		return v2.PublicKey{}, err
	}

	return impl.SecretToPublicKey(key)
}

func (r randomizedImpl) ThresholdSplit(secret v2.PrivateKey, total uint, threshold uint) (map[int]v2.PrivateKey, error) {
	impl, err := r.selectImpl()
	if err != nil {
		return nil, err
	}

	return impl.ThresholdSplit(secret, total, threshold)
}

func (r randomizedImpl) RecoverSecret(shares map[int]v2.PrivateKey, total uint, threshold uint) (v2.PrivateKey, error) {
	impl, err := r.selectImpl()
	if err != nil {
		return v2.PrivateKey{}, err
	}

	return impl.RecoverSecret(shares, total, threshold)
}

func (r randomizedImpl) ThresholdAggregate(partialSignaturesByIndex map[int]v2.Signature) (v2.Signature, error) {
	impl, err := r.selectImpl()
	if err != nil {
		return v2.Signature{}, err
	}

	return impl.ThresholdAggregate(partialSignaturesByIndex)
}

func (r randomizedImpl) Verify(compressedPublicKey v2.PublicKey, data []byte, signature v2.Signature) error {
	impl, err := r.selectImpl()
	if err != nil {
		return err
	}

	return impl.Verify(compressedPublicKey, data, signature)
}

func (r randomizedImpl) Sign(privateKey v2.PrivateKey, data []byte) (v2.Signature, error) {
	impl, err := r.selectImpl()
	if err != nil {
		return v2.Signature{}, err
	}

	return impl.Sign(privateKey, data)
}

func FuzzRandomImplementations(f *testing.F) {
	f.Fuzz(func(t *testing.T, _ byte) {
		TestRandomized(t)
	})
}
