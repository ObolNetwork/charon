// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package tbls_test

import (
	"crypto/rand"
	"io"
	"math/big"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/obolnetwork/charon/tbls"
)

type TestSuite struct {
	suite.Suite

	impl tbls.Implementation
}

func NewTestSuite(implementations tbls.Implementation) TestSuite {
	return TestSuite{
		impl: implementations,
	}
}

func (ts *TestSuite) SetupTest() {
	tbls.SetImplementation(ts.impl)
}

func (ts *TestSuite) Test_GenerateSecretKey() {
	secret, err := tbls.GenerateSecretKey()
	ts.Require().NoError(err)
	ts.Require().NotEmpty(secret)
}

func (ts *TestSuite) Test_SecretToPublicKey() {
	secret, err := tbls.GenerateSecretKey()
	ts.Require().NoError(err)
	ts.Require().NotEmpty(secret)

	pubk, err := tbls.SecretToPublicKey(secret)
	ts.Require().NoError(err)
	ts.Require().NotEmpty(pubk)
}

func (ts *TestSuite) Test_ThresholdSplit() {
	secret, err := tbls.GenerateSecretKey()
	ts.Require().NoError(err)
	ts.Require().NotEmpty(secret)

	shares, err := tbls.ThresholdSplit(secret, 5, 3)
	ts.Require().NoError(err)
	ts.Require().NotEmpty(shares)
}

func (ts *TestSuite) Test_RecoverSecret() {
	secret, err := tbls.GenerateSecretKey()
	ts.Require().NoError(err)
	ts.Require().NotEmpty(secret)

	shares, err := tbls.ThresholdSplit(secret, 5, 3)
	ts.Require().NoError(err)

	recovered, err := tbls.RecoverSecret(shares, 5, 3)
	ts.Require().NoError(err)

	ts.Require().ElementsMatch(secret, recovered)
}

func (ts *TestSuite) Test_ThresholdAggregate() {
	data := []byte("hello obol!")

	secret, err := tbls.GenerateSecretKey()
	ts.Require().NoError(err)
	ts.Require().NotEmpty(secret)

	totalOGSig, err := tbls.Sign(secret, data)
	ts.Require().NoError(err)

	shares, err := tbls.ThresholdSplit(secret, 5, 3)
	ts.Require().NoError(err)

	signatures := map[int]tbls.Signature{}

	for idx, key := range shares {
		signature, err := tbls.Sign(key, data)
		ts.Require().NoError(err)

		signatures[idx] = signature
	}

	totalSig, err := tbls.ThresholdAggregate(signatures)
	ts.Require().NoError(err)

	ts.Require().Equal(totalOGSig, totalSig)
}

func (ts *TestSuite) Test_Verify() {
	data := []byte("hello obol!")

	secret, err := tbls.GenerateSecretKey()
	ts.Require().NoError(err)
	ts.Require().NotEmpty(secret)

	signature, err := tbls.Sign(secret, data)
	ts.Require().NoError(err)
	ts.Require().NotEmpty(signature)

	pubkey, err := tbls.SecretToPublicKey(secret)
	ts.Require().NoError(err)
	ts.Require().NotEmpty(pubkey)

	ts.Require().NoError(tbls.Verify(pubkey, data, signature))
}

func (ts *TestSuite) Test_Sign() {
	data := []byte("hello obol!")

	secret, err := tbls.GenerateSecretKey()
	ts.Require().NoError(err)
	ts.Require().NotEmpty(secret)

	signature, err := tbls.Sign(secret, data)
	ts.Require().NoError(err)
	ts.Require().NotEmpty(signature)
}

func (ts *TestSuite) Test_VerifyAggregate() {
	data := []byte("hello obol!")

	type key struct {
		pub  tbls.PublicKey
		priv tbls.PrivateKey
	}

	var keys []key

	for range 10 {
		secret, err := tbls.GenerateSecretKey()
		ts.Require().NoError(err)
		ts.Require().NotEmpty(secret)

		pubkey, err := tbls.SecretToPublicKey(secret)
		ts.Require().NoError(err)

		keys = append(keys, key{
			pub:  pubkey,
			priv: secret,
		})
	}

	var (
		signs   []tbls.Signature
		pshares []tbls.PublicKey
	)

	for _, key := range keys {
		s, err := tbls.Sign(key.priv, data)
		ts.Require().NoError(err)

		signs = append(signs, s)
		pshares = append(pshares, key.pub)
	}

	sig, err := tbls.Aggregate(signs)
	ts.Require().NoError(err)

	ts.Require().NoError(tbls.VerifyAggregate(pshares, sig, data))
}

func runSuite(t *testing.T, i tbls.Implementation) {
	t.Helper()

	ts := NewTestSuite(i)

	suite.Run(t, &ts)
}

func TestHerumiImplementation(t *testing.T) {
	runSuite(t, tbls.Herumi{})
}

func runBenchmark(b *testing.B, impl tbls.Implementation) {
	b.Helper()

	s := NewTestSuite(impl)
	t := &testing.T{}
	s.SetT(t)
	s.SetupTest()

	b.ResetTimer()

	for range b.N {
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
		s.Test_VerifyAggregate()
	}
}

func BenchmarkHerumiImplementation(b *testing.B) {
	runBenchmark(b, tbls.Herumi{})
}

func TestRandomized(t *testing.T) {
	runSuite(t, randomizedImpl{
		implementations: []tbls.Implementation{
			tbls.Herumi{},
		},
	})
}

// randomizedImpl randomizes execution of each call by choosing a random element from
// the implementations slice.
// Useful to test whether two implementations are compatible.
type randomizedImpl struct {
	implementations []tbls.Implementation
}

func (r randomizedImpl) selectImpl() (tbls.Implementation, error) {
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

func (r randomizedImpl) GenerateSecretKey() (tbls.PrivateKey, error) {
	impl, err := r.selectImpl()
	if err != nil {
		return tbls.PrivateKey{}, err
	}

	return impl.GenerateSecretKey()
}

func (r randomizedImpl) GenerateInsecureKey(t *testing.T, random io.Reader) (tbls.PrivateKey, error) {
	t.Helper()

	impl, err := r.selectImpl()
	if err != nil {
		return tbls.PrivateKey{}, err
	}

	return impl.GenerateInsecureKey(t, random)
}

func (r randomizedImpl) SecretToPublicKey(key tbls.PrivateKey) (tbls.PublicKey, error) {
	impl, err := r.selectImpl()
	if err != nil {
		return tbls.PublicKey{}, err
	}

	return impl.SecretToPublicKey(key)
}

func (r randomizedImpl) ThresholdSplit(secret tbls.PrivateKey, total uint, threshold uint) (map[int]tbls.PrivateKey, error) {
	impl, err := r.selectImpl()
	if err != nil {
		return nil, err
	}

	return impl.ThresholdSplit(secret, total, threshold)
}

func (r randomizedImpl) ThresholdSplitInsecure(t *testing.T, secret tbls.PrivateKey, total uint, threshold uint, random io.Reader) (map[int]tbls.PrivateKey, error) {
	t.Helper()

	impl, err := r.selectImpl()
	if err != nil {
		return nil, err
	}

	return impl.ThresholdSplitInsecure(t, secret, total, threshold, random)
}

func (r randomizedImpl) RecoverSecret(shares map[int]tbls.PrivateKey, total uint, threshold uint) (tbls.PrivateKey, error) {
	impl, err := r.selectImpl()
	if err != nil {
		return tbls.PrivateKey{}, err
	}

	return impl.RecoverSecret(shares, total, threshold)
}

func (r randomizedImpl) ThresholdAggregate(partialSignaturesByIndex map[int]tbls.Signature) (tbls.Signature, error) {
	impl, err := r.selectImpl()
	if err != nil {
		return tbls.Signature{}, err
	}

	return impl.ThresholdAggregate(partialSignaturesByIndex)
}

func (r randomizedImpl) Verify(compressedPublicKey tbls.PublicKey, data []byte, signature tbls.Signature) error {
	impl, err := r.selectImpl()
	if err != nil {
		return err
	}

	return impl.Verify(compressedPublicKey, data, signature)
}

func (r randomizedImpl) Sign(privateKey tbls.PrivateKey, data []byte) (tbls.Signature, error) {
	impl, err := r.selectImpl()
	if err != nil {
		return tbls.Signature{}, err
	}

	return impl.Sign(privateKey, data)
}

func (r randomizedImpl) VerifyAggregate(shares []tbls.PublicKey, signature tbls.Signature, data []byte) error {
	impl, err := r.selectImpl()
	if err != nil {
		return err
	}

	return impl.VerifyAggregate(shares, signature, data)
}

func (r randomizedImpl) Aggregate(signs []tbls.Signature) (tbls.Signature, error) {
	impl, err := r.selectImpl()
	if err != nil {
		return tbls.Signature{}, err
	}

	return impl.Aggregate(signs)
}

func FuzzRandomImplementations(f *testing.F) {
	f.Fuzz(func(t *testing.T, _ byte) {
		TestRandomized(t)
	})
}
