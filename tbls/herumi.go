// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package tbls

import (
	"io"
	"strconv"
	"sync"
	"testing"

	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

var initOnce = sync.Once{}

// PSA: as much as init() is (almost) an antipattern in Go, Herumi BLS implementation needs an initialization routine
// before it can be used.
// Hence, we embed it in an init() method along with a sync.Once, so that this effect is only run once.
//
//nolint:gochecknoinits
func init() {
	initOnce.Do(func() {
		//nolint:nosnakecase
		if err := bls.Init(bls.BLS12_381); err != nil {
			panic(errors.Wrap(err, "cannot initialize Herumi BLS"))
		}

		if err := bls.SetETHmode(bls.EthModeLatest); err != nil {
			panic(errors.Wrap(err, "cannot initialize Herumi BLS"))
		}
	})
}

// Herumi is an Implementation with Herumi-specific inner logic.
type Herumi struct{}

// GenerateInsecureKey generates a key that is not cryptographically secure using the
// provided random number generator. This is useful for testing.
func (Herumi) GenerateInsecureKey(t *testing.T, random io.Reader) (PrivateKey, error) {
	t.Helper()

	secret, err := generateInsecureSecret(t, random)
	if err != nil {
		return PrivateKey{}, err
	}

	return *(*PrivateKey)(secret.Serialize()), nil
}

func (Herumi) GenerateSecretKey() (PrivateKey, error) {
	var p bls.SecretKey
	p.SetByCSPRNG()

	// Commenting here once, this syntax will appear often:
	// here I'm converting the output of p.Serialize() to a pointer to instance of v2.PrivateKey, which is
	// an array with constant size.
	// I'm dereferencing it to return a copy as well.
	// Ref: https://go.dev/ref/spec#Conversions_from_slice_to_array_pointer
	return *(*PrivateKey)(p.Serialize()), nil
}

func (Herumi) SecretToPublicKey(secret PrivateKey) (PublicKey, error) {
	var p bls.SecretKey

	if err := p.Deserialize(secret[:]); err != nil {
		return PublicKey{}, errors.Wrap(err, "cannot unmarshal secret into Herumi secret key")
	}

	pubk, err := p.GetSafePublicKey()
	if err != nil {
		return PublicKey{}, errors.Wrap(err, "cannot obtain public key from secret")
	}

	return *(*PublicKey)(pubk.Serialize()), nil
}

// ThresholdSplitInsecure splits a secret into a number of shares, using a random number generator that is not
// cryptographically secure. This is useful for testing.
func (Herumi) ThresholdSplitInsecure(t *testing.T, secret PrivateKey, total uint, threshold uint, random io.Reader) (map[int]PrivateKey, error) {
	t.Helper()
	var p bls.SecretKey
	
	if (threshold <= 1) {
		return nil, errors.New("threshold has to be greater than 1")
	}

	if err := p.Deserialize(secret[:]); err != nil {
		return nil, errors.Wrap(err, "cannot unmarshal bytes into Herumi secret key")
	}

	// master key Polynomial
	poly := make([]bls.SecretKey, threshold)

	poly[0] = p

	// initialize threshold amount of points
	for i := 1; i < int(threshold); i++ {
		secret, err := generateInsecureSecret(t, random)
		if err != nil {
			return nil, err
		}

		poly[i] = secret
	}

	ret := make(map[int]PrivateKey)
	for i := 1; i <= int(total); i++ {
		var blsID bls.ID

		err := blsID.SetDecString(strconv.Itoa(i))
		if err != nil {
			return nil, errors.Wrap(
				err,
				"cannot set ID",
				z.Int("id_number", i),
				z.Int("key_number", i),
			)
		}

		var sk bls.SecretKey

		err = sk.Set(poly, &blsID)
		if err != nil {
			return nil, errors.Wrap(err, "cannot set ID on polynomial", z.Int("id_number", i))
		}

		ret[i] = *(*PrivateKey)(sk.Serialize())
	}

	return ret, nil
}

func (Herumi) ThresholdSplit(secret PrivateKey, total uint, threshold uint) (map[int]PrivateKey, error) {
	var p bls.SecretKey

	if (threshold <= 1) {
		return nil, errors.New("threshold has to be greater than 1")
	}

	if err := p.Deserialize(secret[:]); err != nil {
		return nil, errors.Wrap(err, "cannot unmarshal bytes into Herumi secret key")
	}

	// master key Polynomial
	poly := make([]bls.SecretKey, threshold)

	poly[0] = p

	// initialize threshold amount of points
	for i := 1; i < int(threshold); i++ {
		var sk bls.SecretKey
		sk.SetByCSPRNG()
		poly[i] = sk
	}

	ret := make(map[int]PrivateKey)
	for i := 1; i <= int(total); i++ {
		var blsID bls.ID

		err := blsID.SetDecString(strconv.Itoa(i))
		if err != nil {
			return nil, errors.Wrap(
				err,
				"cannot set ID",
				z.Int("id_number", i),
				z.Int("key_number", i),
			)
		}

		var sk bls.SecretKey

		err = sk.Set(poly, &blsID)
		if err != nil {
			return nil, errors.Wrap(err, "cannot set ID on polynomial", z.Int("id_number", i))
		}

		ret[i] = *(*PrivateKey)(sk.Serialize())
	}

	return ret, nil
}

func (Herumi) RecoverSecret(shares map[int]PrivateKey, _, _ uint) (PrivateKey, error) {
	var (
		pk      bls.SecretKey
		rawKeys []bls.SecretKey
		rawIDs  []bls.ID
	)

	for idx, key := range shares {
		var kpk bls.SecretKey
		if err := kpk.Deserialize(key[:]); err != nil {
			return PrivateKey{}, errors.Wrap(
				err,
				"cannot unmarshal key with into Herumi secret key",
				z.Int("key_number", idx),
			)
		}

		rawKeys = append(rawKeys, kpk)

		var id bls.ID
		if err := id.SetDecString(strconv.Itoa(idx)); err != nil {
			return PrivateKey{}, errors.Wrap(
				err,
				"private key isn't a number",
				z.Int("key_number", idx),
			)
		}

		rawIDs = append(rawIDs, id)
	}

	if err := pk.Recover(rawKeys, rawIDs); err != nil {
		return PrivateKey{}, errors.Wrap(err, "cannot recover full private key from partial keys")
	}

	return *(*PrivateKey)(pk.Serialize()), nil
}

func (Herumi) Aggregate(signs []Signature) (Signature, error) {
	var (
		sig      bls.Sign
		rawSigns []bls.Sign
	)

	for idx, rawSignature := range signs {
		var signature bls.Sign
		if err := signature.Deserialize(rawSignature[:]); err != nil {
			return Signature{}, errors.Wrap(
				err,
				"cannot unmarshal signature into Herumi signature",
				z.Int("signature_number", idx),
			)
		}

		rawSigns = append(rawSigns, signature)
	}

	sig.Aggregate(rawSigns)

	return *(*Signature)(sig.Serialize()), nil
}

func (Herumi) ThresholdAggregate(partialSignaturesByIndex map[int]Signature) (Signature, error) {
	var (
		rawSigns []bls.Sign
		rawIDs   []bls.ID
	)

	for idx, rawSignature := range partialSignaturesByIndex {
		var signature bls.Sign
		if err := signature.Deserialize(rawSignature[:]); err != nil {
			return Signature{}, errors.Wrap(
				err,
				"cannot unmarshal signature into Herumi signature",
				z.Int("signature_number", idx),
			)
		}

		rawSigns = append(rawSigns, signature)

		var id bls.ID
		if err := id.SetDecString(strconv.Itoa(idx)); err != nil {
			return Signature{}, errors.Wrap(
				err,
				"signature id isn't a number",
				z.Int("signature_number", idx),
			)
		}

		rawIDs = append(rawIDs, id)
	}

	var complete bls.Sign

	if err := complete.Recover(rawSigns, rawIDs); err != nil {
		return Signature{}, errors.Wrap(err, "cannot combine signatures")
	}

	return *(*Signature)(complete.Serialize()), nil
}

func (Herumi) Verify(compressedPublicKey PublicKey, data []byte, rawSignature Signature) error {
	var pubKey bls.PublicKey
	if err := pubKey.Deserialize(compressedPublicKey[:]); err != nil {
		return errors.Wrap(err, "cannot set compressed public key in Herumi format")
	}

	var signature bls.Sign
	if err := signature.Deserialize(rawSignature[:]); err != nil {
		return errors.Wrap(err, "cannot unmarshal signature into Herumi signature")
	}

	if !signature.VerifyByte(&pubKey, data) {
		return errors.New("signature not verified")
	}

	return nil
}

func (Herumi) Sign(privateKey PrivateKey, data []byte) (Signature, error) {
	var p bls.SecretKey

	if err := p.Deserialize(privateKey[:]); err != nil {
		return Signature{}, errors.Wrap(err, "cannot unmarshal secret into Herumi secret key")
	}

	sigBytes := p.SignByte(data).Serialize()

	return *(*Signature)(sigBytes), nil
}

func (Herumi) VerifyAggregate(publicShares []PublicKey, signature Signature, data []byte) error {
	var (
		rawShares []bls.PublicKey
		sig       bls.Sign
	)

	if err := sig.Deserialize(signature[:]); err != nil {
		return errors.Wrap(err, "cannot unmarshal signature into Herumi signature")
	}

	for _, share := range publicShares {
		var pubKey bls.PublicKey
		if err := pubKey.Deserialize(share[:]); err != nil {
			return errors.Wrap(err, "cannot set compressed public key in Herumi format")
		}

		rawShares = append(rawShares, pubKey)
	}

	if !sig.FastAggregateVerify(rawShares, data) {
		return errors.New("signature verification failed")
	}

	return nil
}

// generateInsecureSecret generates a secret that is not cryptographically secure using the
// provided random number generator. This is useful for testing.
func generateInsecureSecret(t *testing.T, random io.Reader) (bls.SecretKey, error) {
	t.Helper()
	for range 100 {
		b := make([]byte, 32)
		_, err := random.Read(b)
		require.NoError(t, err)

		var p bls.SecretKey
		err = p.Deserialize(b)
		if err != nil {
			continue // Try again
		}

		return p, nil
	}

	return bls.SecretKey{}, errors.New("cannot generate insecure key")
}
