package herumi

import (
	"fmt"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/tbls/v2"
	"strconv"
	"sync"
)

var initializationOnce = sync.Once{}

// PSA: as much as init() is (almost) an antipattern in Go, Herumi BLS implementation needs an initialization routine
// before it can be used.
// Hence, we embed it in an init() method along with a sync.Once, so that this effect is only run once.
func init() {
	initializationOnce.Do(func() {
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

func (h Herumi) GenerateSecretKey() (v2.PrivateKey, error) {
	var p bls.SecretKey
	p.SetByCSPRNG()

	// Commenting here once, this syntax will appear often:
	// here I'm converting ret to a pointer to instance of v2.PrivateKey, which is
	// an array with constant size.
	// I'm dereferencing it to return a copy as well.
	// Ref: https://go.dev/ref/spec#Conversions_from_slice_to_array_pointer
	return *(*v2.PrivateKey)(p.Serialize()), nil
}

func (h Herumi) SecretToPublicKey(secret v2.PrivateKey) (v2.PublicKey, error) {
	var p bls.SecretKey

	if err := p.Deserialize(secret[:]); err != nil {
		return v2.PublicKey{}, errors.Wrap(err, "cannot unmarshal secret into Herumi secret key")
	}

	pubk, err := p.GetSafePublicKey()
	if err != nil {
		return v2.PublicKey{}, errors.Wrap(err, "cannot obtain public key from secret secret")
	}

	return *(*v2.PublicKey)(pubk.Serialize()), nil
}

func (h Herumi) ThresholdSplit(secret v2.PrivateKey, total uint, threshold uint) (map[int]v2.PrivateKey, error) {
	var p bls.SecretKey

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

	ret := make(map[int]v2.PrivateKey)
	for i := 1; i <= int(total); i++ {
		var blsID bls.ID

		err := blsID.SetDecString(fmt.Sprintf("%d", i))
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

		ret[i] = *(*v2.PrivateKey)(sk.Serialize())
	}

	return ret, nil
}

func (h Herumi) RecoverSecret(shares map[int]v2.PrivateKey, _, _ uint) (v2.PrivateKey, error) {
	var pk bls.SecretKey

	var rawKeys []bls.SecretKey
	var rawIDs []bls.ID

	for idx, key := range shares {
		// do a local copy, we're dealing with references here
		key := key
		var kpk bls.SecretKey
		if err := kpk.Deserialize(key[:]); err != nil {
			return v2.PrivateKey{}, errors.Wrap(
				err,
				"cannot unmarshal key with into Herumi secret key",
				z.Int("key_number", idx),
			)
		}

		rawKeys = append(rawKeys, kpk)

		var id bls.ID
		if err := id.SetDecString(strconv.Itoa(idx)); err != nil {
			return v2.PrivateKey{}, errors.Wrap(
				err,
				"private key isn't a number",
				z.Int("key_number", idx),
			)
		}

		rawIDs = append(rawIDs, id)
	}

	if err := pk.Recover(rawKeys, rawIDs); err != nil {
		return v2.PrivateKey{}, errors.Wrap(err, "cannot recover full private key from partial keys")
	}

	return *(*v2.PrivateKey)(pk.Serialize()), nil
}

func (h Herumi) ThresholdAggregate(partialSignaturesByIndex map[int]v2.Signature) (v2.Signature, error) {
	var rawSigns []bls.Sign
	var rawIDs []bls.ID

	for idx, rawSignature := range partialSignaturesByIndex {
		// do a local copy, we're dealing with references here
		rawSignature := rawSignature
		var signature bls.Sign
		if err := signature.Deserialize(rawSignature[:]); err != nil {
			return v2.Signature{}, errors.Wrap(
				err,
				"cannot unmarshal signature into Herumi signature",
				z.Int("signature_number", idx),
			)
		}

		rawSigns = append(rawSigns, signature)

		var id bls.ID
		if err := id.SetDecString(strconv.Itoa(idx)); err != nil {
			return v2.Signature{}, errors.Wrap(
				err,
				"signature id isn't a number",
				z.Int("signature_number", idx),
			)
		}

		rawIDs = append(rawIDs, id)
	}

	var complete bls.Sign

	if err := complete.Recover(rawSigns, rawIDs); err != nil {
		return v2.Signature{}, errors.Wrap(err, "cannot combine signatures")
	}

	return *(*v2.Signature)(complete.Serialize()), nil
}

func (h Herumi) Verify(compressedPublicKey v2.PublicKey, data []byte, rawSignature v2.Signature) error {
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

func (h Herumi) Sign(privateKey v2.PrivateKey, data []byte) (v2.Signature, error) {
	var p bls.SecretKey

	if err := p.Deserialize(privateKey[:]); err != nil {
		return v2.Signature{}, errors.Wrap(err, "cannot unmarshal secret into Herumi secret key")
	}

	sigBytes := p.SignByte(data).Serialize()
	return *(*v2.Signature)(sigBytes), nil
}
