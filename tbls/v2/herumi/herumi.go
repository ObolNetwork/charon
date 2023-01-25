package herumi

import (
	"fmt"
	"github.com/herumi/bls-eth-go-binary/bls"
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
			panic(fmt.Errorf("cannot initialize Herumi BLS, %w", err))
		}

		if err := bls.SetETHmode(bls.EthModeLatest); err != nil {
			panic(fmt.Errorf("cannot initialize Herumi BLS, %w", err))
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
		return v2.PublicKey{}, fmt.Errorf("cannot unmarshal secret into Herumi secret key, %w", err)
	}

	pubk, err := p.GetSafePublicKey()
	if err != nil {
		return v2.PublicKey{}, fmt.Errorf("cannot obtain public key from secret secret, %w", err)
	}

	return *(*v2.PublicKey)(pubk.Serialize()), nil
}

func (h Herumi) ThresholdSplit(secret v2.PrivateKey, total uint, threshold uint) (map[int]v2.PrivateKey, error) {
	var p bls.SecretKey

	if err := p.Deserialize(secret[:]); err != nil {
		return nil, fmt.Errorf("cannot unmarshal bytes into Herumi secret key, %w", err)
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
			return nil, fmt.Errorf("cannot set ID %d for key number %d, %w", i, i, err)
		}

		var sk bls.SecretKey

		err = sk.Set(poly, &blsID)
		if err != nil {
			return nil, err
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
			return v2.PrivateKey{}, fmt.Errorf("cannot unmarshal key with index %d into Herumi secret key, %w", idx, err)
		}

		rawKeys = append(rawKeys, kpk)

		var id bls.ID
		if err := id.SetDecString(strconv.Itoa(idx)); err != nil {
			return v2.PrivateKey{}, fmt.Errorf("private key id %d id isn't a number", idx)
		}

		rawIDs = append(rawIDs, id)
	}

	if err := pk.Recover(rawKeys, rawIDs); err != nil {
		return v2.PrivateKey{}, fmt.Errorf("cannot recover full private key from partial keys, %w", err)
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
			return v2.Signature{}, fmt.Errorf("cannot unmarshal signature with index %d into Herumi signature, %w", idx, err)
		}

		rawSigns = append(rawSigns, signature)

		var id bls.ID
		if err := id.SetDecString(strconv.Itoa(idx)); err != nil {
			return v2.Signature{}, fmt.Errorf("signature id %d id isn't a number", idx)
		}

		rawIDs = append(rawIDs, id)
	}

	var complete bls.Sign

	if err := complete.Recover(rawSigns, rawIDs); err != nil {
		return v2.Signature{}, fmt.Errorf("cannot combine signatures, %w", err)
	}

	return *(*v2.Signature)(complete.Serialize()), nil
}

func (h Herumi) Verify(compressedPublicKey v2.PublicKey, data []byte, rawSignature v2.Signature) error {
	var pubKey bls.PublicKey
	if err := pubKey.Deserialize(compressedPublicKey[:]); err != nil {
		return fmt.Errorf("cannot set compressed public key in Herumi format, %w", err)
	}

	var signature bls.Sign
	if err := signature.Deserialize(rawSignature[:]); err != nil {
		return fmt.Errorf("cannot unmarshal signature into Herumi signature, %w", err)
	}

	if !signature.VerifyByte(&pubKey, data) {
		return fmt.Errorf("signature not verified")
	}

	return nil
}

func (h Herumi) Sign(privateKey v2.PrivateKey, data []byte) (v2.Signature, error) {
	var p bls.SecretKey

	if err := p.Deserialize(privateKey[:]); err != nil {
		return v2.Signature{}, fmt.Errorf("cannot unmarshal secret into Herumi secret key, %w", err)
	}

	sigBytes := p.SignByte(data).Serialize()
	return *(*v2.Signature)(sigBytes), nil
}
