package tbls

import (
	"fmt"
	"github.com/herumi/bls-eth-go-binary/bls"
	"strconv"
	"sync"
)

var herumiInit = sync.Once{}

// PSA: as much as init() is (almost) an antipattern in Go, Herumi BLS implementation needs an initialization routine
// before it can be used.
// Hence, we embed it in an init() method along with a sync.Once, so that this effect is only run once.
func init() {
	herumiInit.Do(func() {
		if err := bls.Init(bls.BLS12_381); err != nil {
			panic(fmt.Errorf("cannot initialize Herumi BLS, %w", err))
		}

		if err := bls.SetETHmode(bls.EthModeLatest); err != nil {
			panic(fmt.Errorf("cannot initialize Herumi BLS, %w", err))
		}
	})
}

type HerumiPublicKey struct {
	bls.PublicKey
}

func (h HerumiPublicKey) MarshalText() ([]byte, error) {
	return []byte(h.SerializeToHexStr()), nil
}

type HerumiPrivateKey struct {
	bls.SecretKey
}

func (h *HerumiPrivateKey) MarshalText() ([]byte, error) {
	return []byte(h.SerializeToHexStr()), nil
}

func (h *HerumiPrivateKey) UnmarshalText(text []byte) error {
	return h.SetHexString(string(text))
}

func (h *HerumiPrivateKey) PublicKey() PublicKey {
	p, err := h.GetSafePublicKey()
	if err != nil {
		panic(fmt.Errorf("cannot retrieve public key from private key, %w", err))
	}

	return HerumiPublicKey{
		PublicKey: *p,
	}
}

func (h *HerumiPrivateKey) Sign(data []byte) (Signature, error) {
	return HerumiSignature{
		Sign: *h.SignByte(data),
	}, nil
}

type HerumiPartialPublicKey struct {
	HerumiPublicKey
	id uint
}

func (h HerumiPartialPublicKey) ID() uint {
	return h.id
}

type HerumiPartialPrivateKey struct {
	HerumiPrivateKey
	id uint
}

func (h HerumiPartialPrivateKey) ID() uint {
	return h.id
}

type HerumiSignature struct {
	bls.Sign
}

func (h HerumiSignature) Verify(pk PublicKey, message []byte) error {
	// assert pk to its raw type
	hpubk, ok := pk.(HerumiPublicKey)
	if !ok {
		return fmt.Errorf("public key is not in Herumi format")
	}

	if !h.VerifyByte(&hpubk.PublicKey, message) {
		return fmt.Errorf("signature not verified")
	}

	return nil
}

type HerumiPartialSignature struct {
	HerumiSignature
}

func (h HerumiPartialSignature) Verify(pk PartialPublicKey, message []byte) error {
	// assert pk to its raw type
	hpubk, ok := pk.(HerumiPartialPublicKey)
	if !ok {
		return fmt.Errorf("public key is not in Herumi format")
	}

	if !h.VerifyByte(&hpubk.PublicKey, message) {
		return fmt.Errorf("signature not verified")
	}

	return nil
}

type HerumiThresholdGenerator struct{}

func (h HerumiThresholdGenerator) Split(original PrivateKey, total, threshold uint) ([]PartialPrivateKey, error) {
	// cast original to its herumi representation
	horiginal, ok := original.(*HerumiPrivateKey)
	if !ok {
		return nil, fmt.Errorf("original is not in Herumi format")
	}

	// master key Polynomial
	poly := make([]bls.SecretKey, threshold)

	poly[0] = horiginal.SecretKey

	// initialize threshold amount of points
	for i := 1; i < int(threshold); i++ {
		sk := bls.SecretKey{}
		sk.SetByCSPRNG()
		poly[i] = sk
	}

	ret := make([]PartialPrivateKey, total)
	for i := 1; i <= int(total); i++ {
		blsID := bls.ID{}

		err := blsID.SetDecString(fmt.Sprintf("%d", i))
		if err != nil {
			return nil, fmt.Errorf("cannot set ID %d for key number %d, %w", i, i, err)
		}

		sk := bls.SecretKey{}

		err = sk.Set(poly, &blsID)
		if err != nil {
			return nil, err
		}

		ret[i] = &HerumiPartialPrivateKey{
			HerumiPrivateKey: HerumiPrivateKey{
				SecretKey: sk,
			},
			id: uint(i),
		}
	}

	return ret, nil
}

func (h HerumiThresholdGenerator) RecoverPrivateKey(keys []PartialPrivateKey) (PrivateKey, error) {
	pk := bls.SecretKey{}

	rawKeys := []bls.SecretKey{}
	rawIDs := []bls.ID{}

	for idx, key := range keys {
		// assert key to herumi type
		kpk, ok := key.(*HerumiPartialPrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key %d is not in Herumi format", idx)
		}

		rawKeys = append(rawKeys, kpk.SecretKey)

		id := bls.ID{}
		if err := id.SetDecString(strconv.Itoa(int(kpk.id))); err != nil {
			return nil, fmt.Errorf("private key %d id isn't a number", kpk.id)
		}

		rawIDs = append(rawIDs, id)
	}

	if err := pk.Recover(rawKeys, rawIDs); err != nil {
		return nil, fmt.Errorf("cannot recover full private key from partial keys, %w", err)
	}

	return &HerumiPrivateKey{
		SecretKey: pk,
	}, nil
}

func (h HerumiThresholdGenerator) CombineSignatures(psigns []PartialSignature, pkeys []PartialPublicKey) (Signature, error) {
	var rawSigns []bls.Sign
	var rawIDs []bls.ID

	for idx, sign := range psigns {
		hsign, ok := sign.(HerumiPartialSignature)
		if !ok {
			return nil, fmt.Errorf("partial signature %d is not in Herumi format", idx)
		}

		rawSigns = append(rawSigns, hsign.Sign)
	}

	for idx, pk := range pkeys {
		id := bls.ID{}

		if err := id.SetDecString(strconv.Itoa(int(pk.ID()))); err != nil {
			return nil, fmt.Errorf("cannot set partial public key %d's id, %w", idx, err)
		}

		rawIDs = append(rawIDs, id)
	}

	complete := bls.Sign{}

	if err := complete.Recover(rawSigns, rawIDs); err != nil {
		return nil, fmt.Errorf("cannot combine signatures, %w", err)
	}

	return HerumiSignature{
		Sign: complete,
	}, nil
}

func (h HerumiThresholdGenerator) Generate() (PrivateKey, error) {
	p := bls.SecretKey{}
	p.SetByCSPRNG()

	return &HerumiPrivateKey{
		SecretKey: p,
	}, nil
}
