// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package pedersen

import (
	"github.com/drand/kyber"
	"github.com/drand/kyber/share"
	kdkg "github.com/drand/kyber/share/dkg"
	"github.com/drand/kyber/util/random"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

func randomKeyPair(suite kdkg.Suite) (kyber.Scalar, kyber.Point) {
	private := suite.Scalar().Pick(random.New())
	public := suite.Point().Mul(private, nil)

	return private, public
}

func unmarshalPoint(suite kdkg.Suite, b []byte) (kyber.Point, error) {
	point := suite.Point()
	if err := point.UnmarshalBinary(b); err != nil {
		return nil, errors.Wrap(err, "unmarshal point")
	}

	return point, nil
}

func keyShareToBLS(result *kdkg.DistKeyShare) (tbls.PrivateKey, tbls.PublicKey, error) {
	privShare := result.PriShare()

	bytsSk, err := privShare.V.MarshalBinary()
	if err != nil {
		return tbls.PrivateKey{}, tbls.PublicKey{}, err
	}

	privKey, err := tblsconv.PrivkeyFromBytes(bytsSk)
	if err != nil {
		return tbls.PrivateKey{}, tbls.PublicKey{}, errors.Wrap(err, "convert privkey from bytes")
	}

	pubKey, err := tbls.SecretToPublicKey(privKey)
	if err != nil {
		return tbls.PrivateKey{}, tbls.PublicKey{}, errors.Wrap(err, "derive pubkey from privkey")
	}

	return privKey, pubKey, nil
}

func distKeyShareToValidatorPubKey(result *kdkg.DistKeyShare, suite kdkg.Suite) (tbls.PublicKey, error) {
	exp := share.NewPubPoly(suite, suite.Point().Base(), result.Commitments())

	bytsPK, err := exp.Commit().MarshalBinary()
	if err != nil {
		return tbls.PublicKey{}, errors.Wrap(err, "marshal validator pubkey")
	}

	return tblsconv.PubkeyFromBytes(bytsPK)
}
