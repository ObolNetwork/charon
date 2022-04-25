// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

package dkg

import (
	"context"
	"encoding/json"
	"io"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/sharing"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

// joinKeyCast returns the output for a keycast participant identified by the libp2p peer ID.
//nolint:deadcode // Will be tested and wired in subsequent PRs.
func joinKeyCast(ctx context.Context, tcpNode host.Host) (output, error) {
	var (
		outCh = make(chan output, 1)
		errCh = make(chan error, 1)
	)
	tcpNode.SetStreamHandler(protocol, func(s network.Stream) {
		defer s.Close()

		b, err := io.ReadAll(s)
		if err != nil {
			errCh <- err
			return
		}

		out, err := unmarshalOutput(b)
		if err != nil {
			errCh <- err
			return
		}

		outCh <- out
	})

	select {
	case err := <-errCh:
		return output{}, err
	case <-ctx.Done():
		return output{}, errors.Wrap(ctx.Err(), "timeout")
	case out := <-outCh:
		return out, nil
	}
}

// unmarshalOutput returns the output by unmarshalling the wire message bytes.
func unmarshalOutput(b []byte) (output, error) {
	var msg msg
	if err := json.Unmarshal(b, &msg); err != nil {
		return output{}, errors.Wrap(err, "unmarshal message")
	}

	pubKey := new(bls_sig.PublicKey)
	if err := pubKey.UnmarshalBinary(msg.PubKey); err != nil {
		return output{}, errors.Wrap(err, "unmarshal pubkey")
	}

	var commitments []curves.Point
	for _, v := range msg.Verifiers {
		c, err := curves.BLS12381G1().Point.FromAffineCompressed(v)
		if err != nil {
			return output{}, errors.Wrap(err, "verifier hex")
		}

		commitments = append(commitments, c)
	}

	secretShare := new(bls_sig.SecretKeyShare)
	if err := secretShare.UnmarshalBinary(msg.Share); err != nil {
		return output{}, errors.Wrap(err, "unmarshal pubkey")
	}

	secret, err := tblsconv.ShareToSecret(secretShare)
	if err != nil {
		return output{}, err
	}

	return output{
		PubKey:   pubKey,
		Verifier: &sharing.FeldmanVerifier{Commitments: commitments},
		Share:    secret,
	}, nil
}
