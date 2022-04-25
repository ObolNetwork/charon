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
	"time"

	share "github.com/coinbase/kryptology/pkg/sharing"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

const protocol = "/charon/keycast/1.0.0"

// output is the output of key cast for each participant (including the leader).
type output struct {
	PubKey   *bls_sig.PublicKey
	Verifier *share.FeldmanVerifier
	Share    *bls_sig.SecretKey
}

// msg is the key cast wire json format.
type msg struct {
	PubKey    []byte
	Verifiers [][]byte
	Share     []byte
}

// leadKeyCast generates a new key pair, splits it into shares, and broadcasts one to each participant.
// It returns the leaders output.
//nolint:deadcode // Will be tested and wired in subsequent PRs.
func leadKeyCast(ctx context.Context, tcpNode host.Host, peers []p2p.Peer, t int, r io.Reader) (output, error) {
	pubkey, secret, err := tbls.Keygen()
	if err != nil {
		return output{}, err
	}

	shares, verifier, err := tbls.SplitSecret(secret, t, len(peers), r)
	if err != nil {
		return output{}, err
	}

	eg, ctx := errgroup.WithContext(ctx)

	var leadShare *bls_sig.SecretKey
	for i, p := range peers {
		if p.ID == tcpNode.ID() {
			leadShare, err = tblsconv.ShareToSecret(shares[i])
			if err != nil {
				return output{}, err
			}

			continue // Do not send to self
		}

		msgBytes, err := marshalMsg(pubkey, verifier, shares[i])
		if err != nil {
			return output{}, err
		}

		pID := p.ID // Copy loop variable

		eg.Go(func() error {
			for ctx.Err() == nil {
				err := attemptCast(ctx, tcpNode, pID, msgBytes)
				if err != nil {
					log.Warn(ctx, "Failed broadcast to peer (will retry in 5s)",
						z.Str("peer", p2p.ShortID(pID)), z.Err(err))
					select {
					case <-ctx.Done():
						return ctx.Err() // Timeout
					case <-time.After(time.Second * 5):
						continue
					}
				}

				log.Info(ctx, "Broadcast peer success", z.Str("peer", p2p.ShortID(pID)))

				return nil
			}

			return ctx.Err()
		})
	}

	if err = eg.Wait(); err != nil {
		return output{}, errors.Wrap(err, "broadcast timeout")
	}

	return output{
		PubKey:   pubkey,
		Verifier: verifier,
		Share:    leadShare,
	}, nil
}

// attemptCast attempts to send the message to the peer over libp2p.
func attemptCast(ctx context.Context, tcpNode host.Host, pID peer.ID, msg []byte) error {
	s, err := tcpNode.NewStream(ctx, pID, protocol)
	if err != nil {
		return errors.Wrap(err, "new stream")
	}
	defer s.Close()

	_, err = s.Write(msg)
	if err != nil {
		return errors.Wrap(err, "write message")
	}

	return nil
}

// marshalMsg returns message bytes to send over the wire.
func marshalMsg(pubKey *bls_sig.PublicKey, verifier *share.FeldmanVerifier, share *bls_sig.SecretKeyShare) ([]byte, error) {
	pk, err := pubKey.MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "marshal pubkey")
	}

	var verifiers [][]byte
	for _, commitment := range verifier.Commitments {
		verifiers = append(verifiers, commitment.ToAffineCompressed())
	}

	s, err := share.MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "marshal share")
	}

	resp, err := json.Marshal(msg{
		PubKey:    pk,
		Verifiers: verifiers,
		Share:     s,
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal msg")
	}

	return resp, nil
}
