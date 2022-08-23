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

package parsigex_test

import (
	"context"
	"sync"
	"testing"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/parsigex"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/signing"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestParSigEx(t *testing.T) {
	const (
		n        = 3
		epoch    = 123
		shareIdx = 0
	)
	duty := core.Duty{
		Slot: 123,
		Type: core.DutyRandao,
	}

	pubkey := testutil.RandomCorePubKey(t)
	data := core.ParSignedDataSet{
		pubkey: core.NewPartialSignedRandao(epoch, testutil.RandomEth2Signature(), shareIdx),
	}

	var (
		parsigexs []*parsigex.ParSigEx
		peers     []peer.ID
		hosts     []host.Host
		hostsInfo []peer.AddrInfo
	)

	// create hosts
	for i := 0; i < n; i++ {
		h := testutil.CreateHost(t, testutil.AvailableAddr(t))
		info := peer.AddrInfo{
			ID:    h.ID(),
			Addrs: h.Addrs(),
		}
		hostsInfo = append(hostsInfo, info)
		peers = append(peers, h.ID())
		hosts = append(hosts, h)
	}

	// connect each host with its peers
	for i := 0; i < n; i++ {
		for k := 0; k < n; k++ {
			if i == k {
				continue
			}
			hosts[i].Peerstore().AddAddrs(hostsInfo[k].ID, hostsInfo[k].Addrs, peerstore.PermanentAddrTTL)
		}
	}

	var wg sync.WaitGroup

	// create ParSigEx components for each host
	for i := 0; i < n; i++ {
		wg.Add(n - 1)
		sigex := parsigex.NewParSigEx(hosts[i], p2p.Send, i, peers, func(context.Context, core.Duty, core.PubKey, core.ParSignedData) error {
			return nil
		})
		sigex.Subscribe(func(_ context.Context, d core.Duty, set core.ParSignedDataSet) error {
			defer wg.Done()

			require.Equal(t, duty, d)
			require.Equal(t, data, set)

			return nil
		})
		parsigexs = append(parsigexs, sigex)
	}

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(node int) {
			defer wg.Done()
			// broadcast partially signed data
			require.NoError(t, parsigexs[node].Broadcast(context.Background(), duty, data))
		}(i)
	}

	wg.Wait()
}

func TestParSigExVerifier(t *testing.T) {
	ctx := context.Background()

	const (
		slot     = 123
		shareIdx = 1
	)

	bmock, err := beaconmock.New()
	require.NoError(t, err)

	slotsPerEpoch, err := bmock.SlotsPerEpoch(ctx)
	require.NoError(t, err)

	epoch := eth2p0.Epoch(uint64(slot) / slotsPerEpoch)

	pk, secret, err := tbls.Keygen()
	require.NoError(t, err)

	sign := func(msg []byte) eth2p0.BLSSignature {
		sig, err := tbls.Sign(secret, msg)
		require.NoError(t, err)

		return tblsconv.SigToETH2(sig)
	}

	pubkey, err := tblsconv.KeyToCore(pk)
	require.NoError(t, err)

	mp := map[core.PubKey]map[int]*bls_sig.PublicKey{
		pubkey: {
			shareIdx: pk,
		},
	}
	verifyFunc, err := parsigex.NewEth2Verifier(bmock, mp)
	require.NoError(t, err)

	t.Run("Verify attestation", func(t *testing.T) {
		att := testutil.RandomAttestation()
		sigRoot, err := att.Data.HashTreeRoot()
		require.NoError(t, err)
		sigData, err := signing.GetDataRoot(ctx, bmock, signing.DomainBeaconAttester, att.Data.Target.Epoch, sigRoot)
		require.NoError(t, err)
		att.Signature = sign(sigData[:])
		data := core.NewPartialAttestation(att, shareIdx)

		require.NoError(t, verifyFunc(ctx, core.NewAttesterDuty(slot), pubkey, data))
	})

	t.Run("Verify block", func(t *testing.T) {
		block := testutil.RandomVersionSignedBeaconBlock(t)
		block.Bellatrix.Message.Slot = slot
		sigRoot, err := block.Root()
		require.NoError(t, err)
		sigData, err := signing.GetDataRoot(ctx, bmock, signing.DomainBeaconProposer, epoch, sigRoot)
		require.NoError(t, err)
		block.Bellatrix.Signature = sign(sigData[:])
		data, err := core.NewPartialVersionedSignedBeaconBlock(block, shareIdx)
		require.NoError(t, err)

		require.NoError(t, verifyFunc(ctx, core.NewProposerDuty(slot), pubkey, data))
	})

	t.Run("Verify blinded block", func(t *testing.T) {
		blindedBlock := testutil.RandomVersionSignedBlindedBeaconBlock(t)
		blindedBlock.Bellatrix.Message.Slot = slot
		sigRoot, err := blindedBlock.Root()
		require.NoError(t, err)
		sigData, err := signing.GetDataRoot(ctx, bmock, signing.DomainBeaconProposer, epoch, sigRoot)
		require.NoError(t, err)
		blindedBlock.Bellatrix.Signature = sign(sigData[:])
		data, err := core.NewPartialVersionedSignedBlindedBeaconBlock(blindedBlock, shareIdx)
		require.NoError(t, err)

		require.NoError(t, verifyFunc(ctx, core.NewBuilderProposerDuty(slot), pubkey, data))
	})

	t.Run("Verify Randao", func(t *testing.T) {
		sigRoot, err := eth2util.EpochHashRoot(epoch)
		require.NoError(t, err)
		sigData, err := signing.GetDataRoot(ctx, bmock, signing.DomainRandao, epoch, sigRoot)
		require.NoError(t, err)
		randao := core.NewPartialSignedRandao(epoch, sign(sigData[:]), shareIdx)

		require.NoError(t, verifyFunc(ctx, core.NewRandaoDuty(slot), pubkey, randao))
	})

	t.Run("Verify Voluntary Exit", func(t *testing.T) {
		exit := testutil.RandomExit()
		exit.Message.Epoch = epoch
		sigRoot, err := exit.Message.HashTreeRoot()
		require.NoError(t, err)
		sigData, err := signing.GetDataRoot(ctx, bmock, signing.DomainExit, epoch, sigRoot)
		require.NoError(t, err)
		exit.Signature = sign(sigData[:])
		data := core.NewPartialSignedVoluntaryExit(exit, shareIdx)
		require.NoError(t, err)

		require.NoError(t, verifyFunc(ctx, core.NewVoluntaryExit(slot), pubkey, data))
	})

	t.Run("Verify validator registration", func(t *testing.T) {
		reg := testutil.RandomVersionedSignedValidatorRegistration(t)
		sigRoot, err := reg.V1.Message.HashTreeRoot()
		require.NoError(t, err)
		sigData, err := signing.GetDataRoot(ctx, bmock, signing.DomainApplicationBuilder, 0, sigRoot)
		require.NoError(t, err)
		reg.V1.Signature = sign(sigData[:])
		data, err := core.NewPartialVersionedSignedValidatorRegistration(reg, shareIdx)
		require.NoError(t, err)

		require.NoError(t, verifyFunc(ctx, core.NewBuilderRegistrationDuty(slot), pubkey, data))
	})
}
