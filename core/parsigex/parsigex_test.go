// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package parsigex_test

import (
	"context"
	"sync"
	"testing"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/parsigex"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/signing"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/tbls"
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
	for range n {
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
	for i := range n {
		for k := range n {
			if i == k {
				continue
			}

			hosts[i].Peerstore().AddAddrs(hostsInfo[k].ID, hostsInfo[k].Addrs, peerstore.PermanentAddrTTL)
		}
	}

	verifyFunc := func(context.Context, peer.ID, core.Duty, core.PubKey, core.ParSignedData) error {
		return nil
	}

	gaterFunc := func(core.Duty) bool {
		return true
	}

	var wg sync.WaitGroup

	// create ParSigEx components for each host
	for i := range n {
		wg.Add(n - 1)

		sigex := parsigex.NewParSigEx(hosts[i], p2p.Send, i, peers, verifyFunc, gaterFunc)
		sigex.Subscribe(func(_ context.Context, d core.Duty, set core.ParSignedDataSet) error {
			defer wg.Done()

			require.Equal(t, duty, d)
			require.Equal(t, data, set)

			return nil
		})
		parsigexs = append(parsigexs, sigex)
	}

	errCh := make(chan error, n)
	for i := range n {
		wg.Add(1)

		go func(node int) {
			defer wg.Done()
			// broadcast partially signed data
			err := parsigexs[node].Broadcast(context.Background(), duty, data)
			errCh <- err
		}(i)
	}

	for range n {
		err := <-errCh
		require.NoError(t, err)
	}

	wg.Wait()
}

func TestParSigExVerifier(t *testing.T) {
	ctx := context.Background()

	const (
		slot     = 123
		shareIdx = 1
	)

	bmock, err := beaconmock.New(t.Context())
	require.NoError(t, err)

	slotsPerEpoch, err := bmock.SlotsPerEpoch(ctx)
	require.NoError(t, err)

	epoch := eth2p0.Epoch(uint64(slot) / slotsPerEpoch)

	secret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	pk, err := tbls.SecretToPublicKey(secret)
	require.NoError(t, err)

	sign := func(msg []byte) eth2p0.BLSSignature {
		sig, err := tbls.Sign(secret, msg)
		require.NoError(t, err)

		return eth2p0.BLSSignature(sig)
	}

	pubkey, err := core.PubKeyFromBytes(pk[:])
	require.NoError(t, err)

	mp := map[core.PubKey]map[int]tbls.PublicKey{
		pubkey: {
			shareIdx: pk,
		},
	}

	const sender = peer.ID("sender")

	peerShareIdx := map[peer.ID]cluster.NodeIdx{
		sender: {ShareIdx: shareIdx},
	}
	verifyFunc, err := parsigex.NewEth2Verifier(bmock, mp, peerShareIdx)
	require.NoError(t, err)

	t.Run("Verify attestation", func(t *testing.T) {
		att := testutil.RandomDenebVersionedAttestation()
		attData, err := att.Data()
		require.NoError(t, err)
		sigRoot, err := attData.HashTreeRoot()
		require.NoError(t, err)
		sigData, err := signing.GetDataRoot(ctx, bmock, signing.DomainBeaconAttester, attData.Target.Epoch, sigRoot)
		require.NoError(t, err)

		att.Deneb.Signature = sign(sigData[:])
		data, err := core.NewPartialVersionedAttestation(att, shareIdx)
		require.NoError(t, err)
		require.NoError(t, verifyFunc(ctx, sender, core.NewAttesterDuty(slot), pubkey, data))
	})

	t.Run("Verify proposal", func(t *testing.T) {
		proposal := testutil.RandomDenebVersionedSignedProposal()
		proposal.Deneb.SignedBlock.Message.Slot = slot
		sigRoot, err := versionedSignedProposalRoot(t, proposal)
		require.NoError(t, err)
		sigData, err := signing.GetDataRoot(ctx, bmock, signing.DomainBeaconProposer, epoch, sigRoot)
		require.NoError(t, err)

		proposal.Deneb.SignedBlock.Signature = sign(sigData[:])
		data, err := core.NewPartialVersionedSignedProposal(proposal, shareIdx)
		require.NoError(t, err)

		require.NoError(t, verifyFunc(ctx, sender, core.NewProposerDuty(slot), pubkey, data))
	})

	t.Run("Verify blinded proposal", func(t *testing.T) {
		blindedBlock := testutil.RandomDenebVersionedSignedBlindedProposal()
		blindedBlock.DenebBlinded.Message.Slot = slot
		sigRoot, err := blindedBlock.DenebBlinded.Message.HashTreeRoot()
		require.NoError(t, err)

		sigData, err := signing.GetDataRoot(ctx, bmock, signing.DomainBeaconProposer, epoch, sigRoot)
		require.NoError(t, err)

		blindedBlock.DenebBlinded.Signature = sign(sigData[:])
		eth2apiBlinded, err := blindedBlock.ToBlinded()
		require.NoError(t, err)
		data, err := core.NewPartialVersionedSignedBlindedProposal(&eth2apiBlinded, shareIdx)
		require.NoError(t, err)

		require.NoError(t, verifyFunc(ctx, sender, core.NewProposerDuty(slot), pubkey, data))
	})

	t.Run("Verify Randao", func(t *testing.T) {
		sigEpoch := eth2util.SignedEpoch{Epoch: epoch}
		sigRoot, err := sigEpoch.HashTreeRoot()
		require.NoError(t, err)
		sigData, err := signing.GetDataRoot(ctx, bmock, signing.DomainRandao, epoch, sigRoot)
		require.NoError(t, err)

		randao := core.NewPartialSignedRandao(epoch, sign(sigData[:]), shareIdx)

		require.NoError(t, verifyFunc(ctx, sender, core.NewRandaoDuty(slot), pubkey, randao))
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

		require.NoError(t, verifyFunc(ctx, sender, core.NewVoluntaryExit(slot), pubkey, data))
	})

	t.Run("Verify validator registration", func(t *testing.T) {
		reg, err := core.NewVersionedSignedValidatorRegistration(testutil.RandomVersionedSignedValidatorRegistration(t))
		require.NoError(t, err)
		sigRoot, err := reg.V1.Message.HashTreeRoot()
		require.NoError(t, err)
		epoch, err := reg.Epoch(ctx, bmock)
		require.NoError(t, err)
		sigData, err := signing.GetDataRoot(ctx, bmock, signing.DomainApplicationBuilder, epoch, sigRoot)
		require.NoError(t, err)

		reg.V1.Signature = sign(sigData[:])
		data, err := core.NewPartialVersionedSignedValidatorRegistration(&reg.VersionedSignedValidatorRegistration, shareIdx)
		require.NoError(t, err)

		require.NoError(t, verifyFunc(ctx, sender, core.NewBuilderRegistrationDuty(slot), pubkey, data))
	})

	t.Run("Verify beacon committee selection", func(t *testing.T) {
		selection := testutil.RandomBeaconCommitteeSelection()
		selection.Slot = slot
		sigRoot, err := eth2util.SlotHashRoot(selection.Slot)
		require.NoError(t, err)
		sigData, err := signing.GetDataRoot(ctx, bmock, signing.DomainSelectionProof, epoch, sigRoot)
		require.NoError(t, err)

		selection.SelectionProof = sign(sigData[:])
		data := core.NewPartialSignedBeaconCommitteeSelection(selection, shareIdx)

		require.NoError(t, verifyFunc(ctx, sender, core.NewPrepareAggregatorDuty(slot), pubkey, data))
	})

	t.Run("Verify aggregate and proof", func(t *testing.T) {
		agg := &eth2spec.VersionedSignedAggregateAndProof{
			Version: eth2spec.DataVersionDeneb,
			Deneb: &eth2p0.SignedAggregateAndProof{
				Message: &eth2p0.AggregateAndProof{
					AggregatorIndex: 0,
					Aggregate:       testutil.RandomPhase0Attestation(),
					SelectionProof:  testutil.RandomEth2Signature(),
				},
			},
		}
		agg.Deneb.Message.Aggregate.Data.Slot = slot
		sigRoot, err := agg.Deneb.Message.HashTreeRoot()
		require.NoError(t, err)
		sigData, err := signing.GetDataRoot(ctx, bmock, signing.DomainAggregateAndProof, epoch, sigRoot)
		require.NoError(t, err)

		agg.Deneb.Signature = sign(sigData[:])
		data := core.NewPartialVersionedSignedAggregateAndProof(agg, shareIdx)

		require.NoError(t, verifyFunc(ctx, sender, core.NewAggregatorDuty(slot), pubkey, data))
	})

	t.Run("verify sync committee message", func(t *testing.T) {
		msg := testutil.RandomSyncCommitteeMessage()
		msg.Slot = slot

		sigData, err := signing.GetDataRoot(ctx, bmock, signing.DomainSyncCommittee, epoch, msg.BeaconBlockRoot)
		require.NoError(t, err)

		msg.Signature = sign(sigData[:])

		data := core.NewPartialSignedSyncMessage(msg, shareIdx)
		require.NoError(t, verifyFunc(ctx, sender, core.NewSyncMessageDuty(slot), pubkey, data))

		// Invalid sync committee message.
		data = core.NewPartialSignedRandao(epoch, testutil.RandomEth2Signature(), shareIdx)
		err = verifyFunc(ctx, sender, core.NewSyncMessageDuty(slot), pubkey, data)
		require.Error(t, err)
		require.ErrorContains(t, err, "invalid signature")
	})

	t.Run("verify sync committee selection", func(t *testing.T) {
		selection := testutil.RandomSyncCommitteeSelection()
		selection.Slot = slot

		data := &altair.SyncAggregatorSelectionData{
			Slot:              selection.Slot,
			SubcommitteeIndex: selection.SubcommitteeIndex,
		}
		sigRoot, err := data.HashTreeRoot()
		require.NoError(t, err)

		sigData, err := signing.GetDataRoot(ctx, bmock, signing.DomainSyncCommitteeSelectionProof, epoch, sigRoot)
		require.NoError(t, err)

		selection.SelectionProof = sign(sigData[:])

		parSigData := core.NewPartialSignedSyncCommitteeSelection(selection, shareIdx)

		require.NoError(t, verifyFunc(ctx, sender, core.NewPrepareSyncContributionDuty(slot), pubkey, parSigData))
	})

	t.Run("verify sync committee contribution and proof", func(t *testing.T) {
		proof := testutil.RandomSignedSyncContributionAndProof()
		proof.Message.Contribution.Slot = slot

		sigRoot, err := proof.Message.HashTreeRoot()
		require.NoError(t, err)

		sigData, err := signing.GetDataRoot(ctx, bmock, signing.DomainContributionAndProof, epoch, sigRoot)
		require.NoError(t, err)

		proof.Signature = sign(sigData[:])

		parSigData := core.NewPartialSignedSyncContributionAndProof(proof, shareIdx)

		require.NoError(t, verifyFunc(ctx, sender, core.NewPrepareSyncContributionDuty(slot), pubkey, parSigData))
	})

	t.Run("Reject valid signature from unauthenticated sender", func(t *testing.T) {
		// A cryptographically valid Randao partial for shareIdx, but relayed by a peer not bound to it.
		sigEpoch := eth2util.SignedEpoch{Epoch: epoch}
		sigRoot, err := sigEpoch.HashTreeRoot()
		require.NoError(t, err)
		sigData, err := signing.GetDataRoot(ctx, bmock, signing.DomainRandao, epoch, sigRoot)
		require.NoError(t, err)

		randao := core.NewPartialSignedRandao(epoch, sign(sigData[:]), shareIdx)

		err = verifyFunc(ctx, peer.ID("eve"), core.NewRandaoDuty(slot), pubkey, randao)
		require.ErrorContains(t, err, "unknown peer")
	})
}

// TestVerifyPeerShareIdx covers the sender->shareIdx binding, including a non-contiguous layout where
// a peer's assigned share index does not equal its position (as when earlier operators are removed).
func TestVerifyPeerShareIdx(t *testing.T) {
	const (
		self    = peer.ID("self")
		other   = peer.ID("other")
		unknown = peer.ID("unknown")
	)

	// "other" is the second peer but keeps share index 4, e.g. after operators with lower indices
	// have been removed.
	peerMap := map[peer.ID]cluster.NodeIdx{
		self:  {PeerIdx: 0, ShareIdx: 1},
		other: {PeerIdx: 1, ShareIdx: 4},
	}

	tests := []struct {
		name     string
		sender   peer.ID
		shareIdx int
		wantErr  string
	}{
		{name: "own share index accepted", sender: self, shareIdx: 1},
		{name: "assigned non-contiguous share index accepted", sender: other, shareIdx: 4},
		{name: "mismatched share index rejected", sender: other, shareIdx: 2, wantErr: "share index does not match"},
		{name: "another peer's share index rejected", sender: self, shareIdx: 4, wantErr: "share index does not match"},
		{name: "non-positive share index rejected", sender: self, shareIdx: 0, wantErr: "share index does not match"},
		{name: "unknown sender rejected", sender: unknown, shareIdx: 1, wantErr: "unknown peer"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := core.NewPartialSignature(testutil.RandomCoreSignature(), tt.shareIdx)

			err := parsigex.VerifyPeerShareIdx(peerMap, tt.sender, data)
			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tt.wantErr)
			}
		})
	}
}

func versionedSignedProposalRoot(t *testing.T, p *eth2api.VersionedSignedProposal) (eth2p0.Root, error) {
	t.Helper()

	switch p.Version {
	case eth2spec.DataVersionPhase0:
		return p.Phase0.Message.HashTreeRoot()
	case eth2spec.DataVersionAltair:
		return p.Altair.Message.HashTreeRoot()
	case eth2spec.DataVersionBellatrix:
		return p.Bellatrix.Message.HashTreeRoot()
	case eth2spec.DataVersionCapella:
		return p.Capella.Message.HashTreeRoot()
	case eth2spec.DataVersionDeneb:
		return p.Deneb.SignedBlock.Message.HashTreeRoot()
	case eth2spec.DataVersionElectra:
		return p.Electra.SignedBlock.Message.HashTreeRoot()
	case eth2spec.DataVersionFulu:
		return p.Fulu.SignedBlock.Message.HashTreeRoot()
	default:
		require.Equal(t, 0, 1)
	}

	return eth2p0.Root{}, nil
}
