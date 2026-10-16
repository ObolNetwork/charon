// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package payloadex_test

import (
	"context"
	"testing"
	"time"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/jonboulle/clockwork"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/dutydb"
	"github.com/obolnetwork/charon/core/payloadex"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/testutil"
)

func TestPayloadEx(t *testing.T) {
	t.Run("pushed", func(t *testing.T) {
		testPayloadEx(t, nil)
	})

	t.Run("pulled", func(t *testing.T) {
		// The proposer and peer 2 can't reach each other, so peer 2 pulls the contents from peer 1.
		testPayloadEx(t, map[int][]int{0: {2}, 2: {0}})
	})
}

// testPayloadEx exchanges the contents of a self-built proposal built by peer 0, the proposer,
// between three nodes with real DutyDBs, with the given links broken (from peer index to peer
// indexes), in both the push and the pull.
func testPayloadEx(t *testing.T, broken map[int][]int) {
	t.Helper()

	const (
		n           = 3
		proposerIdx = 0
		slot        = 1
	)

	ctx := t.Context()
	duty := core.NewProposerDuty(slot)
	pubkey := testutil.RandomCorePubKey(t)
	defSet := core.DutyDefinitionSet{pubkey: core.NewProposerDefinition(&eth2v1.ProposerDuty{Slot: slot})}
	retentionFunc := func(core.Duty) (time.Time, bool) { return time.Now().Add(time.Minute), true }

	contents := testutil.RandomGloasCoreVersionedEPBSProposalWithPayload()
	contents.EPBS.GloasContents.Block.Slot = slot

	root, err := contents.Root()
	require.NoError(t, err)

	// The cluster agrees on the bare block with the root of its contents.
	agreed, err := core.WithoutPayloadContents(contents)
	require.NoError(t, err)

	var (
		hosts []host.Host
		peers []p2p.Peer
	)

	for i := range n {
		key := testutil.GenerateInsecureK1Key(t, i)
		h := testutil.CreateHostWithIdentity(t, testutil.AvailableAddr(t), key)

		hosts = append(hosts, h)
		peers = append(peers, p2p.Peer{ID: h.ID(), Index: i})
	}

	for i := range n {
		for k := range n {
			if i != k {
				hosts[i].Peerstore().AddAddrs(hosts[k].ID(), hosts[k].Addrs(), peerstore.PermanentAddrTTL)
			}
		}
	}

	isBroken := func(from int, to peer.ID) bool {
		for _, idx := range broken[from] {
			if to == hosts[idx].ID() {
				return true
			}
		}

		return false
	}

	var (
		dbs        []*dutydb.MemDB
		payloadExs []*payloadex.PayloadEx
	)

	for i := range n {
		sendFunc := func(ctx context.Context, h host.Host, pID protocol.ID, peerID peer.ID, msg proto.Message, opts ...p2p.SendRecvOption) error {
			if isBroken(i, peerID) {
				return nil // Dropped.
			}

			return p2p.Send(ctx, h, pID, peerID, msg, opts...)
		}

		sendReceiveFunc := func(ctx context.Context, h host.Host, peerID peer.ID, req, resp proto.Message, pID protocol.ID, opts ...p2p.SendRecvOption) error {
			if isBroken(i, peerID) {
				return errors.New("broken link")
			}

			return p2p.SendReceive(ctx, h, peerID, req, resp, pID, opts...)
		}

		db := dutydb.NewMemDB(core.NewDeadlinerForT(ctx, t, retentionFunc, clockwork.NewRealClock()))

		p := payloadex.New(hosts[i], sendFunc, sendReceiveFunc, i, peers, func(core.Duty) bool { return true }, retentionFunc)
		p.RegisterAwaitVersionedProposal(db.AwaitVersionedProposal)
		p.RegisterAwaitPayloadContents(db.AwaitPayloadContents)
		p.RegisterStorePayloadContents(db.StorePayloadContents)

		// Only the proposer fetched the block, so only it holds its contents as its candidate.
		if i == proposerIdx {
			require.NoError(t, p.StoreCandidate(ctx, contents))
		}

		dbs = append(dbs, db)
		payloadExs = append(payloadExs, p)
	}

	// The scheduler triggers the duty on every node before the decision.
	for _, p := range payloadExs {
		require.NoError(t, p.Exchange(ctx, duty, defSet))
	}

	// Every node decides on the proposer's block: the proposer pushes, the others pull if needed.
	for _, db := range dbs {
		require.NoError(t, db.Store(ctx, duty, core.UnsignedDataSet{pubkey: agreed}))
	}

	// Every node ends up with the agreed contents in its DutyDB.
	for _, db := range dbs {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)

		got, err := db.AwaitPayloadContents(ctx, slot, root)

		cancel()
		require.NoError(t, err)
		require.Equal(t, contents.EPBS, got)
	}
}
