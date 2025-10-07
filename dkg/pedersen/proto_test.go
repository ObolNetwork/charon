// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package pedersen_test

import (
	"testing"

	"github.com/drand/kyber"
	kdkg "github.com/drand/kyber/share/dkg"
	"github.com/stretchr/testify/require"

	pb "github.com/obolnetwork/charon/dkg/dkgpb/v1"
	"github.com/obolnetwork/charon/dkg/pedersen"
)

func TestDealToProtoAndBack(t *testing.T) {
	deal1 := pedersen.DealFromProto(&pb.PedersenDeal{
		ShareIndex:     1,
		EncryptedShare: []byte{1, 2, 3},
	})
	protoDeal := pedersen.DealToProto(deal1)
	deal2 := pedersen.DealFromProto(protoDeal)
	require.Equal(t, deal1, deal2)
}

func TestDealBundleToProtoAndBack(t *testing.T) {
	bundle := kdkg.DealBundle{
		DealerIndex: 1,
		Deals: []kdkg.Deal{
			{
				ShareIndex:     1,
				EncryptedShare: []byte{1, 2, 3},
			},
			{
				ShareIndex:     2,
				EncryptedShare: []byte{4, 5, 6},
			},
		},
		Public: []kyber.Point{
			pedersen.RandomPoint(t),
			pedersen.RandomPoint(t),
		},
		SessionID: []byte("sessionID"),
		Signature: []byte{13, 14, 15},
	}

	protoBundle, err := pedersen.DealBundleToProto(bundle)
	require.NoError(t, err)

	bundle2, err := pedersen.DealBundleFromProto(protoBundle, pedersen.TestSuite(t))
	require.NoError(t, err)
	require.Equal(t, bundle.SessionID, bundle2.SessionID)
	require.Equal(t, bundle.Signature, bundle2.Signature)
	require.Equal(t, bundle.DealerIndex, bundle2.DealerIndex)
	require.Len(t, bundle.Deals, len(bundle2.Deals))

	for i := range bundle.Deals {
		require.Equal(t, bundle.Deals[i], bundle2.Deals[i])
	}

	require.Len(t, bundle.Public, len(bundle2.Public))

	for i := range bundle.Public {
		b1, err := bundle.Public[i].MarshalBinary()
		require.NoError(t, err)

		b2, err := bundle2.Public[i].MarshalBinary()
		require.NoError(t, err)
		require.Equal(t, b1, b2)
	}
}

func TestJustificationToProtoAndBack(t *testing.T) {
	just1, err := pedersen.JustificationFromProto(&pb.PedersenJustification{
		ShareIndex: 1,
		Share:      pedersen.RandomScalarBytes(t),
	}, pedersen.TestSuite(t))
	require.NoError(t, err)

	protoJust, err := pedersen.JustificationToProto(just1)
	require.NoError(t, err)

	just2, err := pedersen.JustificationFromProto(protoJust, pedersen.TestSuite(t))
	require.NoError(t, err)
	require.Equal(t, just1, just2)
}

func TestJustificationBundleToProtoAndBack(t *testing.T) {
	bundle := kdkg.JustificationBundle{
		DealerIndex: 1,
		Justifications: []kdkg.Justification{
			{
				ShareIndex: 1,
				Share:      pedersen.RandomScalar(t),
			},
			{
				ShareIndex: 2,
				Share:      pedersen.RandomScalar(t),
			},
		},
		SessionID: []byte("sessionID"),
		Signature: []byte{13, 14, 15},
	}

	bundleProto, err := pedersen.JustificationBundleToProto(bundle)
	require.NoError(t, err)

	bundle2, err := pedersen.JustificationBundleFromProto(bundleProto, pedersen.TestSuite(t))
	require.NoError(t, err)
	require.Equal(t, bundle.SessionID, bundle2.SessionID)
	require.Equal(t, bundle.Signature, bundle2.Signature)
	require.Equal(t, bundle.DealerIndex, bundle2.DealerIndex)

	require.Len(t, bundle.Justifications, len(bundle2.Justifications))

	for i := range bundle.Justifications {
		b1, err := bundle.Justifications[i].Share.MarshalBinary()
		require.NoError(t, err)

		b2, err := bundle2.Justifications[i].Share.MarshalBinary()
		require.NoError(t, err)
		require.Equal(t, b1, b2)
	}
}

func TestResponseToProtoAndBack(t *testing.T) {
	resp1 := pedersen.ResponseFromProto(&pb.PedersenResponse{
		DealerIndex: 1,
		Status:      true,
	})
	protoResp := pedersen.ResponseToProto(resp1)
	resp2 := pedersen.ResponseFromProto(protoResp)
	require.Equal(t, resp1, resp2)
}

func TestResponseBundleToProtoAndBack(t *testing.T) {
	bundle := kdkg.ResponseBundle{
		ShareIndex: 1,
		Responses: []kdkg.Response{
			{
				DealerIndex: 1,
				Status:      true,
			},
			{
				DealerIndex: 2,
				Status:      false,
			},
		},
		SessionID: []byte("sessionID"),
		Signature: []byte{13, 14, 15},
	}

	bundleProto, err := pedersen.ResponseBundleToProto(bundle)
	require.NoError(t, err)

	bundle2, err := pedersen.ResponseBundleFromProto(bundleProto)
	require.NoError(t, err)
	require.Equal(t, bundle.SessionID, bundle2.SessionID)
	require.Equal(t, bundle.Signature, bundle2.Signature)
	require.Equal(t, bundle.ShareIndex, bundle2.ShareIndex)

	require.Len(t, bundle.Responses, len(bundle2.Responses))

	for i := range bundle.Responses {
		require.Equal(t, bundle.Responses[i], bundle2.Responses[i])
	}
}
