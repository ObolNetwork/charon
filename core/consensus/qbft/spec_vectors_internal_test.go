// Copyright © 2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package qbft

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/testutil/specvectors"
)

// This file runs the spec conformance suites that need this package's unexported
// functions. hashProto and verifyMsgLimits are not exported, so an external test
// package cannot reach them; see testutil/specvectors for the suites that Charon's
// exported API can serve.

// TestSpecQBFTHashing pins the deterministic encoding and SSZ hash root of the
// messages a QBFT signature is taken over. Most of these values came out of
// Charon originally, so a failure means Charon has moved away from the encoding
// every other implementation was told to reproduce.
func TestSpecQBFTHashing(t *testing.T) {
	var suite struct {
		Duty []struct {
			Name  string `json:"name"`
			Input struct {
				Slot uint64 `json:"slot"`
				Type int32  `json:"type"`
			} `json:"input"`
			EncodingHex string `json:"encoding_hex"`
			HashHex     string `json:"hash_hex"`
		} `json:"duty"`
		UnsignedDataSet []struct {
			Name  string `json:"name"`
			Input struct {
				Set map[string]string `json:"set"`
			} `json:"input"`
			EncodingHex string `json:"encoding_hex"`
			HashHex     string `json:"hash_hex"`
		} `json:"unsigned_data_set"`
		QBFTSigningRoot []struct {
			Name  string `json:"name"`
			Input struct {
				Type              int64  `json:"type"`
				Slot              uint64 `json:"slot"`
				DutyType          int32  `json:"duty_type"`
				PeerIdx           int64  `json:"peer_idx"`
				Round             int64  `json:"round"`
				PreparedRound     int64  `json:"prepared_round"`
				ValueHash         string `json:"value_hash"`
				PreparedValueHash string `json:"prepared_value_hash"`
			} `json:"input"`
			EncodingHex string `json:"encoding_hex"`
			HashHex     string `json:"hash_hex"`
		} `json:"qbft_signing_root"`
	}
	specvectors.Load(t, "qbft_hashing", &suite)
	require.NotEmpty(t, suite.Duty)
	require.NotEmpty(t, suite.UnsignedDataSet)
	require.NotEmpty(t, suite.QBFTSigningRoot)

	for _, tt := range suite.Duty {
		t.Run("duty/"+tt.Name, func(t *testing.T) {
			requireEncodingAndHash(t, &pbv1.Duty{
				Slot: tt.Input.Slot,
				Type: tt.Input.Type,
			}, tt.EncodingHex, tt.HashHex)
		})
	}

	for _, tt := range suite.UnsignedDataSet {
		t.Run("unsigned_data_set/"+tt.Name, func(t *testing.T) {
			set := make(map[string][]byte, len(tt.Input.Set))
			for pubkey, value := range tt.Input.Set {
				set[pubkey] = specvectors.HexToBytes(t, value)
			}

			requireEncodingAndHash(t, &pbv1.UnsignedDataSet{Set: set}, tt.EncodingHex, tt.HashHex)
		})
	}

	for _, tt := range suite.QBFTSigningRoot {
		t.Run("qbft_signing_root/"+tt.Name, func(t *testing.T) {
			// The signing root is taken over the message with the signature
			// cleared, which is what signMsg and verifyMsgSig both do.
			msg := &pbv1.QBFTMsg{
				Type:              tt.Input.Type,
				Duty:              &pbv1.Duty{Slot: tt.Input.Slot, Type: tt.Input.DutyType},
				PeerIdx:           tt.Input.PeerIdx,
				Round:             tt.Input.Round,
				PreparedRound:     tt.Input.PreparedRound,
				Signature:         nil,
				ValueHash:         specvectors.HexToBytes(t, tt.Input.ValueHash),
				PreparedValueHash: specvectors.HexToBytes(t, tt.Input.PreparedValueHash),
			}

			requireEncodingAndHash(t, msg, tt.EncodingHex, tt.HashHex)
		})
	}
}

// TestSpecQBFTMsgLimits pins the bounds a receiver applies before any
// per-element work. The reason is asserted as well as the rejection: Charon
// checks the justification count first, so a message exceeding both limits is
// rejected for its justifications.
func TestSpecQBFTMsgLimits(t *testing.T) {
	var suite struct {
		Counts []struct {
			Name  string `json:"name"`
			Input struct {
				Nodes              int `json:"nodes"`
				JustificationCount int `json:"justification_count"`
				ValueCount         int `json:"value_count"`
			} `json:"input"`
			Accepted bool   `json:"accepted"`
			Reason   string `json:"reason"`
		} `json:"counts"`
		WireSize []struct {
			Name  string `json:"name"`
			Input struct {
				WireSizeBytes int `json:"wire_size_bytes"`
			} `json:"input"`
			Accepted bool `json:"accepted"`
		} `json:"wire_size"`
	}
	specvectors.Load(t, "qbft_msg_limits", &suite)
	require.NotEmpty(t, suite.Counts)
	require.NotEmpty(t, suite.WireSize)

	for _, tt := range suite.Counts {
		t.Run("counts/"+tt.Name, func(t *testing.T) {
			msg := &pbv1.QBFTConsensusMsg{
				Msg:           &pbv1.QBFTMsg{},
				Justification: make([]*pbv1.QBFTMsg, tt.Input.JustificationCount),
				Values:        make([]*anypb.Any, tt.Input.ValueCount),
			}

			err := verifyMsgLimits(msg, tt.Input.Nodes)
			if tt.Accepted {
				require.NoError(t, err)
				return
			}

			require.Error(t, err)

			switch tt.Reason {
			case "too_many_justifications":
				require.ErrorContains(t, err, "too many justifications")
			case "too_many_values":
				require.ErrorContains(t, err, "too many values")
			default:
				require.Failf(t, "unknown rejection reason", "%q", tt.Reason)
			}
		})
	}

	// The wire size is enforced as a stream read limit, so there is no function
	// to call: assert the constant the consensus component passes to
	// p2p.WithReadLimit. Charon's libp2p default is 128 MiB and consensus
	// narrows it, so leaving the default in place would accept messages four
	// times the permitted size.
	for _, tt := range suite.WireSize {
		t.Run("wire_size/"+tt.Name, func(t *testing.T) {
			require.Equal(t, tt.Accepted, tt.Input.WireSizeBytes <= maxConsensusMsgSize)
		})
	}
}

// requireEncodingAndHash asserts both the deterministic encoding and its hash
// root. The encoding is checked too because a hash mismatch alone does not say
// whether the encoder or the hasher moved.
func requireEncodingAndHash(t *testing.T, msg proto.Message, encodingHex, hashHex string) {
	t.Helper()

	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
	require.NoError(t, err)
	require.Equal(t, encodingHex, hex.EncodeToString(encoded))

	hash, err := hashProto(msg)
	require.NoError(t, err)
	require.Equal(t, hashHex, hex.EncodeToString(hash[:]))
}
