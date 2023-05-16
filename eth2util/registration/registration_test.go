// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package registration_test

import (
	"testing"
	"time"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util/registration"
	"github.com/obolnetwork/charon/testutil"
)

func TestNewMessage(t *testing.T) {
	gasLimit := uint64(30000000)

	timestamp, err := time.Parse("Jan 2, 2006", "Jan 1, 2000")
	require.NoError(t, err)

	pubk := testutil.RandomEth2PubKey(t)

	expected := eth2v1.ValidatorRegistration{
		GasLimit:  gasLimit,
		Timestamp: timestamp,
		Pubkey:    pubk,
		FeeRecipient: bellatrix.ExecutionAddress{
			50, 29, 203, 82, 159, 57, 69, 188, 148, 254, 206, 169, 211, 188, 92, 175, 53, 37, 59, 148,
		},
	}

	feeRecipient := "0x321dcb529f3945bc94fecea9d3bc5caf35253b94"

	result, err := registration.NewMessage(pubk, feeRecipient, gasLimit, timestamp)
	require.NoError(t, err)
	require.Equal(t, expected, result)
}

func TestNewMessageBadAddress(t *testing.T) {
	gasLimit := uint64(30000000)

	timestamp, err := time.Parse("Jan 2, 2006", "Jan 1, 2000")
	require.NoError(t, err)

	pubk := testutil.RandomEth2PubKey(t)

	feeRecipient := "0x321dcb529f3945bc94fecea9d3bc5caf35253b9"

	result, err := registration.NewMessage(pubk, feeRecipient, gasLimit, timestamp)

	require.ErrorContains(t, err, "invalid address")
	require.Empty(t, result)
}

func TestGetMessageSigningRoot(t *testing.T) {
	gasLimit := uint64(30000000)

	timestamp, err := time.Parse("Jan 2, 2006", "Jan 1, 2000")
	require.NoError(t, err)

	pubk := testutil.RandomEth2PubKey(t)

	msg := eth2v1.ValidatorRegistration{
		GasLimit:  gasLimit,
		Timestamp: timestamp,
		Pubkey:    pubk,
		FeeRecipient: bellatrix.ExecutionAddress{
			50, 29, 203, 82, 159, 57, 69, 188, 148, 254, 206, 169, 211, 188, 92, 175, 53, 37, 59, 148,
		},
	}

	res, err := registration.GetMessageSigningRoot(msg)
	require.NoError(t, err)
	require.NotEmpty(t, res)
	require.Len(t, res, 32)
}
