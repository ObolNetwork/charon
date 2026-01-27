// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2wrap_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/eth2wrap/mocks"
)

func TestMulti_Name(t *testing.T) {
	client := mocks.NewClient(t)

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client}, nil)

	require.Equal(t, "eth2wrap.multi", m.Name())
}

func TestMulti_Address(t *testing.T) {
	client := mocks.NewClient(t)
	client.On("Address").Return("test").Once()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client}, nil)

	require.Equal(t, "test", m.Address())
}

func TestMulti_IsActive(t *testing.T) {
	client1 := mocks.NewClient(t)
	client1.On("IsActive").Return(false).Once()

	client2 := mocks.NewClient(t)
	client2.On("IsActive").Return(true).Once()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client1, client2}, nil)

	require.True(t, m.IsActive())
}

func TestMulti_IsSynced(t *testing.T) {
	client1 := mocks.NewClient(t)
	client1.On("IsSynced").Return(false).Once()

	client2 := mocks.NewClient(t)
	client2.On("IsSynced").Return(true).Once()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client1, client2}, nil)

	require.True(t, m.IsSynced())
}

func TestMulti_ActiveValidators(t *testing.T) {
	ctx := context.Background()
	vals := make(eth2wrap.ActiveValidators)

	client := mocks.NewClient(t)
	client.On("ActiveValidators", mock.Anything).Return(vals, nil).Once()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client}, nil)

	vals2, err := m.ActiveValidators(ctx)
	require.NoError(t, err)
	require.Equal(t, vals, vals2)

	expectedErr := errors.New("boo")
	client.On("ActiveValidators", mock.Anything).Return(nil, expectedErr).Once()

	_, err = m.ActiveValidators(ctx)
	require.ErrorIs(t, err, expectedErr)
}

func TestMulti_SetValidatorCache(t *testing.T) {
	valCache := func(context.Context) (eth2wrap.ActiveValidators, eth2wrap.CompleteValidators, error) {
		return nil, nil, nil
	}

	client := mocks.NewClient(t)
	client.On("SetValidatorCache", mock.Anything).Once()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client}, nil)
	m.SetValidatorCache(valCache)
}

func TestMulti_SetDutiesCache(t *testing.T) {
	proposerDutiesCache := func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.ProposerDuty, error) {
		return nil, nil
	}
	attesterDutiesCache := func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.AttesterDuty, error) {
		return nil, nil
	}
	syncDutiesCache := func(context.Context, eth2p0.Epoch, []eth2p0.ValidatorIndex) ([]*eth2v1.SyncCommitteeDuty, error) {
		return nil, nil
	}

	client := mocks.NewClient(t)
	client.On("SetDutiesCache", mock.Anything, mock.Anything, mock.Anything).Once()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client}, nil)
	m.SetDutiesCache(proposerDutiesCache, attesterDutiesCache, syncDutiesCache)
}

func TestMulti_ProposerDutiesCache(t *testing.T) {
	ctx := context.Background()
	proposerDuties := make([]*eth2v1.ProposerDuty, 0)

	client := mocks.NewClient(t)
	client.On("ProposerDutiesCache", mock.Anything, mock.Anything, mock.Anything).Return(proposerDuties, nil).Once()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client}, nil)

	proposerDuties2, err := m.ProposerDutiesCache(ctx, 0, []eth2p0.ValidatorIndex{})
	require.NoError(t, err)
	require.Equal(t, proposerDuties, proposerDuties2)
}

func TestMulti_AttesterDutiesCache(t *testing.T) {
	ctx := context.Background()
	attesterDuties := make([]*eth2v1.AttesterDuty, 0)

	client := mocks.NewClient(t)
	client.On("AttesterDutiesCache", mock.Anything, mock.Anything, mock.Anything).Return(attesterDuties, nil).Once()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client}, nil)

	attesterDuties2, err := m.AttesterDutiesCache(ctx, 0, []eth2p0.ValidatorIndex{})
	require.NoError(t, err)
	require.Equal(t, attesterDuties, attesterDuties2)
}

func TestMulti_SyncDutiesCache(t *testing.T) {
	ctx := context.Background()
	syncDuties := make([]*eth2v1.SyncCommitteeDuty, 0)

	client := mocks.NewClient(t)
	client.On("SyncCommDutiesCache", mock.Anything, mock.Anything, mock.Anything).Return(syncDuties, nil).Once()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client}, nil)

	syncDuties2, err := m.SyncCommDutiesCache(ctx, 0, []eth2p0.ValidatorIndex{})
	require.NoError(t, err)
	require.Equal(t, syncDuties, syncDuties2)
}

func TestMulti_UpdateCacheIndices(t *testing.T) {
	ctx := context.Background()

	client := mocks.NewClient(t)
	client.On("UpdateCacheIndices", ctx, []eth2p0.ValidatorIndex{}).Return().Once()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client}, nil)

	m.UpdateCacheIndices(ctx, []eth2p0.ValidatorIndex{})
}

func TestMulti_Proxy(t *testing.T) {
	client := mocks.NewClient(t)
	client.On("Proxy", mock.Anything, mock.Anything).Return(nil, nil).Once()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client}, nil)

	req, err := http.NewRequest(http.MethodGet, "", nil)
	require.NoError(t, err)

	_, err = m.Proxy(t.Context(), req)
	require.NoError(t, err)
}

func TestMulti_Proxy_ReadBody(t *testing.T) {
	cl1 := mocks.NewClient(t)
	cl1.On("Proxy", mock.Anything, mock.MatchedBy(func(req *http.Request) bool {
		_, err := io.ReadAll(req.Body)
		require.NoError(t, err)

		return true
	})).Return(nil, errors.New("syncing")).Once() // force fallback to also read body

	cl2 := mocks.NewClient(t)
	cl2.On("Proxy", mock.Anything, mock.MatchedBy(func(req *http.Request) bool {
		_, err := io.ReadAll(req.Body)
		require.NoError(t, err)

		return true
	})).Return(nil, nil).Once()

	// Two clients reading the same body should not error since the body is duplicated for each backend.
	m := eth2wrap.NewMultiForT([]eth2wrap.Client{cl1}, []eth2wrap.Client{cl2})
	bodyReader := strings.NewReader("foo")
	req, err := http.NewRequest(http.MethodPost, "", bodyReader)
	require.NoError(t, err)

	_, err = m.Proxy(t.Context(), req)
	require.NoError(t, err)
}

func TestMulti_ClientForAddress(t *testing.T) {
	client1 := mocks.NewClient(t)
	client1.On("Address").Return("http://bn1:5051").Maybe()

	client2 := mocks.NewClient(t)
	client2.On("Address").Return("http://bn2:5052").Maybe()

	fallback := mocks.NewClient(t)
	fallback.On("Address").Return("http://fallback:5053").Maybe()

	m := eth2wrap.NewMultiForT([]eth2wrap.Client{client1, client2}, []eth2wrap.Client{fallback})

	t.Run("address found in primary clients", func(t *testing.T) {
		scoped := m.ClientForAddress("http://bn1:5051")
		require.NotNil(t, scoped)
		// The scoped client should only use the specified address
		require.Equal(t, "http://bn1:5051", scoped.Address())
	})

	t.Run("address found in fallback clients", func(t *testing.T) {
		scoped := m.ClientForAddress("http://fallback:5053")
		require.NotNil(t, scoped)
		require.Equal(t, "http://fallback:5053", scoped.Address())
	})

	t.Run("address not found", func(t *testing.T) {
		// Should return the original multi client
		scoped := m.ClientForAddress("http://unknown:5054")
		require.NotNil(t, scoped)
		// When address is not found, it returns the original multi client
		// which will use the first client's address
		require.Equal(t, "http://bn1:5051", scoped.Address())
	})

	t.Run("empty address", func(t *testing.T) {
		// Should return the original multi client
		scoped := m.ClientForAddress("")
		require.NotNil(t, scoped)
		require.Equal(t, "http://bn1:5051", scoped.Address())
	})
}
