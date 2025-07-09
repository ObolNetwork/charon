// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2util_test

import (
	"context"
	"testing"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/testutil"
)

func TestCapellaFork(t *testing.T) {
	tests := []struct {
		name      string
		forkHash  string
		want      string
		errAssert require.ErrorAssertionFunc
	}{
		{
			"bad fork hash string",
			"bad",
			"",
			require.Error,
		},
		{
			"ok fork hash but nonexistent",
			"0x12345678",
			"",
			require.Error,
		},
		{
			"existing ok fork hash",
			"0x00000000",
			"0x03000000",
			require.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := eth2util.CapellaFork(tt.forkHash)
			tt.errAssert(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestComputeDomain(t *testing.T) {
	_, err := eth2util.ComputeDomain("bad", eth2p0.DomainType{0, 0, 0, 0}, eth2p0.Root{})
	require.Error(t, err)

	ret, err := eth2util.ComputeDomain("0x00000000", eth2p0.DomainType{0, 0, 0, 0}, eth2p0.Root{})
	require.NoError(t, err)
	require.NotEmpty(t, ret)
}

type specGenesisProvider struct {
	sp func(ctx context.Context, opts *eth2api.SpecOpts) (*eth2api.Response[map[string]any], error)
	gp func(ctx context.Context, opts *eth2api.GenesisOpts) (*eth2api.Response[*eth2v1.Genesis], error)
}

func (sgp *specGenesisProvider) Genesis(ctx context.Context, opts *eth2api.GenesisOpts) (*eth2api.Response[*eth2v1.Genesis], error) {
	return sgp.gp(ctx, opts)
}

func (sgp *specGenesisProvider) Spec(ctx context.Context, opts *eth2api.SpecOpts) (*eth2api.Response[map[string]any], error) {
	return sgp.sp(ctx, opts)
}

func TestCapellaDomain(t *testing.T) {
	tests := []struct {
		name      string
		forkHash  string
		providers *specGenesisProvider
		err       string
		resFunc   require.ValueAssertionFunc
	}{
		{
			"spec returns error",
			"0x00000000",
			&specGenesisProvider{
				sp: func(ctx context.Context, opts *eth2api.SpecOpts) (*eth2api.Response[map[string]any], error) {
					return &eth2api.Response[map[string]any]{}, errors.New("spec error")
				},
				gp: func(ctx context.Context, opts *eth2api.GenesisOpts) (*eth2api.Response[*eth2v1.Genesis], error) {
					return &eth2api.Response[*eth2v1.Genesis]{}, nil
				},
			},
			"fetch spec",
			require.Empty,
		},
		{
			"genesis returns error",
			"0x00000000",
			&specGenesisProvider{
				sp: func(ctx context.Context, opts *eth2api.SpecOpts) (*eth2api.Response[map[string]any], error) {
					return &eth2api.Response[map[string]any]{}, nil
				},
				gp: func(ctx context.Context, opts *eth2api.GenesisOpts) (*eth2api.Response[*eth2v1.Genesis], error) {
					return &eth2api.Response[*eth2v1.Genesis]{}, errors.New("genesis error")
				},
			},
			"fetch genesis",
			require.Empty,
		},
		{
			name:     "bad fork hash",
			forkHash: "bad",
			providers: &specGenesisProvider{
				sp: func(ctx context.Context, opts *eth2api.SpecOpts) (*eth2api.Response[map[string]any], error) {
					return &eth2api.Response[map[string]any]{
						Data: map[string]any{
							"DOMAIN_VOLUNTARY_EXIT": eth2p0.DomainType{0, 1, 2, 3},
						},
					}, nil
				},
				gp: func(ctx context.Context, opts *eth2api.GenesisOpts) (*eth2api.Response[*eth2v1.Genesis], error) {
					return &eth2api.Response[*eth2v1.Genesis]{
						Data: &eth2v1.Genesis{
							GenesisValidatorsRoot: testutil.RandomRoot(),
						},
					}, nil
				},
			},
			err:     "encoding/hex",
			resFunc: require.Empty,
		},
		{
			name:     "ok",
			forkHash: "0x00000000",
			providers: &specGenesisProvider{
				sp: func(ctx context.Context, opts *eth2api.SpecOpts) (*eth2api.Response[map[string]any], error) {
					return &eth2api.Response[map[string]any]{
						Data: map[string]any{
							"DOMAIN_VOLUNTARY_EXIT": eth2p0.DomainType{0, 1, 2, 3},
						},
					}, nil
				},
				gp: func(ctx context.Context, opts *eth2api.GenesisOpts) (*eth2api.Response[*eth2v1.Genesis], error) {
					return &eth2api.Response[*eth2v1.Genesis]{
						Data: &eth2v1.Genesis{
							GenesisValidatorsRoot: testutil.RandomRoot(),
						},
					}, nil
				},
			},
			err:     "",
			resFunc: require.NotEmpty,
		},
		{
			name:     "fork hash non existent",
			forkHash: "0x12345678",
			providers: &specGenesisProvider{
				sp: func(ctx context.Context, opts *eth2api.SpecOpts) (*eth2api.Response[map[string]any], error) {
					return &eth2api.Response[map[string]any]{
						Data: map[string]any{
							"DOMAIN_VOLUNTARY_EXIT": eth2p0.DomainType{0, 1, 2, 3},
						},
					}, nil
				},
				gp: func(ctx context.Context, opts *eth2api.GenesisOpts) (*eth2api.Response[*eth2v1.Genesis], error) {
					return &eth2api.Response[*eth2v1.Genesis]{
						Data: &eth2v1.Genesis{
							GenesisValidatorsRoot: testutil.RandomRoot(),
						},
					}, nil
				},
			},
			err:     "no capella fork",
			resFunc: require.Empty,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			res, err := eth2util.CapellaDomain(ctx, tt.forkHash, tt.providers, tt.providers)

			if tt.err == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tt.err)
			}

			tt.resFunc(t, res)
		})
	}
}
