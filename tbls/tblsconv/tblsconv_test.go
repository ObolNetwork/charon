// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package tblsconv_test

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	v2 "github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil"
)

func TestPrivkeyFromBytes(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    v2.PrivateKey
		wantErr bool
	}{
		{
			"empty input",
			[]byte{},
			v2.PrivateKey{},
			true,
		},
		{
			"more data than expected",
			bytes.Repeat([]byte{42}, len(v2.PrivateKey{})+1),
			v2.PrivateKey{},
			true,
		},
		{
			"less data than expected",
			bytes.Repeat([]byte{42}, len(v2.PrivateKey{})-1),
			v2.PrivateKey{},
			true,
		},
		{
			"enough data",
			bytes.Repeat([]byte{42}, len(v2.PrivateKey{})),
			*(*v2.PrivateKey)(bytes.Repeat([]byte{42}, len(v2.PrivateKey{}))),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tblsconv.PrivkeyFromBytes(tt.data)

			if tt.wantErr {
				require.Error(t, err)
				require.Empty(t, got)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestPubkeyFromBytes(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    v2.PublicKey
		wantErr bool
	}{
		{
			"empty input",
			[]byte{},
			v2.PublicKey{},
			true,
		},
		{
			"more data than expected",
			bytes.Repeat([]byte{42}, len(v2.PublicKey{})+1),
			v2.PublicKey{},
			true,
		},
		{
			"less data than expected",
			bytes.Repeat([]byte{42}, len(v2.PublicKey{})-1),
			v2.PublicKey{},
			true,
		},
		{
			"enough data",
			bytes.Repeat([]byte{42}, len(v2.PublicKey{})),
			*(*v2.PublicKey)(bytes.Repeat([]byte{42}, len(v2.PublicKey{}))),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tblsconv.PubkeyFromBytes(tt.data)

			if tt.wantErr {
				require.Error(t, err)
				require.Empty(t, got)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestPubkeyToETH2(t *testing.T) {
	pubkey, err := tblsconv.PubkeyFromBytes(bytes.Repeat([]byte{42}, len(v2.PublicKey{})))
	require.NoError(t, err)

	res, err := tblsconv.PubkeyToETH2(pubkey)
	require.NoError(t, err)

	require.Equal(t, pubkey[:], res[:])
}

func TestPubkeyFromCore(t *testing.T) {
	pubkey := testutil.RandomCorePubKey(t)

	res, err := tblsconv.PubkeyFromCore(pubkey)
	require.NoError(t, err)

	expect, err := hex.DecodeString(strings.TrimPrefix(string(pubkey), "0x"))
	require.NoError(t, err)
	require.Equal(t, expect, res[:])
}

func TestSignatureFromBytes(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    v2.Signature
		wantErr bool
	}{
		{
			"empty input",
			[]byte{},
			v2.Signature{},
			true,
		},
		{
			"more data than expected",
			bytes.Repeat([]byte{42}, len(v2.Signature{})+1),
			v2.Signature{},
			true,
		},
		{
			"less data than expected",
			bytes.Repeat([]byte{42}, len(v2.Signature{})-1),
			v2.Signature{},
			true,
		},
		{
			"enough data",
			bytes.Repeat([]byte{42}, len(v2.Signature{})),
			*(*v2.Signature)(bytes.Repeat([]byte{42}, len(v2.Signature{}))),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tblsconv.SignatureFromBytes(tt.data)

			if tt.wantErr {
				require.Error(t, err)
				require.Empty(t, got)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestSigFromCore(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    v2.Signature
		wantErr bool
	}{
		{
			"empty input",
			[]byte{},
			v2.Signature{},
			true,
		},
		{
			"more data than expected",
			bytes.Repeat([]byte{42}, len(v2.Signature{})+1),
			v2.Signature{},
			true,
		},
		{
			"less data than expected",
			bytes.Repeat([]byte{42}, len(v2.Signature{})-1),
			v2.Signature{},
			true,
		},
		{
			"enough data",
			bytes.Repeat([]byte{42}, len(v2.Signature{})),
			*(*v2.Signature)(bytes.Repeat([]byte{42}, len(v2.Signature{}))),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tblsconv.SigFromCore(tt.data)

			if tt.wantErr {
				require.Error(t, err)
				require.Empty(t, got)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestSigToCore(t *testing.T) {
	sig, err := tblsconv.SignatureFromBytes(bytes.Repeat([]byte{42}, len(v2.Signature{})))
	require.NoError(t, err)

	coresig := tblsconv.SigToCore(sig)

	require.Equal(t, sig[:], []byte(coresig))
}

func TestSigToETH2(t *testing.T) {
	sig, err := tblsconv.SignatureFromBytes(bytes.Repeat([]byte{42}, len(v2.Signature{})))
	require.NoError(t, err)

	coresig := tblsconv.SigToETH2(sig)

	require.Equal(t, sig[:], coresig[:])
}
