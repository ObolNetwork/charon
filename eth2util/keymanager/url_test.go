// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package keymanager_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util/keymanager"
)

func TestVerifyKeymanagerAddr(t *testing.T) {
	tests := []struct {
		name   string
		addr   string
		errMsg string
	}{
		{
			name:   "Valid address",
			addr:   "https://keymanager@example.com",
			errMsg: "",
		},
		{
			name:   "Valid localhost",
			addr:   "http://127.0.0.1",
			errMsg: "",
		},
		{
			name:   "Valid localhost with port",
			addr:   "http://127.0.0.1:3756",
			errMsg: "",
		},
		{
			name:   "Address must use https scheme",
			addr:   "http://keymanager@example.com",
			errMsg: "keymanager address must use https scheme",
		},
		{
			name:   "Malformed address",
			addr:   "https://example.com:-80/",
			errMsg: "failed to parse keymanager address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := keymanager.VerifyKeymanagerAddr(tt.addr)
			if tt.errMsg == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tt.errMsg)
			}
		})
	}
}
