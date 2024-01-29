// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/p2p"
)

func TestRunNewEnr(t *testing.T) {
	temp := t.TempDir()

	got := runNewENR(io.Discard, temp, false)
	expected := errors.New("private key not found. If this is your first time running this client, create one with `charon create enr`.", z.Str("enr_path", p2p.KeyPath(temp)))
	require.Equal(t, expected.Error(), got.Error())
}
