// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

package errors_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
)

func TestWithCtxErr(t *testing.T) {
	msg := "wrap"

	ctx, cancel := context.WithCancel(context.Background())
	ctx = errors.WithCtxErr(ctx, msg)
	cancel()
	require.Contains(t, ctx.Err().Error(), msg)
	require.ErrorIs(t, ctx.Err(), context.Canceled)
}
