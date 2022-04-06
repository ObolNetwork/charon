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

package log

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFormatZapTest(t *testing.T) {
	tests := []struct {
		Input  string
		Output string
	}{
		{
			Input: `github.com/obolnetwork/charon/app/log_test.TestErrorWrap
	/Users/corver/repos/charon/app/log/log_test.go:57
testing.tRunner
	/opt/homebrew/Cellar/go/1.17.6/libexec/src/testing/testing.go:1259`,
			Output: "	app/log/log_test.go:57 .TestErrorWrap",
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			actual := formatZapStack(test.Input)
			require.Equal(t, test.Output, actual)
		})
	}
}
