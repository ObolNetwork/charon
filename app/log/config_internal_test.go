// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
