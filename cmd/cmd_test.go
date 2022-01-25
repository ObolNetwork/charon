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

package cmd

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCommands(t *testing.T) {
	commands := []struct {
		name string
		args []string
		out  string
	}{
		{"version without verbose", []string{"version"}, `v0.1.0-dirty`},
	}

	for _, cmd := range commands {
		t.Run(cmd.name, func(t *testing.T) {
			root := New()
			output := &bytes.Buffer{}
			root.SetOut(output)
			root.SetArgs(cmd.args)

			err := root.Execute()
			require.NoError(t, err)

			actualOutput := output.String()
			require.Equal(t, cmd.out, actualOutput)
		})
	}
}
