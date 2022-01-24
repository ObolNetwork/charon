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
