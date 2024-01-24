// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package promrated

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRedactURL(t *testing.T) {
	url := "https://user:password@domain.com"

	redacted := redactURL(url)

	require.Equal(t, "https://user:xxxxx@domain.com", redacted)
}
