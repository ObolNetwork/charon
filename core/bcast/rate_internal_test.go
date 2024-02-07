// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package bcast

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRate(t *testing.T) {
	var r rate

	t.Run("default rate is zero", func(t *testing.T) {
		require.Equal(t, float64(0), r.getRate())
	})

	t.Run("calculates rate", func(t *testing.T) {
		for i := 0; i < 1000; i++ {
			r.incrementTotal()

			if i%2 == 0 {
				r.incrementCount()
			}
		}

		r.incrementCount()
		require.Less(t, float64(50), r.getRate())
	})
}
