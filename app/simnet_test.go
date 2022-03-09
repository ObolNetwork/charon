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

package app_test

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/tbls"
)

func TestPanic(t *testing.T) {
	const n, c = 100, 3

	for i := 0; i < n; i++ {
		manifest, _, _ := app.NewClusterForT(t, 1, c, c, 0)

		var wg sync.WaitGroup
		for _, dv := range manifest.DVs {
			for i := 0; i < c; i++ {
				wg.Add(1)
				go func(dv tbls.TSS, i int) {
					_, err := dv.PublicShare(i + 1)
					require.NoError(t, err)
					wg.Done()
				}(dv, i)
			}
		}
		wg.Wait()
	}
}
