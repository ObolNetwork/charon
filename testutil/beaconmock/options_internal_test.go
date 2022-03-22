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

package beaconmock

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStubRoot(t *testing.T) {
	root := stubRoot(1)
	require.Equal(t, "0x59b7938aec659956a33c86dd8aca840c00000000000000000000000000000000", fmt.Sprintf("%#x", root))
}
