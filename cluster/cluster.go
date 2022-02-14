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

package cluster

import (
	"context"

	"github.com/obolnetwork/charon/types"
)

// Consensus abstracts a cluster consensus layer.
type Consensus interface {
	// ResolveDuty returns the cluster's agreed upon data for the given duty.
	// The result will be proposed data from one of the nodes in the cluster.
	ResolveDuty(ctx context.Context, d types.Duty, proposedData []byte) ([]byte, error)
}
