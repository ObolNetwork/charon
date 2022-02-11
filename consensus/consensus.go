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

package consensus

import (
	"context"
)

// Consensus abstracts a cluster consensus layer.
type Consensus interface {
	// ResolveDuty returns the cluster's agreed upon data for the given duty.
	// The result will be proposed data from one of the nodes in the cluster.
	ResolveDuty(ctx context.Context, d Duty, proposedData []byte) ([]byte, error)
}

type DutyType int

const (
	DutyUnknown = DutyType(iota)
	DutyAttester
	dutySentinel
)

func (t DutyType) Valid() bool {
	return t > DutyUnknown && t < dutySentinel
}

type Duty struct {
	Slot int
	Type DutyType
}
