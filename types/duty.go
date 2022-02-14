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

package types

import (
	"fmt"
)

// DutyType enumerates the different types of duties.
type DutyType int

const (
	DutyUnknown = DutyType(iota)
	DutyAttester
)

func (d DutyType) String() string {
	return map[DutyType]string{
		DutyUnknown:  "unknown",
		DutyAttester: "attester",
	}[d]
}

// Duty is a unit of consensus agreed upon by the cluster and executed by the distributed validators.
type Duty struct {
	// Slot is the Ethereum consensus layer slot.
	Slot int
	// Type is the duty type performed in the slot.
	Type DutyType
}

func (d Duty) String() string {
	return fmt.Sprintf("%d/%s", d.Slot, d.Type)
}
