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

// VIdx is the validator index.
//
// https://benjaminion.xyz/eth2-annotated-spec/phase0/beacon-chain/#custom-types
// Every validator that enters the system is consecutively assigned a unique
// validator index number that is permanent, remaining even after the validator exits.
type VIdx int64
