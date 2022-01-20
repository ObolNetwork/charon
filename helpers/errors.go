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

package helpers

import "fmt"

type NotEnoughSignaturesError struct {
	Present   int
	Threshold int
}

func (e NotEnoughSignaturesError) Error() string {
	return fmt.Sprintf("insufficient signatures; threshold requires %d valid signatures but got %d",
		e.Threshold, e.Present)
}
