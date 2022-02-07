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

package p2p

import (
	"fmt"

	"github.com/libp2p/go-libp2p-core/peer"
)

// ShortID returns the short ID string of the peer ID. It was inspired by peer.ID.ShortString() but even shorter.
func ShortID(id peer.ID) string {
	pid := id.Pretty()
	if len(pid) <= 10 {
		return pid
	}
	return fmt.Sprintf("%s*%s>", pid[:2], pid[len(pid)-6:])
}
