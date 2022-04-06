// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

package p2p

import (
	"fmt"

	"github.com/libp2p/go-libp2p-core/peer"
)

// ShortID returns the short ID string of the peer ID. It was inspired by peer.ID.ShortString() but even shorter.
func ShortID(p peer.ID) string {
	pid := p.Pretty()
	if len(pid) <= 10 {
		return pid
	}

	return fmt.Sprintf("%s*%s", pid[:2], pid[len(pid)-6:])
}
