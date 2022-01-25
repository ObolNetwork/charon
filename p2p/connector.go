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
	"github.com/libp2p/go-libp2p-core/connmgr"

	"github.com/obolnetwork/charon/cluster"
)

const tagDVPeer = "dvPeer"

// PinPeers marks all DV peers as protected peers, preventing disconnects.
func PinPeers(clusters *cluster.KnownClusters, connMgr connmgr.ConnManager) error {
	for _, manifest := range clusters.Clusters() {
		peerIDs, err := manifest.PeerIDs()
		if err != nil {
			return err
		}
		for _, id := range peerIDs {
			connMgr.Protect(id, tagDVPeer)
		}
	}
	return nil
}
