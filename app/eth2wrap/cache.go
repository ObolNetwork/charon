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

package eth2wrap

// valCache caches validators by public key.
// type valCache struct {
//	mu   sync.RWMutex
//	vals map[eth2p0.BLSPubKey]*eth2v1.Validator
//}
//
//// Clear the cache.
// func (c *valCache) Clear() {
//	c.mu.Lock()
//	defer c.mu.Unlock()
//
//	c.vals = nil
//}
//
//// Get returns any found validators (hits) and the public keys not found (misses).
// func (c *valCache) Get(pubkeys []eth2p0.BLSPubKey) (map[eth2p0.ValidatorIndex]*eth2v1.Validator, []eth2p0.BLSPubKey) {
//	c.mu.RLock()
//	defer c.mu.RUnlock()
//
//	var (
//		misses []eth2p0.BLSPubKey
//		hits   = make(map[eth2p0.ValidatorIndex]*eth2v1.Validator)
//	)
//	for _, pk := range pubkeys {
//		val, ok := c.vals[pk]
//		if !ok {
//			misses = append(misses, pk)
//			continue
//		}
//		hits[val.Index] = val
//	}
//
//	return hits, misses
//}
//
//// Set stores the validators in the cache.
// func (c *valCache) Set(vals map[eth2p0.ValidatorIndex]*eth2v1.Validator) {
//	c.mu.Lock()
//	defer c.mu.Unlock()
//
//	if c.vals == nil {
//		c.vals = make(map[eth2p0.BLSPubKey]*eth2v1.Validator)
//	}
//
//	for _, val := range vals {
//		c.vals[val.Validator.PublicKey] = val
//	}
//}
