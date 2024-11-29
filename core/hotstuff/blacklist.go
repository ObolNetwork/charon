// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package hotstuff

type Blacklist uint64

func NewBlacklist() *Blacklist {
	return new(Blacklist)
}

func (b *Blacklist) Add(id ID) {
	*b |= 1 << id
}

func (b *Blacklist) Remove(id ID) {
	*b &= ^(1 << id)
}

func (b Blacklist) Contains(id ID) bool {
	return b&(1<<id) != 0
}
