// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package hotstuff

// Collector is used by the leader to collect messages from the replicas.
// Besides deduplication for safety, this also implements MatchingMsg utility,
// as described by the HotStuff paper.
type Collector struct {
	msgs  []*Msg
	dedup map[dedupKey]struct{}
}

type dedupKey struct {
	msgType MsgType
	view    View
	sender  ID
}

func NewCollector() *Collector {
	return &Collector{
		msgs:  make([]*Msg, 0),
		dedup: make(map[dedupKey]struct{}),
	}
}

func (c *Collector) AddMsg(msg *Msg, sender ID) {
	key := dedupKey{
		msgType: msg.Type,
		view:    msg.View,
		sender:  sender,
	}

	if _, ok := c.dedup[key]; ok {
		return
	}

	c.msgs = append(c.msgs, msg)
	c.dedup[key] = struct{}{}
}

func (c *Collector) MatchingMsg(t MsgType, view View) []*Msg {
	matching := make([]*Msg, 0)

	for _, msg := range c.msgs {
		if msg.Type == t && msg.View == view {
			matching = append(matching, msg)
		}
	}

	return matching
}
