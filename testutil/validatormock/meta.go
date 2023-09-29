// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package validatormock

import "time"

// sepcMeta defines the spec constants.
type specMeta struct {
	GenesisTime   time.Time
	SlotDuration  time.Duration
	SlotsPerEpoch uint64
}

func (m specMeta) SlotStartTime(slot uint64) time.Time {
	return m.GenesisTime.Add(time.Duration(slot) * m.SlotDuration)
}

func (m specMeta) EpochFromSlot(slot uint64) metaEpoch {
	epoch := slot / m.SlotsPerEpoch
	return metaEpoch{
		Epoch: epoch,
		meta:  m,
	}
}

func (m specMeta) FirstSlotInEpoch(epoch uint64) metaSlot {
	return metaSlot{
		Slot: epoch * m.SlotsPerEpoch,
		meta: m,
	}
}

func (m specMeta) LastSlotInEpoch(epoch uint64) metaSlot {
	return metaSlot{
		Slot: (epoch+1)*m.SlotsPerEpoch - 1,
		meta: m,
	}
}

// metaSlot defines a slot with knowledge of spec metadata.
type metaSlot struct {
	Slot uint64
	meta specMeta
}

func (s metaSlot) StartTime() time.Time {
	return s.meta.SlotStartTime(s.Slot)
}

func (s metaSlot) Duration() time.Duration {
	return s.meta.SlotDuration
}

func (s metaSlot) Epoch() metaEpoch {
	return s.meta.EpochFromSlot(s.Slot)
}

func (s metaSlot) Next() metaSlot {
	return metaSlot{
		Slot: s.Slot + 1,
		meta: s.meta,
	}
}

func (s metaSlot) InSlot(t time.Time) bool {
	startTime := s.StartTime()      // Including
	endTime := s.Next().StartTime() // Excluding

	return (t.After(startTime) && t.Before(endTime)) || t.Equal(startTime)
}

func (s metaSlot) FirstInEpoch() bool {
	return s.Slot == s.Epoch().FirstSlot().Slot
}

// metaEpoch defines an epoch with knowledge of spec metadata.
type metaEpoch struct {
	Epoch uint64
	meta  specMeta
}

func (e metaEpoch) FirstSlot() metaSlot {
	return e.meta.FirstSlotInEpoch(e.Epoch)
}

func (e metaEpoch) LastSlot() metaSlot {
	return e.meta.LastSlotInEpoch(e.Epoch)
}

func (e metaEpoch) Slots() []metaSlot {
	return e.SlotsForLookAhead(1)
}

func (e metaEpoch) SlotsForLookAhead(totalEpochs uint64) []metaSlot {
	slot := e.FirstSlot()
	var resp []metaSlot
	for i := uint64(0); i < totalEpochs*e.meta.SlotsPerEpoch; i++ {
		resp = append(resp, slot)
		slot = slot.Next()
	}

	return resp
}

func (e metaEpoch) SlotsForLookBack(totalEpochs uint64) []metaSlot {
	epoch := e
	for i := uint64(0); i < totalEpochs; i++ {
		epoch = epoch.Prev()
	}

	slot := epoch.FirstSlot()
	total := totalEpochs * e.meta.SlotsPerEpoch

	var resp []metaSlot
	for i := uint64(0); i < total; i++ {
		resp = append(resp, slot)
		slot = slot.Next()
	}

	return resp
}

func (e metaEpoch) Next() metaEpoch {
	return metaEpoch{
		Epoch: e.Epoch + 1,
		meta:  e.meta,
	}
}

func (e metaEpoch) Prev() metaEpoch {
	return metaEpoch{
		Epoch: e.Epoch - 1,
		meta:  e.meta,
	}
}
