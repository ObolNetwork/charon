// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package validatormock

import "time"

// sepcMeta defines the spec constants.
type specMeta struct {
	GenesisTime   time.Time
	SlotDuration  time.Duration
	SlotsPerEpoch uint64
}

// SlotStartTime calculates the start time of a slot by adding slot duration to the genesis time.
func (m specMeta) SlotStartTime(slot uint64) time.Time {
	return m.GenesisTime.Add(time.Duration(slot) * m.SlotDuration)
}

// EpochFromSlot calculates the epoch number from a given slot.
func (m specMeta) EpochFromSlot(slot uint64) metaEpoch {
	epoch := slot / m.SlotsPerEpoch

	return metaEpoch{
		Epoch: epoch,
		meta:  m,
	}
}

// FirstSlotInEpoch returns first slot in the given epoch as metaSlot.
func (m specMeta) FirstSlotInEpoch(epoch uint64) metaSlot {
	return metaSlot{
		Slot: epoch * m.SlotsPerEpoch,
		meta: m,
	}
}

// LastSlotInEpoch returns last slot in the given epoch as metaSlot.
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

// StartTime returns start time of the current metaSlot.
func (s metaSlot) StartTime() time.Time {
	return s.meta.SlotStartTime(s.Slot)
}

// Duration returns slot duration of the current metaSlot.
func (s metaSlot) Duration() time.Duration {
	return s.meta.SlotDuration
}

// Epoch returns epoch number of the current metaSlot as metaEpoch.
func (s metaSlot) Epoch() metaEpoch {
	return s.meta.EpochFromSlot(s.Slot)
}

// Next returns the next metaSlot after the current one.
func (s metaSlot) Next() metaSlot {
	return metaSlot{
		Slot: s.Slot + 1,
		meta: s.meta,
	}
}

// InSlot returns true if the given time t is inside the current metaSlot duration.
func (s metaSlot) InSlot(t time.Time) bool {
	startTime := s.StartTime()      // Including
	endTime := s.Next().StartTime() // Excluding

	return (t.After(startTime) && t.Before(endTime)) || t.Equal(startTime)
}

// FirstInEpoch returns true if the given metaSlot is the first slot in epoch.
func (s metaSlot) FirstInEpoch() bool {
	return s.Slot == s.Epoch().FirstSlot().Slot
}

// metaEpoch defines an epoch with knowledge of spec metadata.
type metaEpoch struct {
	Epoch uint64
	meta  specMeta
}

// FirstSlot returns first slot in current metaEpoch as metaSlot.
func (e metaEpoch) FirstSlot() metaSlot {
	return e.meta.FirstSlotInEpoch(e.Epoch)
}

// LastSlot returns last slot in current metaEpoch as metaSlot.
func (e metaEpoch) LastSlot() metaSlot {
	return e.meta.LastSlotInEpoch(e.Epoch)
}

// Slots returns the slots in the given epoch.
func (e metaEpoch) Slots() []metaSlot {
	return e.SlotsForLookAhead(1)
}

// SlotsForLookAhead returns the slots in future epochs equal to totalEpochs including the current epoch.
func (e metaEpoch) SlotsForLookAhead(totalEpochs uint64) []metaSlot {
	slot := e.FirstSlot()

	var resp []metaSlot
	for range totalEpochs * e.meta.SlotsPerEpoch {
		resp = append(resp, slot)
		slot = slot.Next()
	}

	return resp
}

// SlotsForLookBack returns the slots in past epochs equal to totalEpochs including the current epoch.
func (e metaEpoch) SlotsForLookBack(totalEpochs uint64) []metaSlot {
	epoch := e
	for range totalEpochs {
		epoch = epoch.Prev()
	}

	slot := epoch.FirstSlot()
	total := totalEpochs * e.meta.SlotsPerEpoch

	var resp []metaSlot
	for range total {
		resp = append(resp, slot)
		slot = slot.Next()
	}

	return resp
}

// Next returns the next epoch number as metaEpoch.
func (e metaEpoch) Next() metaEpoch {
	return metaEpoch{
		Epoch: e.Epoch + 1,
		meta:  e.meta,
	}
}

// Prev returns the previous epoch number as metaEpoch.
func (e metaEpoch) Prev() metaEpoch {
	return metaEpoch{
		Epoch: e.Epoch - 1,
		meta:  e.meta,
	}
}
