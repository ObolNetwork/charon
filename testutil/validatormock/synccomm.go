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

package validatormock

import (
	"context"
	"time"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/altair"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/eth2util/signing"
)

func NewSyncCommMember(signFunc SignFunc, pubkeys []eth2p0.BLSPubKey) *SyncCommMember {
	return &SyncCommMember{
		pubkeys:  pubkeys,
		signFunc: signFunc,
	}
}

// SyncCommMember is a stateful structure providing sync committee message and contribution APIs.
type SyncCommMember struct {
	pubkeys  []eth2p0.BLSPubKey
	duties   []*eth2v1.SyncCommitteeDuty
	signFunc SignFunc
}

// PrepareEpoch does store sync committee duties and submits sync committee subscriptions at the start of an epoch.
func (s *SyncCommMember) PrepareEpoch(ctx context.Context, eth2Cl eth2wrap.Client, epoch eth2p0.Epoch) error {
	vals, err := activeValidators(ctx, eth2Cl, s.pubkeys)
	if err != nil {
		return err
	}

	var vIdxs []eth2p0.ValidatorIndex
	for idx := range vals {
		vIdxs = append(vIdxs, idx)
	}

	s.duties, err = eth2Cl.SyncCommitteeDuties(ctx, epoch, vIdxs)
	if err != nil {
		return err
	}

	// Don't proceed if we have no duties.
	if len(s.duties) == 0 {
		return nil
	}

	var subs []*eth2v1.SyncCommitteeSubscription
	for _, duty := range s.duties {
		subs = append(subs, &eth2v1.SyncCommitteeSubscription{
			ValidatorIndex:       duty.ValidatorIndex,
			SyncCommitteeIndices: duty.ValidatorSyncCommitteeIndices,
			UntilEpoch:           epoch + 1,
		})
	}

	err = eth2Cl.SubmitSyncCommitteeSubscriptions(ctx, subs)
	if err != nil {
		return err
	}

	log.Info(ctx, "Mock sync committee subscription submitted")

	return nil
}

// Message submits Sync committee messages at desired i.e., 1/3rd into the slot.
func (s *SyncCommMember) Message(ctx context.Context, eth2Cl eth2wrap.Client, slot eth2p0.Slot, slotStartTime time.Time, slotDuration time.Duration) error {
	if len(s.duties) == 0 {
		return nil
	}

	// Schedule DutySyncMessage 1/3rd into the slot.
	offset := slotDuration / 3

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(time.Until(slotStartTime.Add(offset))):
		return submitSyncMessage(ctx, eth2Cl, slot, s.signFunc, s.duties)
	}
}

// submitSyncMessage submits signed sync committee messages for desired slot.
func submitSyncMessage(ctx context.Context, eth2Cl eth2wrap.Client, slot eth2p0.Slot, signFunc SignFunc, duties []*eth2v1.SyncCommitteeDuty) error {
	blockRoot, err := eth2Cl.BeaconBlockRoot(ctx, "head")
	if err != nil {
		return err
	}

	epoch, err := epochFromSlot(ctx, eth2Cl, slot)
	if err != nil {
		return err
	}

	sigData, err := signing.GetDataRoot(ctx, eth2Cl, signing.DomainSyncCommittee, epoch, *blockRoot)
	if err != nil {
		return err
	}

	var msgs []*altair.SyncCommitteeMessage
	for _, duty := range duties {
		sig, err := signFunc(duty.PubKey, sigData[:])
		if err != nil {
			return err
		}

		msgs = append(msgs, &altair.SyncCommitteeMessage{
			Slot:            slot,
			BeaconBlockRoot: *blockRoot,
			ValidatorIndex:  duty.ValidatorIndex,
			Signature:       sig,
		})
	}

	return eth2Cl.SubmitSyncCommitteeMessages(ctx, msgs)
}

// IsAggregator submits selection proof POST /eth/v1/validator/sync_committee_selections
// and stores the boolean result and selection proof to further generate ContributionAndProof.
// TODO(dhruv): Implement this method as part of https://github.com/ObolNetwork/charon/issues/1268.
func (*SyncCommMember) IsAggregator(context.Context) error {
	return nil
}

// SubmitContribution submits sync committee contributions if chosen as an aggregator based on selection proof.
// TODO(dhruv): Implement this method as part of https://github.com/ObolNetwork/charon/issues/1268.
func (*SyncCommMember) SubmitContribution(context.Context) error {
	return nil
}
