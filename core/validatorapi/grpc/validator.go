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

package grpc

import (
	"context"
	"fmt"
	"math/rand"
	"sync"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/jonboulle/clockwork"
	pb "github.com/prysmaticlabs/prysm/v3/consensus-types/primitives"
	prysmpb "github.com/prysmaticlabs/prysm/v3/proto/prysm/v1alpha1"

	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/scheduler"
)

var _ prysmpb.BeaconNodeValidatorServer = (*BeaconNodeValidatorServer)(nil)

// BeaconNodeValidatorServer implements the server API for BeaconNodeValidator grpc service.
//
// The beacon node validator API enables a validator to connect
// and perform its obligations on the Ethereum Beacon Chain.
type BeaconNodeValidatorServer struct {
	dutyDB             core.DutyDB
	syncDutiesProvider eth2client.SyncCommitteeDutiesProvider
	attDutiesProvider  eth2client.AttesterDutiesProvider
	propDutiesProvider eth2client.ProposerDutiesProvider
	prepareSubmitter   eth2client.ProposalPreparationsSubmitter
	valsProvider       eth2client.ValidatorsProvider
	eventsProvider     eth2client.EventsProvider
	blockProvider      eth2client.SignedBeaconBlockProvider

	eth2Cl     eth2wrap.Client
	builderAPI bool

	mu      sync.Mutex
	streams map[int64]func(epoch eth2p0.Epoch)

	aggSigDB core.AggSigDB
}

// GetDuties 🎉 can proxy to valiatgorAPI (multiple calls)
func (s *BeaconNodeValidatorServer) GetDuties(ctx context.Context, req *prysmpb.DutiesRequest) (*prysmpb.DutiesResponse, error) {
	pubkeys := toGroupPubkeys(req.PublicKeys)

	current := s.getDuties(ctx, eth2p0.Epoch(req.Epoch), pubkeys)
	next := s.getDuties(ctx, eth2p0.Epoch(req.Epoch+1), pubkeys)

	return &prysmpb.DutiesResponse{
		CurrentEpochDuties: current,
		NextEpochDuties:    next,
	}, nil
}

// StreamDuties 🕰 requires scheduler epoch events, 🎉 but can then just query validatorAPI.
func (s *BeaconNodeValidatorServer) StreamDuties(req *prysmpb.DutiesRequest, server prysmpb.BeaconNodeValidator_StreamDutiesServer) error {
	ctx := server.Context()
	first, _ := s.GetDuties(ctx, req)
	_ = server.Send(first)

	s.subscribeEpoch(func(epoch eth2p0.Epoch) {
		req.Epoch = pb.Epoch(epoch)
		duties, _ := s.GetDuties(ctx, req)
		_ = server.Send(duties)
	})

	return nil
}

// DomainData 🎉 can proxy to valiatgorAPI
func (s *BeaconNodeValidatorServer) DomainData(ctx context.Context, req *prysmpb.DomainRequest) (*prysmpb.DomainResponse, error) {
	var domainType eth2p0.DomainType
	copy(domainType[:], req.Domain)

	resp, _ := s.eth2Cl.Domain(ctx, domainType, eth2p0.Epoch(req.Epoch))

	return &prysmpb.DomainResponse{SignatureDomain: resp[:]}, nil
}

// DomainData 🎉 can proxy to valiatgorAPI (copy simple scheduler logic)
func (s *BeaconNodeValidatorServer) WaitForChainStart(e *empty.Empty, server prysmpb.BeaconNodeValidator_WaitForChainStartServer) error {
	scheduler.WaitChainStart(server.Context(), s.eth2Cl, clockwork.NewRealClock())
	return nil
}

// WaitForActivation 🕰 requires scheduler epoch events, 🎉 but can then just query validatorAPI.
func (s *BeaconNodeValidatorServer) WaitForActivation(req *prysmpb.ValidatorActivationRequest, server prysmpb.BeaconNodeValidator_WaitForActivationServer) error {
	done := make(chan struct{})
	s.subscribeEpoch(func(epoch eth2p0.Epoch) {
		vals, _ := s.eth2Cl.ValidatorsByPubKey(server.Context(), "head", toGroupPubkeys(req.PublicKeys))
		for _, val := range vals {
			if val.Status == eth2v1.ValidatorStateActiveOngoing {
				close(done)
			}
		}
	})

	select {
	case <-server.Context().Done():
		return server.Context().Err()
	case <-done:
		return nil
	}
}

// ValidatorIndex 🎉 can proxy to valiatgorAPI
func (s *BeaconNodeValidatorServer) ValidatorIndex(ctx context.Context, req *prysmpb.ValidatorIndexRequest) (*prysmpb.ValidatorIndexResponse, error) {
	resp, _ := s.valsProvider.ValidatorsByPubKey(ctx, "head", toGroupPubkeys([][]byte{req.PublicKey}))

	return &prysmpb.ValidatorIndexResponse{Index: pb.ValidatorIndex(resp[0].Index)}, nil
}

// ValidatorStatus 🎉 can proxy to valiatgorAPI, 🙈 but will not return some data either not used in prysm or just used for logging.
func (s *BeaconNodeValidatorServer) ValidatorStatus(ctx context.Context, req *prysmpb.ValidatorStatusRequest) (*prysmpb.ValidatorStatusResponse, error) {
	resp, _ := s.valsProvider.ValidatorsByPubKey(ctx, "head", toGroupPubkeys([][]byte{req.PublicKey}))
	return &prysmpb.ValidatorStatusResponse{
		Status:                    prysmpb.ValidatorStatus(resp[0].Status),
		Eth1DepositBlockNumber:    0, // TODO(corver): We do not have access to this, but it seems unused.
		DepositInclusionSlot:      0, // TODO(corver): We do not have access to this, but it seems unused.
		ActivationEpoch:           pb.Epoch(resp[0].Validator.ActivationEpoch),
		PositionInActivationQueue: 0, // TODO(corver): We do not have access to this, it is only used for logging.
	}, nil
}

// MultipleValidatorStatus 🎉 can proxy to valiatgorAPI, 🙈 but will not return some data either not used in prysm or just used for logging.
func (s *BeaconNodeValidatorServer) MultipleValidatorStatus(ctx context.Context, req *prysmpb.MultipleValidatorStatusRequest) (*prysmpb.MultipleValidatorStatusResponse, error) {
	// TODO(corver): This is same as ValidatorStatus above
	return nil, nil
}

// GetBeaconBlock 🎉 can proxy to valiatgorAPI, 🔧 but requires access to config flag BuilderAPI.
func (s *BeaconNodeValidatorServer) GetBeaconBlock(ctx context.Context, req *prysmpb.BlockRequest) (*prysmpb.GenericBeaconBlock, error) {
	var randao eth2p0.BLSSignature
	copy(randao[:], req.RandaoReveal)

	if s.builderAPI {
		block, _ := s.eth2Cl.BlindedBeaconBlockProposal(ctx, eth2p0.Slot(req.Slot), randao, req.Graffiti)
		return convertBlindedBlock(block), nil
	}

	block, _ := s.eth2Cl.BeaconBlockProposal(ctx, eth2p0.Slot(req.Slot), randao, req.Graffiti)

	return convertBlock(block), nil
}

// ProposeBeaconBlock 🎉 can proxy to valiatgorAPI, 🔧 but requires access to config flag BuilderAPI.
func (s *BeaconNodeValidatorServer) ProposeBeaconBlock(ctx context.Context, block *prysmpb.GenericSignedBeaconBlock) (*prysmpb.ProposeResponse, error) {
	var blockRoot [32]byte
	if s.builderAPI {
		var blinded *eth2api.VersionedSignedBlindedBeaconBlock
		// blinded := convert(block)
		blockRoot, _ = blinded.Root()

		_ = s.eth2Cl.SubmitBlindedBeaconBlock(ctx, blinded)
	} else {
		var bblock *spec.VersionedSignedBeaconBlock
		// bblock := convert(block)
		blockRoot, _ = bblock.Root()

		_ = s.eth2Cl.SubmitBeaconBlock(ctx, bblock)
	}

	return &prysmpb.ProposeResponse{
		BlockRoot: blockRoot[:],
	}, nil
}

// PrepareBeaconProposer 🎉 can proxy to valiatgorAPI
func (s *BeaconNodeValidatorServer) PrepareBeaconProposer(ctx context.Context, req *prysmpb.PrepareBeaconProposerRequest) (*empty.Empty, error) {
	var preps []*eth2v1.ProposalPreparation
	for _, recipient := range req.Recipients {
		var addr bellatrix.ExecutionAddress
		copy(addr[:], recipient.FeeRecipient)

		preps = append(preps, &eth2v1.ProposalPreparation{
			ValidatorIndex: eth2p0.ValidatorIndex(recipient.ValidatorIndex),
			FeeRecipient:   addr,
		})
	}

	return &empty.Empty{}, s.prepareSubmitter.SubmitProposalPreparations(ctx, preps)
}

// GetAttestationData 🎉 can proxy to valiatgorAPI
func (s *BeaconNodeValidatorServer) GetAttestationData(ctx context.Context, req *prysmpb.AttestationDataRequest) (*prysmpb.AttestationData, error) {
	data, _ := s.eth2Cl.AttestationData(ctx, eth2p0.Slot(req.Slot), eth2p0.CommitteeIndex(req.CommitteeIndex))

	return &prysmpb.AttestationData{
		Slot:            pb.Slot(data.Slot),
		CommitteeIndex:  pb.CommitteeIndex(data.Index),
		BeaconBlockRoot: data.BeaconBlockRoot[:],
		Source:          convert(data.Source).(*prysmpb.Checkpoint),
		Target:          convert(data.Target).(*prysmpb.Checkpoint),
	}, nil
}

// ProposeAttestation 🎉 can proxy to valiatgorAPI
func (s *BeaconNodeValidatorServer) ProposeAttestation(ctx context.Context, attestation *prysmpb.Attestation) (*prysmpb.AttestResponse, error) {
	att := convert(attestation).(*eth2p0.Attestation)
	root, _ := att.Data.HashTreeRoot()

	_ = s.eth2Cl.SubmitAttestations(ctx, []*eth2p0.Attestation{att})

	return &prysmpb.AttestResponse{AttestationDataRoot: root[:]}, nil
}

// SubmitAggregateSelectionProof can use integrated but probably 🆙 requires upgrade along with SubscribeCommitteeSubnets.
func (s *BeaconNodeValidatorServer) SubmitAggregateSelectionProof(ctx context.Context, req *prysmpb.AggregateSelectionRequest) (*prysmpb.AggregateSelectionResponse, error) {
	// TODO(corver): This is an interesting alternative to our v2 API change.
	//  The VC provides the partial selection proof and the BN returns the complete aggregation and proof
	//  for the VC to sign. The VC basically doesn't need to be any logic.

	// Assuming we already completed `core.DutyPrepareAggregator` for this slot.
	aggSig, _ := s.aggSigDB.Await(ctx, core.NewPrepareAggregatorDuty(int64(req.Slot)), toGroupPubkey(req.PublicKey))

	// TODO(corver): We will need to add a different API to dutyDB to query the DutyAggregator data by pubkey instead of attestation hash.
	aggAtt, _ := s.dutyDB.AwaitAggAttestation(ctx, int64(req.Slot), eth2p0.Root{} /* req.PublicKey */)

	return &prysmpb.AggregateSelectionResponse{AggregateAndProof: &prysmpb.AggregateAttestationAndProof{
		AggregatorIndex: pb.ValidatorIndex(pubkeyToValIdx(req.PublicKey)),
		Aggregate:       convert(aggAtt).(*prysmpb.Attestation),
		SelectionProof:  aggSig.Signature(),
	}}, nil
}

// SubmitSignedAggregateSelectionProof 🎉 can proxy to valiatgorAPI
func (s *BeaconNodeValidatorServer) SubmitSignedAggregateSelectionProof(ctx context.Context, req *prysmpb.SignedAggregateSubmitRequest) (*prysmpb.SignedAggregateSubmitResponse, error) {
	proof := convert(req).(*eth2p0.SignedAggregateAndProof)
	_ = s.eth2Cl.SubmitAggregateAttestations(ctx, []*eth2p0.SignedAggregateAndProof{proof})

	dataRoot, _ := proof.Message.Aggregate.Data.HashTreeRoot()

	return &prysmpb.SignedAggregateSubmitResponse{AttestationDataRoot: dataRoot[:]}, nil
}

// ProposeExit 🎉 can proxy to valiatgorAPI
func (s *BeaconNodeValidatorServer) ProposeExit(ctx context.Context, exit *prysmpb.SignedVoluntaryExit) (*prysmpb.ProposeExitResponse, error) {
	var sig eth2p0.BLSSignature
	copy(sig[:], exit.Signature)

	signedExit := &eth2p0.SignedVoluntaryExit{
		Message:   convert(exit.Exit).(*eth2p0.VoluntaryExit),
		Signature: eth2p0.BLSSignature{},
	}

	_ = s.eth2Cl.SubmitVoluntaryExit(ctx, signedExit)

	root, _ := signedExit.Message.HashTreeRoot()
	return &prysmpb.ProposeExitResponse{ExitRoot: root[:]}, nil
}

// SubscribeCommitteeSubnets 🆙 requires upgrade along with SubscribeCommitteeSubnets.
func (s *BeaconNodeValidatorServer) SubscribeCommitteeSubnets(ctx context.Context, req *prysmpb.CommitteeSubnetsSubscribeRequest) (*empty.Empty, error) {
	// TODO(corver): We need to same upgrade to the API as beaconAPI to support sync
	//  committee contributions. The VC needs to provide the partial selection proofs and we need return the aggregated proof.

	// Note that timing of these requests need to be figured out and included in the spec.

	return nil, nil
}

// CheckDoppelGanger 🙈 is assumed not required so already returns false.
func (s *BeaconNodeValidatorServer) CheckDoppelGanger(ctx context.Context, req *prysmpb.DoppelGangerRequest) (*prysmpb.DoppelGangerResponse, error) {
	// TODO(corver): We are assuming no doppelgangers are possible so always return false for all validators.
	var resps []*prysmpb.DoppelGangerResponse_ValidatorResponse
	for _, request := range req.ValidatorRequests {
		resps = append(resps, &prysmpb.DoppelGangerResponse_ValidatorResponse{
			PublicKey:       request.PublicKey,
			DuplicateExists: false,
		})
	}

	return &prysmpb.DoppelGangerResponse{
		Responses: resps,
	}, nil
}

// GetSyncMessageBlockRoot 😔 has implicit BeaconBlockRoot similar to BeaconAPI, 🎉 but otherwise can proxied to valiatgorAPI
func (s *BeaconNodeValidatorServer) GetSyncMessageBlockRoot(ctx context.Context, _ *empty.Empty) (*prysmpb.SyncMessageBlockRootResponse, error) {
	// TODO(corver): it would be great if the request included the slot and validator
	//  pubkey so we could add proper cluster wide consensus of blockroot, but alas we
	//  are stuck with the same best effort solution as beaconAPI VCs...

	// Either stick with outr best effort sync message beacon block root and just get one from the BN
	block, _ := s.blockProvider.SignedBeaconBlock(ctx, "head")
	root, _ := block.Root()

	return &prysmpb.SyncMessageBlockRootResponse{
		Root: root[:],
	}, nil
}

// SubmitSyncMessage 🎉 can proxy to valiatgorAPI
func (s *BeaconNodeValidatorServer) SubmitSyncMessage(ctx context.Context, message *prysmpb.SyncCommitteeMessage) (*empty.Empty, error) {
	var root eth2p0.Root
	copy(root[:], message.BlockRoot)
	var sig eth2p0.BLSSignature
	copy(sig[:], message.Signature)

	return nil, s.eth2Cl.SubmitSyncCommitteeMessages(ctx, []*altair.SyncCommitteeMessage{
		{
			Slot:            eth2p0.Slot(message.Slot),
			BeaconBlockRoot: root,
			ValidatorIndex:  eth2p0.ValidatorIndex(message.ValidatorIndex),
			Signature:       sig,
		},
	})
}

// GetSyncSubcommitteeIndex 🎉 can proxy to valiatgorAPI
func (s *BeaconNodeValidatorServer) GetSyncSubcommitteeIndex(ctx context.Context, req *prysmpb.SyncSubcommitteeIndexRequest) (*prysmpb.SyncSubcommitteeIndexResponse, error) {
	duties, _ := s.eth2Cl.SyncCommitteeDuties(ctx, epochFromSlot(req.Slot), []eth2p0.ValidatorIndex{pubkeyToValIdx(req.PublicKey)})

	return &prysmpb.SyncSubcommitteeIndexResponse{
		Indices: convert(duties[0].ValidatorSyncCommitteeIndices).([]pb.CommitteeIndex),
	}, nil
}

// GetSyncCommitteeContribution 🎉 can proxy to valiatgorAPI
func (s *BeaconNodeValidatorServer) GetSyncCommitteeContribution(ctx context.Context, req *prysmpb.SyncCommitteeContributionRequest) (*prysmpb.SyncCommitteeContribution, error) {
	// We have two options here:

	// Either map the slot/pubkey to a sync committee message's blockRoot and call the validatorapi
	signedData, _ := s.aggSigDB.Await(ctx, core.NewSyncMessageDuty(int64(req.Slot)), toGroupPubkey(req.PublicKey))
	root := signedData.(core.SignedSyncMessage).BeaconBlockRoot

	// Or, call dutyDB directly.

	contrib, _ := s.eth2Cl.SyncCommitteeContribution(ctx, eth2p0.Slot(req.Slot), req.SubnetId, root)

	return convert(contrib).(*prysmpb.SyncCommitteeContribution), nil
}

// SubmitSignedContributionAndProof 🆙 needs to be accompanied by similar upgrades to our proposed `BeaconAPI` changes.
func (s *BeaconNodeValidatorServer) SubmitSignedContributionAndProof(ctx context.Context, proof *prysmpb.SignedContributionAndProof) (*empty.Empty, error) {
	var sig eth2p0.BLSSignature
	copy(sig[:], proof.Signature)
	var selection eth2p0.BLSSignature
	copy(selection[:], proof.Message.SelectionProof)

	return nil, s.eth2Cl.SubmitSyncCommitteeContributions(ctx, []*altair.SignedContributionAndProof{
		{
			Message: &altair.ContributionAndProof{
				AggregatorIndex: eth2p0.ValidatorIndex(proof.Message.AggregatorIndex),
				Contribution:    convert(proof.Message.Contribution).(*altair.SyncCommitteeContribution),
				SelectionProof:  selection,
			},
			Signature: sig,
		},
	})
}

// StreamBlocksAltair 🎉 can proxy to valiatgorAPI
func (s *BeaconNodeValidatorServer) StreamBlocksAltair(req *prysmpb.StreamBlocksRequest, server prysmpb.BeaconNodeValidator_StreamBlocksAltairServer) error {
	// Only used in "attest timely"
	_ = s.eventsProvider.Events(server.Context(), []string{"block"}, func(event *eth2v1.Event) {

		// TODO(corver): The VC requests req.VerifiedOnly=true, double check that block event stream is "verified"...

		blockEvent := event.Data.(*eth2v1.BlockEvent)
		block, _ := s.blockProvider.SignedBeaconBlock(server.Context(), fmt.Sprintf("%#x", blockEvent.Block))
		_ = server.Send(&prysmpb.StreamBlocksResponse{
			Block: convert(block).(*prysmpb.StreamBlocksResponse_BellatrixBlock), /* convert block */
		})
	})

	<-server.Context().Done()

	return nil
}

// SubmitValidatorRegistrations 🎉 can proxy to valiatgorAPI
func (s *BeaconNodeValidatorServer) SubmitValidatorRegistrations(ctx context.Context, v1 *prysmpb.SignedValidatorRegistrationsV1) (*empty.Empty, error) {
	// Convert and call
	_ = s.eth2Cl.SubmitValidatorRegistrations(ctx, []*eth2api.VersionedSignedValidatorRegistration{})

	return &empty.Empty{}, nil
}

func (s *BeaconNodeValidatorServer) subscribeEpoch(fn func(epoch eth2p0.Epoch)) func() {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := rand.Int63()
	s.streams[id] = fn

	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()

		delete(s.streams, id)
	}
}

// getDuties returns all duties for the given epoch and validator set.
func (s *BeaconNodeValidatorServer) getDuties(ctx context.Context, epoch eth2p0.Epoch,
	pubkeys []eth2p0.BLSPubKey,
) []*prysmpb.DutiesResponse_Duty {
	var valIdxs []eth2p0.ValidatorIndex
	var duties map[eth2p0.ValidatorIndex]*prysmpb.DutiesResponse_Duty
	var slot eth2p0.Slot
	// slot := startOfEpoch(req.Epoch)

	vals, _ := s.valsProvider.ValidatorsByPubKey(ctx, fmt.Sprint(slot), pubkeys)
	for _, val := range vals {
		valIdxs = append(valIdxs, val.Index)
		duties[val.Index] = &prysmpb.DutiesResponse_Duty{
			PublicKey:      toPubShare(val.Validator.PublicKey),
			Status:         prysmpb.ValidatorStatus(val.Status),
			ValidatorIndex: pb.ValidatorIndex(val.Index),
		}
	}

	attDuties, _ := s.attDutiesProvider.AttesterDuties(ctx, epoch, valIdxs)
	for _, attDuty := range attDuties {
		duties[attDuty.ValidatorIndex].AttesterSlot = pb.Slot(attDuty.Slot)
		duties[attDuty.ValidatorIndex].CommitteeIndex = pb.CommitteeIndex(attDuty.CommitteeIndex)
		duties[attDuty.ValidatorIndex].Committee = nil // TODO(corver): Query GET /eth/v1/beacon/states/{state_id}/committees to get committee members
	}

	propDuties, _ := s.propDutiesProvider.ProposerDuties(ctx, epoch, valIdxs)
	for _, propDuty := range propDuties {
		duties[propDuty.ValidatorIndex].ProposerSlots = append(duties[propDuty.ValidatorIndex].ProposerSlots, pb.Slot(propDuty.Slot))
	}

	syncDuties, _ := s.syncDutiesProvider.SyncCommitteeDuties(ctx, epoch, valIdxs)
	for _, syncDuty := range syncDuties {
		duties[syncDuty.ValidatorIndex].IsSyncCommittee = len(syncDuty.ValidatorSyncCommitteeIndices) > 0
	}

	// TODO(corver): Do the same for the next epoch.

	var resp []*prysmpb.DutiesResponse_Duty
	for _, duty := range duties {
		resp = append(resp, duty)
	}

	return resp
}

func toGroupPubkey(pubkeys []byte) core.PubKey {
	// TODO(corver): Convert pubkeys into core type and map to group pubkey.
	return ""
}

func toGroupPubkeys(pubkeys [][]byte) []eth2p0.BLSPubKey {
	// TODO(corver): Convert pubkeys into eth2 type and map to group pubkey.
	return nil
}

func toPubShare(key eth2p0.BLSPubKey) []byte {
	// TODO(corver): Map to group pubkey to pubshare and convert to bytes.
	return nil
}

func convertBlock(block *spec.VersionedBeaconBlock) *prysmpb.GenericBeaconBlock {
	bellatrix := &prysmpb.BeaconBlockBellatrix{
		Slot:          pb.Slot(block.Bellatrix.Slot),
		ProposerIndex: pb.ValidatorIndex(block.Bellatrix.ProposerIndex),
		ParentRoot:    block.Bellatrix.ParentRoot[:],
		StateRoot:     block.Bellatrix.StateRoot[:],
		Body:          nil, // TODO(corver): Convert body,
	}

	return &prysmpb.GenericBeaconBlock{Block: &prysmpb.GenericBeaconBlock_Bellatrix{Bellatrix: bellatrix}}
}

func convertBlindedBlock(block *eth2api.VersionedBlindedBeaconBlock) *prysmpb.GenericBeaconBlock {
	bellatrix := &prysmpb.BlindedBeaconBlockBellatrix{
		Slot:          pb.Slot(block.Bellatrix.Slot),
		ProposerIndex: pb.ValidatorIndex(block.Bellatrix.ProposerIndex),
		ParentRoot:    block.Bellatrix.ParentRoot[:],
		StateRoot:     block.Bellatrix.StateRoot[:],
		Body:          nil, // TODO(corver): Convert body,
	}

	return &prysmpb.GenericBeaconBlock{Block: &prysmpb.GenericBeaconBlock_BlindedBellatrix{BlindedBellatrix: bellatrix}}
}

func convert(interface{}) interface{} { return nil }

func epochFromSlot(slot pb.Slot) eth2p0.Epoch {
	return 0
}

func pubkeyToValIdx([]byte) eth2p0.ValidatorIndex {
	return 0
}
