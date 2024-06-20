// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package validatormock provides mock validator client functionality.
package validatormock

import (
	"context"
	"encoding/hex"
	"strings"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2bellatrix "github.com/attestantio/go-eth2-client/api/v1/bellatrix"
	eth2capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	eth2deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/signing"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

// SignFunc abstract signing done by the validator client.
type SignFunc func(pubshare eth2p0.BLSPubKey, data []byte) (eth2p0.BLSSignature, error)

// ProposeBlock proposes block for the given slot.
func ProposeBlock(ctx context.Context, eth2Cl eth2wrap.Client, signFunc SignFunc,
	slot eth2p0.Slot,
) error {
	valMap, err := eth2Cl.ActiveValidators(ctx)
	if err != nil {
		return err
	}

	slotsPerEpoch, err := eth2Cl.SlotsPerEpoch(ctx)
	if err != nil {
		return err
	}
	epoch := eth2p0.Epoch(uint64(slot) / slotsPerEpoch)

	var indexes []eth2p0.ValidatorIndex
	for index := range valMap {
		indexes = append(indexes, index)
	}

	opts := &eth2api.ProposerDutiesOpts{
		Epoch:   epoch,
		Indices: indexes,
	}
	eth2Resp, err := eth2Cl.ProposerDuties(ctx, opts)
	if err != nil {
		return err
	}
	duties := eth2Resp.Data

	var slotProposer *eth2v1.ProposerDuty
	for _, duty := range duties {
		if duty.Slot == slot {
			slotProposer = duty
			break
		}
	}

	if slotProposer == nil {
		return nil
	}

	var (
		pubkey eth2p0.BLSPubKey
		block  *eth2api.VersionedProposal
	)
	pubkey = slotProposer.PubKey

	// Create randao reveal to propose block
	randaoSigRoot, err := eth2util.SignedEpoch{Epoch: epoch}.HashTreeRoot()
	if err != nil {
		return err
	}

	randaoSigData, err := signing.GetDataRoot(ctx, eth2Cl, signing.DomainRandao, epoch, randaoSigRoot)
	if err != nil {
		return err
	}

	randao, err := signFunc(slotProposer.PubKey, randaoSigData[:])
	if err != nil {
		return err
	}

	// Get Unsigned beacon block with given randao and slot
	proposalOpts := &eth2api.ProposalOpts{
		Slot:         slot,
		RandaoReveal: randao,
	}
	eth2ProposalResp, err := eth2Cl.Proposal(ctx, proposalOpts)
	if err != nil {
		return errors.Wrap(err, "vmock beacon block proposal")
	}
	block = eth2ProposalResp.Data

	if block == nil {
		return errors.New("block not found")
	}

	// Sign beacon block
	blockSigRoot, err := block.Root()
	if err != nil {
		return err
	}

	blockSigData, err := signing.GetDataRoot(ctx, eth2Cl, signing.DomainBeaconProposer, epoch, blockSigRoot)
	if err != nil {
		return err
	}

	sig, err := signFunc(pubkey, blockSigData[:])
	if err != nil {
		return err
	}

	if block.Blinded {
		signedBlock := new(eth2api.VersionedSignedBlindedProposal)
		signedBlock.Version = block.Version
		switch block.Version {
		case eth2spec.DataVersionBellatrix:
			signedBlock.Bellatrix = &eth2bellatrix.SignedBlindedBeaconBlock{
				Message:   block.BellatrixBlinded,
				Signature: sig,
			}
		case eth2spec.DataVersionCapella:
			signedBlock.Capella = &eth2capella.SignedBlindedBeaconBlock{
				Message:   block.CapellaBlinded,
				Signature: sig,
			}
		case eth2spec.DataVersionDeneb:
			signedBlock.Deneb = &eth2deneb.SignedBlindedBeaconBlock{
				Message:   block.DenebBlinded,
				Signature: sig,
			}
		default:
			return errors.New("invalid blinded block")
		}

		return eth2Cl.SubmitBlindedProposal(ctx, &eth2api.SubmitBlindedProposalOpts{
			Proposal: signedBlock,
		})
	}

	// Full block
	signedBlock := new(eth2api.VersionedSignedProposal)
	signedBlock.Version = block.Version
	switch block.Version {
	case eth2spec.DataVersionPhase0:
		signedBlock.Phase0 = &eth2p0.SignedBeaconBlock{
			Message:   block.Phase0,
			Signature: sig,
		}
	case eth2spec.DataVersionAltair:
		signedBlock.Altair = &altair.SignedBeaconBlock{
			Message:   block.Altair,
			Signature: sig,
		}
	case eth2spec.DataVersionBellatrix:
		signedBlock.Bellatrix = &bellatrix.SignedBeaconBlock{
			Message:   block.Bellatrix,
			Signature: sig,
		}
	case eth2spec.DataVersionCapella:
		signedBlock.Capella = &capella.SignedBeaconBlock{
			Message:   block.Capella,
			Signature: sig,
		}
	case eth2spec.DataVersionDeneb:
		signedBlock.Deneb = &eth2deneb.SignedBlockContents{
			SignedBlock: &deneb.SignedBeaconBlock{
				Message:   block.Deneb.Block,
				Signature: sig,
			},
			KZGProofs: block.Deneb.KZGProofs,
			Blobs:     block.Deneb.Blobs,
		}
	default:
		return errors.New("invalid block")
	}

	return eth2Cl.SubmitProposal(ctx, &eth2api.SubmitProposalOpts{Proposal: signedBlock})
}

// RegistrationsFromProposerConfig returns all enabled builder-API registrations from upstream proposer config.
func RegistrationsFromProposerConfig(ctx context.Context, eth2Cl eth2wrap.Client) (map[eth2p0.BLSPubKey]*eth2api.VersionedValidatorRegistration, error) {
	confs, err := eth2Cl.ProposerConfig(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "get proposer config")
	}

	resp := make(map[eth2p0.BLSPubKey]*eth2api.VersionedValidatorRegistration)
	for pubshare, conf := range confs.Proposers {
		if !conf.Builder.Enabled {
			continue
		}

		ts, ok, err := conf.Builder.TimestampOverride()
		if err != nil {
			return nil, errors.Wrap(err, "get builder timestamp override")
		} else if !ok {
			return nil, errors.Wrap(err, "no builder timestamp override")
		}

		pubkey, ok, err := conf.Builder.PublicKeyOverride()
		if err != nil {
			return nil, errors.Wrap(err, "get builder public key override")
		} else if !ok {
			return nil, errors.Wrap(err, "no builder public key override")
		}

		if conf.Builder.GasLimit == 0 {
			return nil, errors.New("invalid builder gas limit")
		}

		feeRecipientBytes, err := hex.DecodeString(strings.TrimPrefix(conf.FeeRecipient, "0x"))
		if err != nil {
			return nil, errors.Wrap(err, "decode fee recipient")
		} else if len(feeRecipientBytes) != 20 {
			return nil, errors.New("invalid fee recipient")
		}

		resp[pubshare] = &eth2api.VersionedValidatorRegistration{
			Version: eth2spec.BuilderVersionV1,
			V1: &eth2v1.ValidatorRegistration{
				FeeRecipient: bellatrix.ExecutionAddress(feeRecipientBytes),
				GasLimit:     uint64(conf.Builder.GasLimit),
				Timestamp:    ts,
				Pubkey:       pubkey,
			},
		}
	}

	return resp, nil
}

// Register signs and submits the validator builder registration to the validator API.
func Register(ctx context.Context, eth2Cl eth2wrap.Client, signFunc SignFunc,
	registration *eth2api.VersionedValidatorRegistration, pubshare eth2p0.BLSPubKey,
) error {
	sigRoot, err := registration.Root()
	if err != nil {
		return err
	}

	// Always use epoch 0 for DomainApplicationBuilder
	sigData, err := signing.GetDataRoot(ctx, eth2Cl, signing.DomainApplicationBuilder, 0, sigRoot)
	if err != nil {
		return err
	}

	sig, err := signFunc(pubshare, sigData[:])
	if err != nil {
		return err
	}

	// create signed builder registration
	signedRegistration := new(eth2api.VersionedSignedValidatorRegistration)
	switch signedRegistration.Version {
	case eth2spec.BuilderVersionV1:
		signedRegistration.V1 = &eth2v1.SignedValidatorRegistration{
			Message:   registration.V1,
			Signature: sig,
		}
	default:
		return errors.New("invalid registration")
	}

	return eth2Cl.SubmitValidatorRegistrations(ctx, []*eth2api.VersionedSignedValidatorRegistration{signedRegistration})
}

// NewSigner returns a signing function supporting the provided private keys.
func NewSigner(secrets ...tbls.PrivateKey) (SignFunc, error) {
	secretByPubkey := make(map[eth2p0.BLSPubKey]tbls.PrivateKey)
	for _, secret := range secrets {
		pk, err := tbls.SecretToPublicKey(secret)
		if err != nil {
			return nil, errors.Wrap(err, "get pubkey")
		}

		eth2Pubkey, err := tblsconv.PubkeyToETH2(pk)
		if err != nil {
			return nil, err
		}

		secretByPubkey[eth2Pubkey] = secret
	}

	return func(pubkey eth2p0.BLSPubKey, msg []byte) (eth2p0.BLSSignature, error) {
		secret, ok := secretByPubkey[pubkey]
		if !ok {
			return eth2p0.BLSSignature{}, errors.New("secret not found")
		}

		sig, err := tbls.Sign(secret, msg)
		if err != nil {
			return eth2p0.BLSSignature{}, err
		}

		return tblsconv.SigToETH2(sig), nil
	}, nil
}
