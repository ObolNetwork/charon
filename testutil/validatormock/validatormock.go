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

// Package validatormock provides mock validator client functionality.
package validatormock

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/prysmaticlabs/go-bitfield"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core/validatorapi"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

// Eth2Provider defines the eth2 beacon api providers required to perform attestations.
type Eth2Provider interface {
	eth2client.AttestationDataProvider
	eth2client.AttestationsSubmitter
	eth2client.AttesterDutiesProvider
	eth2client.BeaconBlockProposalProvider
	eth2client.BeaconBlockSubmitter
	eth2client.DomainProvider
	eth2client.ProposerDutiesProvider
	eth2client.SlotsPerEpochProvider
	eth2client.SpecProvider
	eth2client.ValidatorsProvider
	// Above sorted alphabetically.
}

// SignFunc abstract signing done by the validator client.
type SignFunc func(context.Context, eth2p0.BLSPubKey, eth2p0.SigningData) (eth2p0.BLSSignature, error)

// Attest performs attestation duties for the provided slot and pubkeys (validators).
func Attest(ctx context.Context, eth2Cl Eth2Provider, signFunc SignFunc,
	slot eth2p0.Slot, pubkeys ...eth2p0.BLSPubKey,
) error {
	slotsPerEpoch, err := eth2Cl.SlotsPerEpoch(ctx)
	if err != nil {
		return err
	}

	epoch := eth2p0.Epoch(uint64(slot) / slotsPerEpoch)

	valMap, err := eth2Cl.ValidatorsByPubKey(ctx, fmt.Sprint(slot), pubkeys)
	if err != nil {
		return err
	}

	var indexes []eth2p0.ValidatorIndex
	for index, val := range valMap {
		if !val.Status.IsActive() {
			continue
		}
		indexes = append(indexes, index)
	}

	duties, err := eth2Cl.AttesterDuties(ctx, epoch, indexes)
	if err != nil {
		return err
	}

	var atts []*eth2p0.Attestation
	for _, duty := range duties {
		if duty.Slot != slot {
			continue
		}

		data, err := eth2Cl.AttestationData(ctx, duty.Slot, duty.CommitteeIndex)
		if err != nil {
			return err
		}

		domain, err := validatorapi.GetDomain(ctx, eth2Cl, validatorapi.DomainBeaconAttester, data.Target.Epoch)
		if err != nil {
			return err
		}

		root, err := data.HashTreeRoot()
		if err != nil {
			return errors.Wrap(err, "hash attestation")
		}

		sig, err := signFunc(ctx, duty.PubKey, eth2p0.SigningData{
			ObjectRoot: root,
			Domain:     domain,
		})
		if err != nil {
			return err
		}

		aggBits := bitfield.NewBitlist(duty.CommitteeLength)
		aggBits.SetBitAt(duty.ValidatorCommitteeIndex, true)

		atts = append(atts, &eth2p0.Attestation{
			AggregationBits: aggBits,
			Data:            data,
			Signature:       sig,
		})
	}

	return eth2Cl.SubmitAttestations(ctx, atts)
}

// ProposeBlock proposes block for the given slot.

func ProposeBlock(ctx context.Context, eth2Cl Eth2Provider, signFunc SignFunc, slot eth2p0.Slot, addr string, pubkeys ...eth2p0.BLSPubKey) error {
	slotsPerEpoch, err := eth2Cl.SlotsPerEpoch(ctx)
	if err != nil {
		return err
	}

	epoch := eth2p0.Epoch(uint64(slot) / slotsPerEpoch)

	valMap, err := eth2Cl.ValidatorsByPubKey(ctx, fmt.Sprint(slot), pubkeys)
	if err != nil {
		return err
	}

	var indexes []eth2p0.ValidatorIndex
	for index, val := range valMap {
		if !val.Status.IsActive() {
			continue
		}
		indexes = append(indexes, index)
	}

	duties, err := eth2Cl.ProposerDuties(ctx, epoch, indexes)
	if err != nil {
		return err
	}

	var pubkey eth2p0.BLSPubKey
	var block *spec.VersionedBeaconBlock
	for _, duty := range duties {
		if duty.Slot != slot {
			continue
		}
		pubkey = duty.PubKey

		// create randao reveal to propose block
		sigRoot, err := validatorapi.MerkleEpoch(epoch).HashTreeRoot()
		if err != nil {
			return err
		}

		domain, err := validatorapi.GetDomain(ctx, eth2Cl, validatorapi.DomainRandao, epoch)
		if err != nil {
			return err
		}

		msg := eth2p0.SigningData{
			ObjectRoot: sigRoot,
			Domain:     domain,
		}
		randao, err := signFunc(ctx, duty.PubKey, msg)
		if err != nil {
			return err
		}

		// Get Unsigned beacon block with given randao and slot
		if addr == "" {
			// For testing purposes assuming beaconmock is used in place of validatorapi
			block, err = eth2Cl.BeaconBlockProposal(ctx, slot, randao, nil)
		} else {
			block, err = beaconBlockProposal(ctx, slot, randao, nil, addr)
		}
		if err != nil {
			return errors.Wrap(err, "vmock beacon block proposal")
		}

		// since there would be only one proposer duty per slot
		break
	}

	if block == nil {
		return errors.New("block not found")
	}

	// Sign beacon block
	sigRoot, err := block.Root()
	if err != nil {
		return err
	}

	domain, err := validatorapi.GetDomain(ctx, eth2Cl, validatorapi.DomainBeaconProposer, epoch)
	if err != nil {
		return err
	}

	sig, err := signFunc(ctx, pubkey, eth2p0.SigningData{
		ObjectRoot: sigRoot,
		Domain:     domain,
	})
	if err != nil {
		return err
	}

	// create signed beacon block
	signedBlock := new(spec.VersionedSignedBeaconBlock)
	signedBlock.Version = block.Version
	switch block.Version {
	case spec.DataVersionPhase0:
		signedBlock.Phase0 = new(eth2p0.SignedBeaconBlock)
		signedBlock.Phase0.Message = block.Phase0
		signedBlock.Phase0.Signature = sig
	case spec.DataVersionAltair:
		signedBlock.Altair = new(altair.SignedBeaconBlock)
		signedBlock.Altair.Message = block.Altair
		signedBlock.Altair.Signature = sig
	case spec.DataVersionBellatrix:
		signedBlock.Bellatrix = new(bellatrix.SignedBeaconBlock)
		signedBlock.Bellatrix.Message = block.Bellatrix
		signedBlock.Bellatrix.Signature = sig
	default:
		return errors.New("invalid block")
	}

	return eth2Cl.SubmitBeaconBlock(ctx, signedBlock)
}

// NewSigner returns a singing function supporting the provided private keys.
func NewSigner(secrets ...*bls_sig.SecretKey) SignFunc {
	return func(ctx context.Context, pubkey eth2p0.BLSPubKey, data eth2p0.SigningData) (eth2p0.BLSSignature, error) {
		secret, err := getSecret(secrets, pubkey)
		if err != nil {
			return eth2p0.BLSSignature{}, err
		}

		msg, err := data.HashTreeRoot()
		if err != nil {
			return eth2p0.BLSSignature{}, errors.Wrap(err, "marshal signing data")
		}

		sig, err := tbls.Sign(secret, msg[:])
		if err != nil {
			return eth2p0.BLSSignature{}, err
		}

		return tblsconv.SigToETH2(sig), nil
	}
}

func getSecret(secrets []*bls_sig.SecretKey, pubkey eth2p0.BLSPubKey) (*bls_sig.SecretKey, error) {
	for _, secret := range secrets {
		pk, err := secret.GetPublicKey()
		if err != nil {
			return nil, errors.Wrap(err, "get pubkey")
		}

		eth2Pubkey, err := tblsconv.KeyToETH2(pk)
		if err != nil {
			return nil, err
		}

		if eth2Pubkey == pubkey {
			return secret, nil
		}
	}

	return nil, errors.New("private key not found")
}

// responseMetadata returns metadata related to responses.
type responseMetadata struct {
	Version spec.DataVersion `json:"version"`
}

type phase0BeaconBlockProposalJSON struct {
	Data *eth2p0.BeaconBlock `json:"data"`
}

type altairBeaconBlockProposalJSON struct {
	Data *altair.BeaconBlock `json:"data"`
}

type bellatrixBeaconBlockProposalJSON struct {
	Data *bellatrix.BeaconBlock `json:"data"`
}

func beaconBlockProposal(_ context.Context, slot eth2p0.Slot, randaoReveal eth2p0.BLSSignature, graffiti []byte, addr string) (*spec.VersionedBeaconBlock, error) {
	url := fmt.Sprintf("/eth/v2/validator/blocks/%d?randao_reveal=%#x&graffiti=%#x", slot, randaoReveal, graffiti)
	respBodyReader, err := getBlock(url, addr)
	if err != nil {
		return nil, errors.Wrap(err, "failed to request beacon block proposal")
	}
	if respBodyReader == nil {
		return nil, errors.New("failed to obtain beacon block proposal")
	}

	var dataBodyReader bytes.Buffer
	metadataReader := io.TeeReader(respBodyReader, &dataBodyReader)
	var metadata responseMetadata
	if err := json.NewDecoder(metadataReader).Decode(&metadata); err != nil {
		return nil, errors.Wrap(err, "failed to parse response")
	}
	res := &spec.VersionedBeaconBlock{
		Version: metadata.Version,
	}

	switch metadata.Version {
	case spec.DataVersionPhase0:
		var resp phase0BeaconBlockProposalJSON
		if err := json.NewDecoder(&dataBodyReader).Decode(&resp); err != nil {
			return nil, errors.Wrap(err, "failed to parse phase 0 beacon block proposal")
		}
		// Ensure the data returned to us is as expected given our input.
		if resp.Data.Slot != slot {
			return nil, errors.New("beacon block proposal not for requested slot")
		}
		res.Phase0 = resp.Data
	case spec.DataVersionAltair:
		var resp altairBeaconBlockProposalJSON
		if err := json.NewDecoder(&dataBodyReader).Decode(&resp); err != nil {
			return nil, errors.Wrap(err, "failed to parse altair beacon block proposal")
		}
		// Ensure the data returned to us is as expected given our input.
		if resp.Data.Slot != slot {
			return nil, errors.New("beacon block proposal not for requested slot")
		}
		res.Altair = resp.Data
	case spec.DataVersionBellatrix:
		var resp bellatrixBeaconBlockProposalJSON
		if err := json.NewDecoder(&dataBodyReader).Decode(&resp); err != nil {
			return nil, errors.Wrap(err, "failed to parse bellatrix beacon block proposal")
		}
		// Ensure the data returned to us is as expected given our input.
		if resp.Data.Slot != slot {
			return nil, errors.New("beacon block proposal not for requested slot")
		}
		res.Bellatrix = resp.Data
	default:
		return nil, errors.New("unsupported block version", z.Any("version", metadata.Version))
	}

	return res, nil
}

func getBlock(endpoint string, base string) (io.Reader, error) {
	url, err := url.Parse(fmt.Sprintf("%s%s", strings.TrimSuffix(base, "/"), endpoint))
	if err != nil {
		return nil, errors.Wrap(err, "invalid endpoint")
	}
	res, err := http.Get(url.String())
	if err != nil {
		return nil, errors.Wrap(err, "http get")
	}

	if res.StatusCode == 404 {
		// Nothing found.  This is not an error, so we return nil on both counts.
		return nil, nil
	}

	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read GET response")
	}

	statusFamily := res.StatusCode / 100
	if statusFamily != 2 {
		return nil, errors.New("GET failed", z.Int("status", res.StatusCode), z.Str("data", string(data)))
	}

	return bytes.NewReader(data), nil
}
