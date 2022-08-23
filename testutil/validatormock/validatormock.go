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
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/prysmaticlabs/go-bitfield"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/signing"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

// SignFunc abstract signing done by the validator client.
type SignFunc func(pubshare eth2p0.BLSPubKey, data []byte) (eth2p0.BLSSignature, error)

// Attest performs attestation duties for the provided slot and pubkeys (validators).
func Attest(ctx context.Context, eth2Cl eth2wrap.Client, signFunc SignFunc,
	slot eth2p0.Slot, pubkeys ...eth2p0.BLSPubKey,
) error {
	slotsPerEpoch, err := eth2Cl.SlotsPerEpoch(ctx)
	if err != nil {
		return err
	}

	epoch := eth2p0.Epoch(uint64(slot) / slotsPerEpoch)

	valMap, err := eth2Cl.ValidatorsByPubKey(ctx, "head", pubkeys) // Using head to mitigate future slot issues.
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

		root, err := data.HashTreeRoot()
		if err != nil {
			return errors.Wrap(err, "hash attestation")
		}

		sigData, err := signing.GetDataRoot(ctx, eth2Cl, signing.DomainBeaconAttester, data.Target.Epoch, root)
		if err != nil {
			return err
		}

		sig, err := signFunc(duty.PubKey, sigData[:])
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
func ProposeBlock(ctx context.Context, eth2Cl eth2wrap.Client, signFunc SignFunc,
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
		sigRoot, err := eth2util.EpochHashRoot(epoch)
		if err != nil {
			return err
		}

		sigData, err := signing.GetDataRoot(ctx, eth2Cl, signing.DomainRandao, epoch, sigRoot)
		if err != nil {
			return err
		}

		randao, err := signFunc(duty.PubKey, sigData[:])
		if err != nil {
			return err
		}

		// Get Unsigned beacon block with given randao and slot
		block, err = beaconBlockProposal(ctx, slot, randao, nil, eth2Cl.Address())
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

	sigData, err := signing.GetDataRoot(ctx, eth2Cl, signing.DomainBeaconProposer, epoch, sigRoot)
	if err != nil {
		return err
	}

	sig, err := signFunc(pubkey, sigData[:])
	if err != nil {
		return err
	}

	// create signed beacon block
	signedBlock := new(spec.VersionedSignedBeaconBlock)
	signedBlock.Version = block.Version
	switch block.Version {
	case spec.DataVersionPhase0:
		signedBlock.Phase0 = &eth2p0.SignedBeaconBlock{
			Message:   block.Phase0,
			Signature: sig,
		}
	case spec.DataVersionAltair:
		signedBlock.Altair = &altair.SignedBeaconBlock{
			Message:   block.Altair,
			Signature: sig,
		}
	case spec.DataVersionBellatrix:
		signedBlock.Bellatrix = &bellatrix.SignedBeaconBlock{
			Message:   block.Bellatrix,
			Signature: sig,
		}
	default:
		return errors.New("invalid block")
	}

	return eth2Cl.SubmitBeaconBlock(ctx, signedBlock)
}

// ProposeBlindedBlock proposes blinded block for the given slot.
func ProposeBlindedBlock(ctx context.Context, eth2Cl eth2wrap.Client, signFunc SignFunc,
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

	duties, err := eth2Cl.ProposerDuties(ctx, epoch, indexes)
	if err != nil {
		return err
	}

	var pubkey eth2p0.BLSPubKey
	var block *eth2api.VersionedBlindedBeaconBlock
	for _, duty := range duties {
		if duty.Slot != slot {
			continue
		}
		pubkey = duty.PubKey

		// create randao reveal to propose block
		sigRoot, err := eth2util.EpochHashRoot(epoch)
		if err != nil {
			return err
		}

		sigData, err := signing.GetDataRoot(ctx, eth2Cl, signing.DomainRandao, epoch, sigRoot)
		if err != nil {
			return err
		}

		randao, err := signFunc(duty.PubKey, sigData[:])
		if err != nil {
			return err
		}

		// Get Unsigned beacon block with given randao and slot
		block, err = blindedBeaconBlockProposal(ctx, slot, randao, nil, eth2Cl.Address())
		if err != nil {
			return errors.Wrap(err, "vmock blinded beacon block proposal")
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

	// TODO(corver): Create a function similar to `signing.VerifySignedData`
	//  called `signing.UnsignedRoot(ctx, eth2Cl, core.UnsignedData)`
	sigData, err := signing.GetDataRoot(ctx, eth2Cl, signing.DomainBeaconProposer, epoch, sigRoot)
	if err != nil {
		return err
	}

	sig, err := signFunc(pubkey, sigData[:])
	if err != nil {
		return err
	}

	// create signed beacon block
	signedBlock := new(eth2api.VersionedSignedBlindedBeaconBlock)
	signedBlock.Version = block.Version
	switch block.Version {
	case spec.DataVersionBellatrix:
		signedBlock.Bellatrix = &eth2v1.SignedBlindedBeaconBlock{
			Message:   block.Bellatrix,
			Signature: sig,
		}
	default:
		return errors.New("invalid block")
	}

	return eth2Cl.SubmitBlindedBeaconBlock(ctx, signedBlock)
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
	case spec.BuilderVersionV1:
		signedRegistration.V1 = &eth2v1.SignedValidatorRegistration{
			Message:   registration.V1,
			Signature: sig,
		}
	default:
		return errors.New("invalid registration")
	}

	return eth2Cl.SubmitValidatorRegistrations(ctx, []*eth2api.VersionedSignedValidatorRegistration{signedRegistration})
}

// NewSigner returns a singing function supporting the provided private keys.
func NewSigner(secrets ...*bls_sig.SecretKey) SignFunc {
	return func(pubkey eth2p0.BLSPubKey, msg []byte) (eth2p0.BLSSignature, error) {
		secret, err := getSecret(secrets, pubkey)
		if err != nil {
			return eth2p0.BLSSignature{}, err
		}

		sig, err := tbls.Sign(secret, msg)
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

// versionJSON extracts the version from a response.
type versionJSON struct {
	Version spec.DataVersion `json:"version"`
}

type phase0BlockJSON struct {
	Data *eth2p0.BeaconBlock `json:"data"`
}

type altairBlockJSON struct {
	Data *altair.BeaconBlock `json:"data"`
}

type bellatrixBlockJSON struct {
	Data *bellatrix.BeaconBlock `json:"data"`
}

// beaconBlockProposal is used rather than go-eth2-client's BeaconBlockProposal to avoid the randao reveal check
// refer: https://github.com/attestantio/go-eth2-client/blob/906db73739859de06f46dfa91384675ed9300af0/http/beaconblockproposal.go#L87
func beaconBlockProposal(_ context.Context, slot eth2p0.Slot, randaoReveal eth2p0.BLSSignature,
	graffiti []byte, addr string,
) (*spec.VersionedBeaconBlock, error) {
	endpoint := fmt.Sprintf("/eth/v2/validator/blocks/%d?randao_reveal=%#x&graffiti=%#x",
		slot, randaoReveal, graffiti)
	body, err := httpGet(addr, endpoint)
	if err != nil {
		return nil, errors.Wrap(err, "failed to request beacon block proposal")
	}

	var version versionJSON
	if err := json.Unmarshal(body, &version); err != nil {
		return nil, errors.Wrap(err, "failed to parse version")
	}
	res := &spec.VersionedBeaconBlock{
		Version: version.Version,
	}

	switch version.Version {
	case spec.DataVersionPhase0:
		var resp phase0BlockJSON
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, errors.Wrap(err, "failed to parse phase 0 beacon block proposal")
		}
		// Ensure the data returned to us is as expected given our input.
		if resp.Data.Slot != slot {
			return nil, errors.New("beacon block proposal not for requested slot")
		}
		res.Phase0 = resp.Data
	case spec.DataVersionAltair:
		var resp altairBlockJSON
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, errors.Wrap(err, "failed to parse altair beacon block proposal")
		}
		// Ensure the data returned to us is as expected given our input.
		if resp.Data.Slot != slot {
			return nil, errors.New("beacon block proposal not for requested slot")
		}
		res.Altair = resp.Data
	case spec.DataVersionBellatrix:
		var resp bellatrixBlockJSON
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, errors.Wrap(err, "failed to parse bellatrix beacon block proposal")
		}
		// Ensure the data returned to us is as expected given our input.
		if resp.Data.Slot != slot {
			return nil, errors.New("beacon block proposal not for requested slot")
		}
		res.Bellatrix = resp.Data
	default:
		return nil, errors.New("unsupported block version", z.Any("version", version.Version))
	}

	return res, nil
}

type bellatrixBlindedBlockJSON struct {
	Data *eth2v1.BlindedBeaconBlock `json:"data"`
}

// blindedBeaconBlockProposal is used rather than go-eth2-client's BlindedBeaconBlockProposal to avoid the randao reveal check
// refer: https://github.com/attestantio/go-eth2-client/blob/dceb0b761e5ea6a75534a7b11d544d91a5d610ee/http/blindedbeaconblockproposal.go#L75
func blindedBeaconBlockProposal(_ context.Context, slot eth2p0.Slot, randaoReveal eth2p0.BLSSignature,
	graffiti []byte, addr string,
) (*eth2api.VersionedBlindedBeaconBlock, error) {
	endpoint := fmt.Sprintf("/eth/v1/validator/blinded_blocks/%d?randao_reveal=%#x&graffiti=%#x",
		slot, randaoReveal, graffiti)
	body, err := httpGet(addr, endpoint)
	if err != nil {
		return nil, errors.Wrap(err, "failed to request beacon block proposal")
	}

	var version versionJSON
	if err := json.Unmarshal(body, &version); err != nil {
		return nil, errors.Wrap(err, "failed to parse version")
	}
	res := &eth2api.VersionedBlindedBeaconBlock{
		Version: version.Version,
	}

	switch version.Version {
	case spec.DataVersionBellatrix:
		var resp bellatrixBlindedBlockJSON
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, errors.Wrap(err, "failed to parse bellatrix beacon block proposal")
		}
		// Ensure the data returned to us is as expected given our input.
		if resp.Data.Slot != slot {
			return nil, errors.New("beacon block proposal not for requested slot")
		}
		res.Bellatrix = resp.Data
	default:
		return nil, errors.New("unsupported block version", z.Any("version", version.Version))
	}

	return res, nil
}

func httpGet(base string, endpoint string) ([]byte, error) {
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

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read GET response")
	}

	if res.StatusCode/100 != 2 {
		return nil, errors.New("get failed", z.Int("status", res.StatusCode), z.Str("body", string(body)))
	}

	return body, nil
}
