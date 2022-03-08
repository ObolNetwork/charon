// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package validatorapi

import (
	"context"
	"fmt"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	bls12381 "github.com/dB2510/kryptology/pkg/core/curves/native/bls12-381"
	"github.com/dB2510/kryptology/pkg/signatures/bls/bls_sig"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/tbls"
)

type eth2Provider interface {
	Eth2DomainProvider
	eth2client.SlotsPerEpochProvider
}

// PubShareFunc abstracts the mapping of validator root public key to tbls public share.
type PubShareFunc func(pubkey core.PubKey, index int) (*bls_sig.PublicKey, error)

// NewComponentInsecure returns a new instance of the validator API core workflow component
// that does not perform signature verification.
func NewComponentInsecure(eth2Svc eth2client.Service, index int) (*Component, error) {
	eth2Cl, ok := eth2Svc.(eth2Provider)
	if !ok {
		return nil, errors.New("invalid eth2 service")
	}

	return &Component{
		skipVerify: true,
		eth2Cl:     eth2Cl,
		index:      index,
	}, nil
}

// NewComponent returns a new instance of the validator API core workflow component.
func NewComponent(eth2Svc eth2client.Service, pubShareFunc PubShareFunc, index int) (*Component, error) {
	eth2Cl, ok := eth2Svc.(eth2Provider)
	if !ok {
		return nil, errors.New("invalid eth2 service")
	}

	return &Component{
		pubShareFunc: pubShareFunc,
		eth2Cl:       eth2Cl,
		index:        index,
	}, nil
}

type Component struct {
	eth2Cl       eth2Provider
	index        int
	skipVerify   bool
	pubShareFunc PubShareFunc

	// Registered input functions

	pubKeyByAttFunc func(ctx context.Context, slot, commIdx, valCommIdx int64) (core.PubKey, error)
	awaitAttFunc    func(ctx context.Context, slot, commIdx int64) (*eth2p0.AttestationData, error)
	parSigDBFuncs   []func(context.Context, core.Duty, core.ParSignedDataSet) error
}

// RegisterAwaitAttestation registers a function to query attestation data.
// It only supports a single function, since it is an input of the component.
func (c *Component) RegisterAwaitAttestation(fn func(ctx context.Context, slot, commIdx int64) (*eth2p0.AttestationData, error)) {
	c.awaitAttFunc = fn
}

// RegisterPubKeyByAttestation registers a function to query pubkeys by attestation.
// It only supports a single function, since it is an input of the component.
func (c *Component) RegisterPubKeyByAttestation(fn func(ctx context.Context, slot, commIdx, valCommIdx int64) (core.PubKey, error)) {
	c.pubKeyByAttFunc = fn
}

// RegisterParSigDB registers a partial signed data set store function.
// It supports functions multiple since it is the output of the component.
func (c *Component) RegisterParSigDB(fn func(context.Context, core.Duty, core.ParSignedDataSet) error) {
	c.parSigDBFuncs = append(c.parSigDBFuncs, fn)
}

// AttestationData implements the eth2client.AttesterDutiesProvider for the router.
func (c *Component) AttestationData(ctx context.Context, slot eth2p0.Slot, committeeIndex eth2p0.CommitteeIndex) (*eth2p0.AttestationData, error) {
	return c.awaitAttFunc(ctx, int64(slot), int64(committeeIndex))
}

// SubmitAttestations implements the eth2client.AttestationsSubmitter for the router.
func (c *Component) SubmitAttestations(ctx context.Context, attestations []*eth2p0.Attestation) error {
	setsBySlot := make(map[int64]core.ParSignedDataSet)

	for _, att := range attestations {
		slot := int64(att.Data.Slot)
		duty := core.Duty{Slot: slot, Type: core.DutyAttester}

		// Determine the validator that sent this by mapping values from original AttestationDuty via the dutyDB
		indices := att.AggregationBits.BitIndices()
		if len(indices) != 1 {
			return errors.New("unexpected number of aggregation bits",
				z.Str("aggbits", fmt.Sprintf("%#x", []byte(att.AggregationBits))))
		}

		pubkey, err := c.pubKeyByAttFunc(ctx, slot, int64(att.Data.Index), int64(indices[0]))
		if err != nil {
			return err
		}

		// Verify signature
		sigRoot, err := att.Data.HashTreeRoot()
		if err != nil {
			return errors.Wrap(err, "hash attestation data")
		}

		if err := c.verifyParSig(ctx, duty, pubkey, sigRoot, att.Signature); err != nil {
			return err
		}

		// Encode partial signed data and add to a set
		set, ok := setsBySlot[slot]
		if !ok {
			set = make(core.ParSignedDataSet)
			setsBySlot[slot] = set
		}

		signedData, err := core.EncodeAttestationParSignedData(att, c.index)
		if err != nil {
			return err
		}

		set[pubkey] = signedData
	}

	// Send sets to subscriptions.
	for slot, set := range setsBySlot {
		duty := core.Duty{
			Slot: slot,
			Type: core.DutyAttester,
		}

		for _, dbFunc := range c.parSigDBFuncs {
			err := dbFunc(ctx, duty, set)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// verifyParSig verifies the partial signature against the root and validator.
func (c *Component) verifyParSig(ctx context.Context, duty core.Duty, pubkey core.PubKey, sigRoot eth2p0.Root, sig eth2p0.BLSSignature) error {
	if c.skipVerify {
		return nil
	}

	// Get the public key of the share that created the signature.
	pubshare, err := c.pubShareFunc(pubkey, c.index)
	if err != nil {
		return err
	}

	// Wrap the signing root with the domain and serialise it.
	sigData, err := prepSigningData(ctx, c.eth2Cl, duty, sigRoot)
	if err != nil {
		return err
	}

	// Convert the signature
	s, err := bls12381.NewG2().FromCompressed(sig[:])
	if err != nil {
		return errors.Wrap(err, "convert signature")
	}

	// Verify
	ok, err := tbls.Verify(pubshare, sigData, &bls_sig.Signature{Value: *s})
	if err != nil {
		return err
	} else if !ok {
		return errors.New("invalid signature")
	}

	return nil
}
