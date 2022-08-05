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

package signing_test

import (
	"context"
	"testing"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util/signing"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestVerifyAttestation(t *testing.T) {
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	att := testutil.RandomAttestation()

	root, err := att.Data.HashTreeRoot()
	require.NoError(t, err)

	sigData, err := signing.GetDataRoot(context.Background(), bmock, signing.DomainBeaconAttester, att.Data.Target.Epoch, root)
	require.NoError(t, err)

	sig, pubkey := sign(t, sigData[:])
	att.Signature = tblsconv.SigToETH2(sig)

	require.NoError(t, signing.VerifySignedData(context.Background(), bmock, pubkey, att))
}

func TestVerifyBeaconBlock(t *testing.T) {
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	block := testutil.RandomCoreVersionSignedBeaconBlock(t)

	slot, err := block.Slot()
	require.NoError(t, err)

	root, err := block.Root()
	require.NoError(t, err)

	slotsPerEpoch, err := bmock.SlotsPerEpoch(context.Background())
	require.NoError(t, err)
	epoch := eth2p0.Epoch(uint64(slot) / slotsPerEpoch)

	sigData, err := signing.GetDataRoot(context.Background(), bmock, signing.DomainBeaconProposer, epoch, root)
	require.NoError(t, err)

	sig, pubkey := sign(t, sigData[:])
	data, err := block.SetSignature(tblsconv.SigToCore(sig))
	require.NoError(t, err)

	versionedBlock := data.(core.VersionedSignedBeaconBlock).VersionedSignedBeaconBlock

	require.NoError(t, signing.VerifySignedData(context.Background(), bmock, pubkey, versionedBlock))
}

//
// func TestVerifyDutyRandao(t *testing.T) {
//	duty := core.NewRandaoDuty(123)
//
//	bmock, err := beaconmock.New()
//	require.NoError(t, err)
//
//	slotsPerEpoch, err := bmock.SlotsPerEpoch(context.Background())
//	require.NoError(t, err)
//
//	epoch := eth2p0.Epoch(uint64(duty.Slot) / slotsPerEpoch)
//	sigRoot, err := eth2util.EpochHashRoot(epoch)
//	require.NoError(t, err)
//
//	sigData, err := signing.GetDataRoot(context.Background(), bmock, signing.DomainRandao, epoch, sigRoot)
//	require.NoError(t, err)
//
//	sig, pubkey := sign(t, sigData[:])
//	psig := core.NewPartialSignature(tblsconv.SigToCore(sig), 0)
//
//	verifyFunc := signing.NewVerifyFunc(bmock)
//	require.NoError(t, verifyFunc(context.Background(), duty, pubkey, psig))
//}

func TestVerifyVoluntaryExit(t *testing.T) {
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	exit := testutil.RandomExit()

	sigRoot, err := exit.Message.HashTreeRoot()
	require.NoError(t, err)

	sigData, err := signing.GetDataRoot(context.Background(), bmock, signing.DomainExit, exit.Message.Epoch, sigRoot)
	require.NoError(t, err)

	sig, pubkey := sign(t, sigData[:])
	exit.Signature = tblsconv.SigToETH2(sig)

	require.NoError(t, signing.VerifySignedData(context.Background(), bmock, pubkey, exit))
}

func TestVerifyBlindedBeaconBlock(t *testing.T) {
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	block := testutil.RandomCoreVersionSignedBlindedBeaconBlock(t)

	slot, err := block.Slot()
	require.NoError(t, err)

	root, err := block.Root()
	require.NoError(t, err)

	slotsPerEpoch, err := bmock.SlotsPerEpoch(context.Background())
	require.NoError(t, err)
	epoch := eth2p0.Epoch(uint64(slot) / slotsPerEpoch)

	sigData, err := signing.GetDataRoot(context.Background(), bmock, signing.DomainBeaconProposer, epoch, root)
	require.NoError(t, err)

	sig, pubkey := sign(t, sigData[:])
	data, err := block.SetSignature(tblsconv.SigToCore(sig))
	require.NoError(t, err)

	versionedBlock := data.(core.VersionedSignedBlindedBeaconBlock).VersionedSignedBlindedBeaconBlock

	require.NoError(t, signing.VerifySignedData(context.Background(), bmock, pubkey, versionedBlock))
}

func TestVerifyBuilderRegistration(t *testing.T) {
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	registration := testutil.RandomCoreVersionedSignedValidatorRegistration(t).VersionedSignedValidatorRegistration

	sigRoot, err := registration.V1.Message.HashTreeRoot()
	require.NoError(t, err)

	sigData, err := signing.GetDataRoot(nil, nil, signing.DomainApplicationBuilder, 0, sigRoot)
	require.NoError(t, err)

	sig, pubkey := sign(t, sigData[:])
	registration.V1.Signature = tblsconv.SigToETH2(sig)

	require.NoError(t, signing.VerifySignedData(context.Background(), bmock, pubkey, registration))
}

func sign(t *testing.T, data []byte) (*bls_sig.Signature, *bls_sig.PublicKey) {
	t.Helper()

	pk, secret, err := tbls.Keygen()
	require.NoError(t, err)

	sig, err := tbls.Sign(secret, data)
	require.NoError(t, err)

	return sig, pk
}
