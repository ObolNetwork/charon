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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util"
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

	require.NoError(t, signing.VerifyAttestation(context.Background(), bmock, pubkey, att))
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

	require.NoError(t, signing.VerifyBlock(context.Background(), bmock, pubkey, &versionedBlock))
}

func TestVerifyDutyRandao(t *testing.T) {
	duty := core.NewRandaoDuty(123)

	bmock, err := beaconmock.New()
	require.NoError(t, err)

	slotsPerEpoch, err := bmock.SlotsPerEpoch(context.Background())
	require.NoError(t, err)

	randao := eth2util.SignedEpoch{Epoch: eth2p0.Epoch(uint64(duty.Slot) / slotsPerEpoch)}
	sigRoot, err := randao.EpochHashRoot()
	require.NoError(t, err)

	sigData, err := signing.GetDataRoot(context.Background(), bmock, signing.DomainRandao, randao.Epoch, sigRoot)
	require.NoError(t, err)

	sig, pubkey := sign(t, sigData[:])
	randao.Signature = tblsconv.SigToETH2(sig)

	require.NoError(t, signing.VerifyRandao(context.Background(), bmock, pubkey, randao))
}

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

	require.NoError(t, signing.VerifyVoluntaryExit(context.Background(), bmock, pubkey, exit))
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

	require.NoError(t, signing.VerifyBlindedBlock(context.Background(), bmock, pubkey, &versionedBlock))
}

func TestVerifyRegistrationReference(t *testing.T) {
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	// Test data obtained from teku.

	secretShareBytes, err := hex.DecodeString("345768c0245f1dc702df9e50e811002f61ebb2680b3d5931527ef59f96cbaf9b")
	require.NoError(t, err)

	secretShare, err := tblsconv.SecretFromBytes(secretShareBytes)
	require.NoError(t, err)

	registrationJSON := `
 {
  "message": {
   "fee_recipient": "0x000000000000000000000000000000000000dead",
   "gas_limit": "30000000",
   "timestamp": "1646092800",
   "pubkey": "0x86966350b672bd502bfbdb37a6ea8a7392e8fb7f5ebb5c5e2055f4ee168ebfab0fef63084f28c9f62c3ba71f825e527e"
  },
  "signature": "0xb101da0fc08addcc5d010ee569f6bbbdca049a5cb27efad231565bff2e3af504ec2bb87b11ed22843e9c1094f1dfe51a0b2a5ad1808df18530a2f59f004032dbf6281ecf0fc3df86d032da5b9d32a3d282c05923de491381f8f28c2863a00180"
 }`

	registration := new(eth2v1.SignedValidatorRegistration)
	err = json.Unmarshal([]byte(registrationJSON), registration)
	require.NoError(t, err)

	sigRoot, err := registration.Message.HashTreeRoot()
	require.NoError(t, err)

	sigData, err := signing.GetDataRoot(context.Background(), bmock, signing.DomainApplicationBuilder, 0, sigRoot)
	require.NoError(t, err)

	sig, err := tbls.Sign(secretShare, sigData[:])
	require.NoError(t, err)

	sigEth2 := tblsconv.SigToETH2(sig)
	require.Equal(t,
		fmt.Sprintf("%x", registration.Signature),
		fmt.Sprintf("%x", sigEth2),
	)
}

func TestVerifyBuilderRegistration(t *testing.T) {
	bmock, err := beaconmock.New()
	require.NoError(t, err)

	registration := testutil.RandomCoreVersionedSignedValidatorRegistration(t).VersionedSignedValidatorRegistration

	sigRoot, err := registration.Root()
	require.NoError(t, err)

	sigData, err := signing.GetDataRoot(context.Background(), bmock, signing.DomainApplicationBuilder, 0, sigRoot)
	require.NoError(t, err)

	sig, pubkey := sign(t, sigData[:])
	registration.V1.Signature = tblsconv.SigToETH2(sig)

	require.NoError(t, signing.VerifyValidatorRegistration(context.Background(), bmock, pubkey, &registration))
}

func sign(t *testing.T, data []byte) (*bls_sig.Signature, *bls_sig.PublicKey) {
	t.Helper()

	pk, secret, err := tbls.Keygen()
	require.NoError(t, err)

	sig, err := tbls.Sign(secret, data)
	require.NoError(t, err)

	return sig, pk
}
