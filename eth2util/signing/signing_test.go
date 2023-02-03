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
	"os"
	"testing"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util/signing"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	tblsv2 "github.com/obolnetwork/charon/tbls/v2"
	herumiImpl "github.com/obolnetwork/charon/tbls/v2/herumi"
	"github.com/obolnetwork/charon/testutil/beaconmock"
)

func TestMain(m *testing.M) {
	tblsv2.SetImplementation(herumiImpl.Herumi{})
	os.Exit(m.Run())
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

	pubkey, err := secretShare.GetPublicKey()
	require.NoError(t, err)

	rawKey, err := pubkey.MarshalBinary()
	require.NoError(t, err)

	err = signing.Verify(context.Background(), bmock, signing.DomainApplicationBuilder, 0, sigRoot, tblsconv.SigToETH2(sig), rawKey)
	require.NoError(t, err)
}
