// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cluster_test

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/testutil"
)

//go:generate go test . -v -update -clean

const (
	v1_6 = "v1.6.0"
	v1_5 = "v1.5.0"
	v1_4 = "v1.4.0"
	v1_3 = "v1.3.0"
	v1_2 = "v1.2.0"
	v1_1 = "v1.1.0"
	v1_0 = "v1.0.0"
)

// TestEncode tests whether charon can correctly encode lock and definition files.
func TestEncode(t *testing.T) {
	for _, version := range cluster.SupportedVersionsForT(t) {
		t.Run(version, func(t *testing.T) {
			vStr := strings.ReplaceAll(version, ".", "_")
			rand.Seed(1)

			const (
				numVals   = 2
				threshold = 3
			)

			opts := []func(d *cluster.Definition){
				func(d *cluster.Definition) {
					d.Version = version
					d.Timestamp = "2022-07-19T18:19:58+02:00" // Make deterministic
				},
			}
			// Definition version prior to v1.5 don't support multiple validator addresses.
			if isAnyVersion(version, v1_0, v1_1, v1_2, v1_3, v1_4) {
				opts = append(opts, cluster.WithLegacyVAddrs(testutil.RandomETHAddress(), testutil.RandomETHAddress()))
			}

			var feeRecipientAddrs, withdrawalAddrs []string
			for i := 0; i < numVals; i++ {
				feeRecipientAddrs = append(feeRecipientAddrs, testutil.RandomETHAddress())
				withdrawalAddrs = append(withdrawalAddrs, testutil.RandomETHAddress())
			}

			definition, err := cluster.NewDefinition(
				"test definition",
				numVals,
				threshold,
				feeRecipientAddrs,
				withdrawalAddrs,
				eth2util.Sepolia.GenesisForkVersionHex,
				cluster.Creator{
					Address:         testutil.RandomETHAddress(),
					ConfigSignature: testutil.RandomSecp256k1Signature(),
				},
				[]cluster.Operator{
					{
						Address:         testutil.RandomETHAddress(),
						ENR:             fmt.Sprintf("enr://%x", testutil.RandomBytes32()),
						ConfigSignature: testutil.RandomSecp256k1Signature(),
						ENRSignature:    testutil.RandomSecp256k1Signature(),
					},
					{
						Address:         testutil.RandomETHAddress(),
						ENR:             fmt.Sprintf("enr://%x", testutil.RandomBytes32()),
						ConfigSignature: testutil.RandomSecp256k1Signature(),
						ENRSignature:    testutil.RandomSecp256k1Signature(),
					},
				},
				rand.New(rand.NewSource(0)),
				opts...,
			)
			testutil.RequireNoError(t, err)

			// Definition version prior to v1.3.0 don't support EIP712 signatures.
			if isAnyVersion(version, v1_0, v1_1, v1_2) {
				for i := range definition.Operators {
					// Set to empty values instead of nil to align with unmarshalled json.
					definition.Operators[i].ConfigSignature = []byte{}
					definition.Operators[i].ENRSignature = []byte{}
				}
			}

			// Definition version prior to v1.4.0 don't support creator.
			if isAnyVersion(version, v1_0, v1_1, v1_2, v1_3) {
				definition.Creator = cluster.Creator{}
			}

			t.Run("definition_json_"+vStr, func(t *testing.T) {
				testutil.RequireGoldenJSON(t, definition,
					testutil.WithFilename("cluster_definition_"+vStr+".json"))
			})

			b1, err := json.Marshal(definition)
			testutil.RequireNoError(t, err)

			var definition2 cluster.Definition
			err = json.Unmarshal(b1, &definition2)
			require.NoError(t, err)

			b2, err := json.Marshal(definition2)
			require.NoError(t, err)

			require.Equal(t, b1, b2)

			definition, err = definition.SetDefinitionHashes() // Add hashes to locally created definition.
			require.NoError(t, err)
			require.Equal(t, definition, definition2)

			lock := cluster.Lock{
				Definition:         definition,
				SignatureAggregate: testutil.RandomBytes32(),
				Validators: []cluster.DistValidator{
					{
						PubKey: testutil.RandomBytes48(),
						PubShares: [][]byte{
							testutil.RandomBytes48(),
							testutil.RandomBytes48(),
						},
						DepositData:         cluster.RandomDepositData(),
						BuilderRegistration: cluster.RandomRegistration(t, eth2util.Sepolia.Name),
					}, {
						PubKey: testutil.RandomBytes48(),
						PubShares: [][]byte{
							testutil.RandomBytes48(),
							testutil.RandomBytes48(),
						},
						DepositData:         cluster.RandomDepositData(),
						BuilderRegistration: cluster.RandomRegistration(t, eth2util.Sepolia.Name),
					},
				},
				NodeSignatures: [][]byte{
					testutil.RandomBytes32(),
					testutil.RandomBytes32(),
				},
			}

			// Make sure all the pubkeys are same.
			for i := range lock.Validators {
				lock.Validators[i].DepositData.PubKey = lock.Validators[i].PubKey
				lock.Validators[i].BuilderRegistration.Message.PubKey = lock.Validators[i].PubKey
			}

			// Lock version prior to v1.6.0 don't support DepositData.
			if isAnyVersion(version, v1_0, v1_1, v1_2, v1_3, v1_4, v1_5) {
				for i := range lock.Validators {
					lock.Validators[i].DepositData = cluster.DepositData{}
				}
			}

			// Lock version prior to v1.7.0 don't support BuilderRegistration.
			if isAnyVersion(version, v1_0, v1_1, v1_2, v1_3, v1_4, v1_5, v1_6) {
				for i := range lock.Validators {
					lock.Validators[i].BuilderRegistration = cluster.BuilderRegistration{}
				}

				lock.NodeSignatures = nil
			}

			t.Run("lock_json_"+vStr, func(t *testing.T) {
				testutil.RequireGoldenJSON(t, lock,
					testutil.WithFilename("cluster_lock_"+vStr+".json"))
			})

			b1, err = json.Marshal(lock)
			require.NoError(t, err)

			var lock2 cluster.Lock
			err = json.Unmarshal(b1, &lock2)
			require.NoError(t, err)

			b2, err = json.Marshal(lock2)
			require.NoError(t, err)

			require.Equal(t, b1, b2)

			lock, err = lock.SetLockHash()
			require.NoError(t, err)
			require.Equal(t, lock, lock2)
		})
	}
}

func TestUnsupportedVersion(t *testing.T) {
	var def cluster.Definition
	err := json.Unmarshal([]byte(`{"version":"invalid"}`), &def)
	require.ErrorContains(t, err, "unsupported definition version")

	var lock cluster.Lock
	err = json.Unmarshal([]byte(`{"cluster_definition":{"version":"invalid"}}`), &lock)
	require.ErrorContains(t, err, "unsupported definition version")
}

// TestExamples tests whether charon is backwards compatible with all examples. Note that these examples
// are added manually and not auto-generated.
func TestExamples(t *testing.T) {
	lockFiles, err := filepath.Glob("examples/*lock*")
	require.NoError(t, err)

	for _, file := range lockFiles {
		t.Run(filepath.Base(file), func(t *testing.T) {
			b, err := os.ReadFile(file)
			require.NoError(t, err)

			var lock cluster.Lock
			err = json.Unmarshal(b, &lock)
			require.NoError(t, err)

			require.NoError(t, lock.VerifyHashes())
			require.NoError(t, lock.VerifySignatures())
		})
	}

	defFiles, err := filepath.Glob("examples/*-definition*")
	require.NoError(t, err)

	for _, file := range defFiles {
		t.Run(filepath.Base(file), func(t *testing.T) {
			b, err := os.ReadFile(file)
			require.NoError(t, err)

			var def cluster.Definition
			err = json.Unmarshal(b, &def)
			require.NoError(t, err)
			require.NoError(t, def.VerifyHashes())
			require.NoError(t, def.VerifySignatures())
		})
	}
}

func TestDefinitionPeers(t *testing.T) {
	lock, _, _ := cluster.NewForT(t, 2, 3, 4, 5)
	peers, err := lock.Peers()
	require.NoError(t, err)

	names := []string{"curious-land", "adventurous-age", "witty-industry", "cute-group"}

	for i, peer := range peers {
		require.Equal(t, i, peer.Index)
		require.Equal(t, names[i], peer.Name)
	}
}

func isAnyVersion(version string, list ...string) bool {
	for _, v := range list {
		if version == v {
			return true
		}
	}

	return false
}

var newLock = flag.Bool("new-lock", false, "Generate new cluster lock file.")

func TestGenerateLatestLock(t *testing.T) {
	if !*newLock {
		t.Skip()
	}

	lockBytes, err := os.ReadFile("../.charon/node0/cluster-lock.json")
	require.NoError(t, err)

	var oldLock oldLockJSON
	err = json.Unmarshal(lockBytes, &oldLock)
	require.NoError(t, err)

	var (
		enrKeys   []*k1.PrivateKey
		keyshares []tbls.PrivateKey
	)
	for i := 0; i < len(oldLock.Definition.Operators); i++ {
		keyFiles, err := keystore.LoadFilesUnordered(fmt.Sprintf("../.charon/node%d/validator_keys", i))
		require.NoError(t, err)

		secrets, err := keyFiles.SequencedKeys()
		require.NoError(t, err)

		keyshares = append(keyshares, secrets...)

		p2pKey, err := k1util.Load(fmt.Sprintf("../.charon/node%d/charon-enr-private-key", i))
		require.NoError(t, err)

		enrKeys = append(enrKeys, p2pKey)
	}

	newLock := cluster.Lock{
		Definition: oldLock.Definition,
		Validators: distValidatorsFromV1x7OrLater(t, oldLock.Validators),
	}

	newLock, err = newLock.SetLockHash()
	require.NoError(t, err)
	require.NotNil(t, newLock.LockHash)

	// Fill signature_aggregate field.
	var sigs []tbls.Signature
	for _, key := range keyshares {
		sig, err := tbls.Sign(key, newLock.LockHash)
		require.NoError(t, err)

		sigs = append(sigs, sig)
	}

	sigAgg, err := tbls.Aggregate(sigs)
	require.NoError(t, err)

	newLock.SignatureAggregate = sigAgg[:]

	// Generate node_signatures.
	var nodeSigs [][]byte
	for _, key := range enrKeys {
		nodeSig, err := k1util.Sign(key, newLock.LockHash)
		require.NoError(t, err)

		nodeSigs = append(nodeSigs, nodeSig)
	}

	newLock.NodeSignatures = nodeSigs
	require.NoError(t, newLock.VerifySignatures())

	lockBytes, err = json.MarshalIndent(newLock, "", " ")
	require.NoError(t, err)

	require.NoError(t, os.WriteFile("cluster-lock.json", lockBytes, 0o444))
}

type oldLockJSON struct {
	Definition         cluster.Definition      `json:"cluster_definition"`
	Validators         []distValidatorJSONv1x7 `json:"distributed_validators"`
	SignatureAggregate ethHex                  `json:"signature_aggregate"`
	LockHash           ethHex                  `json:"lock_hash"`
	NodeSignatures     []ethHex                `json:"node_signatures"`
}

type ethHex []byte

func (h *ethHex) UnmarshalJSON(data []byte) error {
	var strHex string
	if err := json.Unmarshal(data, &strHex); err != nil {
		return errors.Wrap(err, "unmarshal hex string")
	}

	resp, err := hex.DecodeString(strings.TrimPrefix(strHex, "0x"))
	if err != nil {
		return errors.Wrap(err, "unmarshal hex")
	}

	*h = resp

	return nil
}

func (h ethHex) MarshalJSON() ([]byte, error) {
	resp, err := json.Marshal(to0xHex(h))
	if err != nil {
		return nil, errors.Wrap(err, "marshal hex")
	}

	return resp, nil
}

func to0xHex(b []byte) string {
	if len(b) == 0 {
		return ""
	}

	return fmt.Sprintf("%#x", b)
}

type distValidatorJSONv1x7 struct {
	PubKey              ethHex                  `json:"distributed_public_key"`
	PubShares           []ethHex                `json:"public_shares,omitempty"`
	DepositData         depositDataJSON         `json:"deposit_data,omitempty"`
	BuilderRegistration builderRegistrationJSON `json:"builder_registration,omitempty"`
}

type depositDataJSON struct {
	PubKey                ethHex `json:"pubkey"`
	WithdrawalCredentials ethHex `json:"withdrawal_credentials"`
	Amount                int    `json:"amount,string"`
	Signature             ethHex `json:"signature"`
}

type builderRegistrationJSON struct {
	Message   registrationJSON `json:"message"`
	Signature ethHex           `json:"signature"`
}

// registrationJSON is the json formatter of Registration.
type registrationJSON struct {
	FeeRecipient ethHex `json:"fee_recipient"`
	GasLimit     int    `json:"gas_limit"`
	Timestamp    string `json:"timestamp"`
	PubKey       ethHex `json:"pubkey"`
}

func distValidatorsFromV1x7OrLater(t *testing.T, distValidators []distValidatorJSONv1x7) []cluster.DistValidator {
	t.Helper()

	var resp []cluster.DistValidator
	for _, dv := range distValidators {
		var shares [][]byte
		for _, share := range dv.PubShares {
			shares = append(shares, share)
		}

		timestamp, err := time.Parse(time.RFC3339, dv.BuilderRegistration.Message.Timestamp)
		require.NoError(t, err)

		resp = append(resp, cluster.DistValidator{
			PubKey:    dv.PubKey,
			PubShares: shares,
			DepositData: cluster.DepositData{
				PubKey:                dv.DepositData.PubKey,
				WithdrawalCredentials: dv.DepositData.WithdrawalCredentials,
				Amount:                dv.DepositData.Amount,
				Signature:             dv.DepositData.Signature,
			},
			BuilderRegistration: cluster.BuilderRegistration{
				Message: cluster.Registration{
					FeeRecipient: dv.BuilderRegistration.Message.FeeRecipient,
					GasLimit:     dv.BuilderRegistration.Message.GasLimit,
					Timestamp:    timestamp,
					PubKey:       dv.BuilderRegistration.Message.PubKey,
				},
				Signature: dv.BuilderRegistration.Signature,
			},
		})
	}

	return resp
}
