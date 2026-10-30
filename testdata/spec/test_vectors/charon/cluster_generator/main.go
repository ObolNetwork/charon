// Command zz_spec_vectors emits golden cluster config, definition and lock
// hashes for the distributed-validator-specs test vectors. Temporary generator,
// not part of charon.
//
// Every expected hash comes out of charon's own cluster package via the exported
// SetDefinitionHashes and SetLockHash, so a passing suite means "agrees with
// charon" rather than "agrees with the spec".
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/tbls"
)

const (
	version = "v1.10.0"

	// Sepolia's genesis fork version, which charon's own v1.10 testdata uses.
	forkVersion = "90000069"

	definitionGolden = "cluster/testdata/cluster_definition_v1_10_0.json"
	lockGolden       = "cluster/testdata/cluster_lock_v1_10_0.json"

	// The 3-of-4 BLS sharing already pinned in bls_threshold.json, reused so the
	// lock's signature aggregate can be verified against public shares that
	// suite already fixes.
	groupSecretHex = "598d4150de5b558716e1ca4df2853d696c1cc47f3af380d9ac3db876ebd038c5"
)

// blsShareHexes are the same shares as bls_threshold.json, at x=1..4.
var blsShareHexes = []string{
	"7113350cf92900d71d73cab886f244c12b589bfa98d2fd116e0d25265b82fedb",
	"2a14b99e273adba1640ac3ea6be7ab097b50c6f7e04292598513ebc615f2b4c8",
	"6c6d1daabbcbe076511a65f3b4a9204d03808d7d113ef8aff1520c541b1f5a8e",
	"5041128c63a114c57e2f00c44df2f4811c6ca7842bcb7816b2c786d26b08f02b",
}

// nodeSecretHexes are the charon node keys of the four operators. The first is
// the same secp256k1 key as secp256k1_signatures.json.
var nodeSecretHexes = []string{
	"4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d",
	"2b0f1a3f5c9d8e7b6a4c2d0e1f3a5b7c9d8e6f4a2b0c1d3e5f7a9b8c6d4e2f01",
	"6d4e2f0a1b3c5d7e9f8a6b4c2d0e1f3a5b7c9d8e6f4a2b0c1d3e5f7a9b8c6d42",
	"1f3a5b7c9d8e6f4a2b0c1d3e5f7a9b8c6d4e2f0a1b3c5d7e9f8a6b4c2d0e1f30",
}

// hashCase is one definition or lock, with the hashes charon derives from it.
// Input is charon's own JSON for the object, so the spec has to parse the real
// file format rather than a transcription of it.
type hashCase struct {
	Name           string          `json:"name"`
	Input          json.RawMessage `json:"input"`
	ConfigHash     string          `json:"config_hash,omitempty"`
	DefinitionHash string          `json:"definition_hash,omitempty"`
	LockHash       string          `json:"lock_hash,omitempty"`
	NodePubkeys    []string        `json:"node_pubkeys,omitempty"`
	Notes          string          `json:"notes,omitempty"`
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}

	return v
}

func mustHex(h string) []byte {
	return must(hex.DecodeString(h))
}

// repeatByte returns n copies of b, for placeholder signature bytes.
func repeatByte(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}

	return out
}

// operatorFor builds an operator whose ENR is derived from its node key, so the
// lock's node signatures can be verified against the ENRs the file carries.
func operatorFor(idx int, withSigs bool) cluster.Operator {
	record := must(enr.New(k1.PrivKeyFromBytes(mustHex(nodeSecretHexes[idx]))))

	op := cluster.Operator{
		Address: fmt.Sprintf("0x%040x", idx+1),
		ENR:     record.String(),
	}
	if withSigs {
		op.ConfigSignature = repeatByte(byte(0x10+idx), 65)
		op.ENRSignature = repeatByte(byte(0x20+idx), 65)
	}

	return op
}

func validatorAddresses(count int) []cluster.ValidatorAddresses {
	var out []cluster.ValidatorAddresses
	for i := range count {
		out = append(out, cluster.ValidatorAddresses{
			FeeRecipientAddress: fmt.Sprintf("0x%040x", 0xfee0+i),
			WithdrawalAddress:   fmt.Sprintf("0x%040x", 0xdead0+i),
		})
	}

	return out
}

// definitionCase hashes a hand-built definition and emits it.
func definitionCase(name string, def cluster.Definition, notes string) hashCase {
	hashed := must(def.SetDefinitionHashes())

	return hashCase{
		Name:           name,
		Input:          must(json.Marshal(hashed)),
		ConfigHash:     hex.EncodeToString(hashed.ConfigHash),
		DefinitionHash: hex.EncodeToString(hashed.DefinitionHash),
		Notes:          notes,
	}
}

// lockCase hashes a hand-built lock and emits it.
func lockCase(name string, lock cluster.Lock, notes string, nodePubkeys []string) hashCase {
	lock.Definition = must(lock.Definition.SetDefinitionHashes())
	hashed := must(lock.SetLockHash())

	return hashCase{
		Name:        name,
		Input:       must(json.Marshal(hashed)),
		LockHash:    hex.EncodeToString(hashed.LockHash),
		NodePubkeys: nodePubkeys,
		Notes:       notes,
	}
}

func registrationFor(pubkey []byte, gasLimit int, timestamp int64) cluster.BuilderRegistration {
	return cluster.BuilderRegistration{
		Message: cluster.Registration{
			FeeRecipient: mustHex("9be1072fb63c35d6042c4160f38ee9e2a9f3fb4f"),
			GasLimit:     gasLimit,
			Timestamp:    time.Unix(timestamp, 0),
			PubKey:       pubkey,
		},
		Signature: repeatByte(0x55, 96),
	}
}

func main() {
	out := map[string]any{}

	// --- Charon's own regression fixtures, loaded and re-hashed. TestEncode in
	// cluster_test.go asserts these files, so they are goldens in charon's CI.
	var goldenDef cluster.Definition
	if err := json.Unmarshal(must(os.ReadFile(definitionGolden)), &goldenDef); err != nil {
		panic(err)
	}

	goldenLock := must(cluster.LoadClusterLock(context.Background(), lockGolden, true, nil))

	definitions := []hashCase{{
		Name:           "charon_testdata_golden",
		Input:          must(json.Marshal(goldenDef)),
		ConfigHash:     hex.EncodeToString(goldenDef.ConfigHash),
		DefinitionHash: hex.EncodeToString(goldenDef.DefinitionHash),
		Notes: "Charon's own v1.10.0 regression fixture, " +
			"cluster/testdata/cluster_definition_v1_10_0.json, unmodified. " +
			"Two operators, two validators, two partial deposit amounts.",
	}}

	// --- Every string field empty, no operators, no validators, no deposit
	// amounts: the structural floor of a definition.
	definitions = append(definitions, definitionCase("all_empty_lists", cluster.Definition{
		UUID:           "00000000-0000-0000-0000-000000000000",
		Version:        version,
		ForkVersion:    mustHex("00000000"),
		TargetGasLimit: 30000000,
	}, "Empty name, timestamp, consensus protocol, operators, validators and "+
		"deposit amounts. Pins the empty-list hashes: a byte list whose capacity "+
		"is one chunk hashes to sha256(zero chunk || zero length), while "+
		"deposit_amounts spans 64 chunks and so hashes its depth-6 zero subtree "+
		"with a zero length mixed in."))

	// --- The same definition unsigned and then signed. The config hash must not
	// move, because that is the hash the operators are signing; the definition
	// hash must move, because it covers the signatures. Emitting both as cases
	// lets a consumer assert the relationship rather than take it on trust.
	unsigned := cluster.Definition{
		UUID:               "0194FDC2-FA2F-4CC0-81D3-FF12045B73C8",
		Name:               "signature collection",
		Version:            version,
		Timestamp:          "2026-07-29T12:00:00+00:00",
		NumValidators:      1,
		Threshold:          1,
		DKGAlgorithm:       "default",
		ForkVersion:        mustHex(forkVersion),
		Operators:          []cluster.Operator{operatorFor(0, false)},
		Creator:            cluster.Creator{Address: fmt.Sprintf("0x%040x", 0xc0ffee)},
		ValidatorAddresses: validatorAddresses(1),
		ConsensusProtocol:  "qbft",
		TargetGasLimit:     30000000,
	}

	signed := unsigned
	signed.Operators = []cluster.Operator{operatorFor(0, true)}
	signed.Creator = cluster.Creator{
		Address:         fmt.Sprintf("0x%040x", 0xc0ffee),
		ConfigSignature: repeatByte(0x30, 65),
	}

	definitions = append(definitions,
		definitionCase("unsigned_single_operator", unsigned,
			"A definition as it looks while signatures are still being collected. "+
				"Absent signatures are left-padded to 65 zero bytes, so this hashes "+
				"identically to a definition carrying all-zero signatures."),
		definitionCase("signed_single_operator", signed,
			"The unsigned_single_operator definition with operator and creator "+
				"signatures added, and nothing else changed. Its config_hash MUST equal "+
				"that case's config_hash and its definition_hash MUST differ: an "+
				"implementation whose config hash moves when a signature arrives makes "+
				"every already-collected signature invalid."))

	// --- Three operators (an odd list length) and compounding enabled.
	definitions = append(definitions, definitionCase("three_operators_compounding",
		cluster.Definition{
			UUID:          "0194FDC2-FA2F-4CC0-81D3-FF12045B73C8",
			Name:          "three operators",
			Version:       version,
			Timestamp:     "2026-07-29T12:00:00+00:00",
			NumValidators: 2,
			Threshold:     2,
			DKGAlgorithm:  "default",
			ForkVersion:   mustHex(forkVersion),
			Operators: []cluster.Operator{
				operatorFor(0, true), operatorFor(1, true), operatorFor(2, true),
			},
			Creator: cluster.Creator{
				Address:         fmt.Sprintf("0x%040x", 0xc0ffee),
				ConfigSignature: repeatByte(0x30, 65),
			},
			ValidatorAddresses: validatorAddresses(2),
			DepositAmounts:     []eth2p0.Gwei{1000000000, 31000000000},
			ConsensusProtocol:  "abft",
			TargetGasLimit:     36000000,
			Compounding:        true,
		},
		"Three operators, an odd list length: the leaf layer completes with a "+
			"zero chunk, and the odd node it propagates pairs with each higher "+
			"level's zero-subtree hash. Also the only case with compounding set."))

	// --- A target gas limit above 2^32, which a 32-bit write would truncate.
	definitions = append(definitions, definitionCase("gas_limit_above_2_32",
		cluster.Definition{
			UUID:               "0194FDC2-FA2F-4CC0-81D3-FF12045B73C8",
			Name:               "wide gas limit",
			Version:            version,
			Timestamp:          "2026-07-29T12:00:00+00:00",
			NumValidators:      1,
			Threshold:          1,
			DKGAlgorithm:       "default",
			ForkVersion:        mustHex(forkVersion),
			Operators:          []cluster.Operator{operatorFor(0, true)},
			Creator:            cluster.Creator{Address: fmt.Sprintf("0x%040x", 0xc0ffee)},
			ValidatorAddresses: validatorAddresses(1),
			TargetGasLimit:     4294967296,
			DepositAmounts:     []eth2p0.Gwei{32000000000},
		},
		"target_gas_limit is 2^32, which a hasher writing a 32-bit integer would "+
			"truncate to zero. Deposit amounts hold one element, so the uint64 "+
			"list is a partly filled chunk."))

	out["definition"] = definitions

	// --- Locks.
	locks := []hashCase{{
		Name:     "charon_testdata_golden",
		Input:    must(json.Marshal(goldenLock)),
		LockHash: hex.EncodeToString(goldenLock.LockHash),
		Notes: "Charon's own v1.10.0 regression fixture, " +
			"cluster/testdata/cluster_lock_v1_10_0.json, unmodified. Its signatures " +
			"are random test bytes, so only the lock hash is meaningful here.",
	}}

	// --- A validator with no deposit data at all.
	noDepositDef := cluster.Definition{
		UUID:               "0194FDC2-FA2F-4CC0-81D3-FF12045B73C8",
		Name:               "no deposits",
		Version:            version,
		Timestamp:          "2026-07-29T12:00:00+00:00",
		NumValidators:      1,
		Threshold:          2,
		DKGAlgorithm:       "default",
		ForkVersion:        mustHex(forkVersion),
		Operators:          []cluster.Operator{operatorFor(0, true), operatorFor(1, true)},
		Creator:            cluster.Creator{Address: fmt.Sprintf("0x%040x", 0xc0ffee)},
		ValidatorAddresses: validatorAddresses(1),
		ConsensusProtocol:  "qbft",
		TargetGasLimit:     30000000,
	}

	locks = append(locks, lockCase("validator_without_deposit_data", cluster.Lock{
		Definition: noDepositDef,
		Validators: []cluster.DistValidator{{
			PubKey:              repeatByte(0xa1, 48),
			PubShares:           [][]byte{repeatByte(0xb1, 48), repeatByte(0xb2, 48)},
			BuilderRegistration: registrationFor(repeatByte(0xa1, 48), 30000000, 1655733600),
		}},
	}, "One validator whose partial_deposit_data is empty, so the deposit list "+
		"hashes its zero subtree with a zero length mixed in. The pubkeys here "+
		"are not real BLS keys; only the hash is meaningful.", nil))

	// --- Three validators, an odd list length at the lock level.
	threeValDef := noDepositDef
	threeValDef.Name = "three validators"
	threeValDef.NumValidators = 3
	threeValDef.ValidatorAddresses = validatorAddresses(3)
	threeValDef.DepositAmounts = []eth2p0.Gwei{32000000000}

	var threeVals []cluster.DistValidator
	for i := range 3 {
		pubkey := repeatByte(byte(0xa1+i), 48)
		threeVals = append(threeVals, cluster.DistValidator{
			PubKey:    pubkey,
			PubShares: [][]byte{repeatByte(byte(0xb1+i), 48), repeatByte(byte(0xc1+i), 48)},
			PartialDepositData: []cluster.DepositData{{
				PubKey:                pubkey,
				WithdrawalCredentials: repeatByte(byte(0xd1+i), 32),
				Amount:                32000000000,
				Signature:             repeatByte(byte(0xe1+i), 96),
			}},
			BuilderRegistration: registrationFor(pubkey, 30000000, 1655733600),
		})
	}

	locks = append(locks, lockCase("three_validators", cluster.Lock{
		Definition: threeValDef,
		Validators: threeVals,
	}, "Three validators, so the validator list's bottom layer is odd. Each has "+
		"exactly one partial deposit, the shape a full single deposit takes at "+
		"v1.8 and later.", nil))

	// --- A lock with real keys, signed for real.
	realDef := cluster.Definition{
		UUID:          "0194FDC2-FA2F-4CC0-81D3-FF12045B73C8",
		Name:          "real keys",
		Version:       version,
		Timestamp:     "2026-07-29T12:00:00+00:00",
		NumValidators: 1,
		Threshold:     3,
		DKGAlgorithm:  "default",
		ForkVersion:   mustHex(forkVersion),
		Operators: []cluster.Operator{
			operatorFor(0, true), operatorFor(1, true),
			operatorFor(2, true), operatorFor(3, true),
		},
		Creator: cluster.Creator{
			Address:         fmt.Sprintf("0x%040x", 0xc0ffee),
			ConfigSignature: repeatByte(0x30, 65),
		},
		ValidatorAddresses: validatorAddresses(1),
		DepositAmounts:     []eth2p0.Gwei{32000000000},
		ConsensusProtocol:  "qbft",
		TargetGasLimit:     30000000,
	}

	groupPubkey := must(tbls.SecretToPublicKey(tbls.PrivateKey(mustHex(groupSecretHex))))

	var (
		shares    []tbls.PrivateKey
		pubshares [][]byte
	)

	for _, shareHex := range blsShareHexes {
		share := tbls.PrivateKey(mustHex(shareHex))
		shares = append(shares, share)
		pubshare := must(tbls.SecretToPublicKey(share))
		pubshares = append(pubshares, pubshare[:])
	}

	realLock := cluster.Lock{
		Definition: must(realDef.SetDefinitionHashes()),
		Validators: []cluster.DistValidator{{
			PubKey:    groupPubkey[:],
			PubShares: pubshares,
			PartialDepositData: []cluster.DepositData{{
				PubKey:                groupPubkey[:],
				WithdrawalCredentials: mustHex(
					"010000000000000000000000000000000000000000000000000000000000dead"),
				Amount:    32000000000,
				Signature: repeatByte(0x55, 96),
			}},
			BuilderRegistration: registrationFor(groupPubkey[:], 30000000, 1655733600),
		}},
	}
	realLock = must(realLock.SetLockHash())

	// The lock's aggregate is a plain aggregate of one signature per share.
	var (
		shareSigs  []tbls.Signature
		blsPubkeys []tbls.PublicKey
	)

	for i, share := range shares {
		shareSigs = append(shareSigs, must(tbls.Sign(share, realLock.LockHash)))

		var pubkey tbls.PublicKey
		copy(pubkey[:], pubshares[i])
		blsPubkeys = append(blsPubkeys, pubkey)
	}

	realLock.SignatureAggregate = func() []byte {
		agg := must(tbls.Aggregate(shareSigs))

		return agg[:]
	}()

	if err := tbls.VerifyAggregate(blsPubkeys, tbls.Signature(realLock.SignatureAggregate),
		realLock.LockHash); err != nil {
		panic(fmt.Sprintf("charon rejects its own lock aggregate: %v", err))
	}

	// One node signature per operator, over the same lock hash.
	var nodePubkeys []string

	for _, secretHex := range nodeSecretHexes {
		privkey := k1.PrivKeyFromBytes(mustHex(secretHex))
		realLock.NodeSignatures = append(realLock.NodeSignatures,
			must(k1util.Sign(privkey, realLock.LockHash)))
		nodePubkeys = append(nodePubkeys,
			hex.EncodeToString(privkey.PubKey().SerializeCompressed()))
	}

	// Charon derives each node key from the operator's ENR, so check the ENRs in
	// this lock really do carry these keys before publishing it as a vector.
	for i, operator := range realLock.Operators {
		record := must(enr.Parse(operator.ENR))
		if hex.EncodeToString(record.PubKey.SerializeCompressed()) != nodePubkeys[i] {
			panic(fmt.Sprintf("operator %d ENR does not carry its node key", i))
		}

		verified := must(k1util.Verify65(record.PubKey, realLock.LockHash,
			realLock.NodeSignatures[i]))
		if !verified {
			panic(fmt.Sprintf("charon rejects its own node signature %d", i))
		}
	}

	locks = append(locks, hashCase{
		Name:        "real_keys_3_of_4",
		Input:       must(json.Marshal(realLock)),
		LockHash:    hex.EncodeToString(realLock.LockHash),
		NodePubkeys: nodePubkeys,
		Notes: "One validator with the 3-of-4 BLS sharing from bls_threshold.json. " +
			"signature_aggregate is a plain aggregate of the lock hash signed by all " +
			"four private shares, and charon's VerifyAggregate accepts it against the " +
			"four public shares. node_signatures are secp256k1 signatures of the same " +
			"lock hash by each operator's node key, and each operator's ENR really " +
			"carries that key, so charon verifies them from the ENRs alone. " +
			"node_pubkeys repeats those keys so an implementation that does not decode " +
			"ENRs can still check the signatures. The operator and creator EIP-712 " +
			"signatures are placeholder bytes: they are covered by the hashes but " +
			"charon's signing helpers for them are not exported.",
	})

	out["lock"] = locks

	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")
	if err := e.Encode(out); err != nil {
		panic(err)
	}
}
