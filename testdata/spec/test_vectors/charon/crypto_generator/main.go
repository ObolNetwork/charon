// Command zz_spec_vectors emits golden BLS12-381 and secp256k1 values for the
// distributed-validator-specs test vectors. Temporary generator, not part of charon.
package main

import (
	"encoding/hex"
	"encoding/json"
	"os"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/tbls"
)

// Fixed degree-2 polynomial shares over the BLS12-381 scalar field, threshold 3
// of 4, evaluated at x=1..4. Computed by the spec, so charon derives the public
// shares and signatures rather than choosing the secrets.
var shareHexes = map[int]string{
	1: "7113350cf92900d71d73cab886f244c12b589bfa98d2fd116e0d25265b82fedb",
	2: "2a14b99e273adba1640ac3ea6be7ab097b50c6f7e04292598513ebc615f2b4c8",
	3: "6c6d1daabbcbe076511a65f3b4a9204d03808d7d113ef8aff1520c541b1f5a8e",
	4: "5041128c63a114c57e2f00c44df2f4811c6ca7842bcb7816b2c786d26b08f02b",
}

const (
	groupSecretHex = "598d4150de5b558716e1ca4df2853d696c1cc47f3af380d9ac3db876ebd038c5"
	probeSecretHex = "0000000000000000000000000000000000000000000000000000000000000042"

	// The QBFT attester_pre_prepare signing root from qbft_hashing.json, so the
	// signature cases chain onto the hashing cases.
	qbftRootHex = "3a08c29e25a343e6e5a15c629a9b8ffa4f2b39294544f4ccea75dfe659e77f60"
	zeroRootHex = "0000000000000000000000000000000000000000000000000000000000000000"

	k1SecretHex = "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d"
)

func mustPrivKey(h string) tbls.PrivateKey {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}

	return tbls.PrivateKey(b)
}

type blsKey struct {
	SecretHex string `json:"secret_hex"`
	PubkeyHex string `json:"pubkey_hex"`
}

type partial struct {
	ShareIdx     int    `json:"share_idx"`
	ShareHex     string `json:"share_hex"`
	PubshareHex  string `json:"pubshare_hex"`
	SignatureHex string `json:"signature_hex"`
}

type k1Case struct {
	Name         string `json:"name"`
	HashHex      string `json:"hash_hex"`
	SignatureHex string `json:"signature_hex"`
	PubkeyHex    string `json:"pubkey_hex"`
}

func main() {
	out := map[string]any{}
	message := []byte("distributed-validator-specs test vector")

	// --- Byte order probe and the group key.
	var keys []blsKey
	for _, h := range []string{probeSecretHex, groupSecretHex} {
		pub, err := tbls.SecretToPublicKey(mustPrivKey(h))
		if err != nil {
			panic(err)
		}

		keys = append(keys, blsKey{h, hex.EncodeToString(pub[:])})
	}

	out["bls_keys"] = keys
	out["message_hex"] = hex.EncodeToString(message)

	// --- Group signature by the undivided secret.
	groupSig, err := tbls.Sign(mustPrivKey(groupSecretHex), message)
	if err != nil {
		panic(err)
	}

	out["group_signature_hex"] = hex.EncodeToString(groupSig[:])

	// --- Per-share public shares and partial signatures.
	var (
		partials  []partial
		sigsByIdx = map[int]tbls.Signature{}
		pubsByIdx = map[int]tbls.PublicKey{}
		secsByIdx = map[int]tbls.PrivateKey{}
	)
	for idx := 1; idx <= len(shareHexes); idx++ {
		secret := mustPrivKey(shareHexes[idx])
		secsByIdx[idx] = secret

		pub, err := tbls.SecretToPublicKey(secret)
		if err != nil {
			panic(err)
		}

		sig, err := tbls.Sign(secret, message)
		if err != nil {
			panic(err)
		}

		pubsByIdx[idx] = pub
		sigsByIdx[idx] = sig
		partials = append(partials, partial{
			ShareIdx:     idx,
			ShareHex:     shareHexes[idx],
			PubshareHex:  hex.EncodeToString(pub[:]),
			SignatureHex: hex.EncodeToString(sig[:]),
		})
	}

	out["partials"] = partials

	// --- Threshold aggregation over different quorums must give one signature.
	aggregates := map[string]string{}
	for name, subset := range map[string][]int{
		"1,2,3": {1, 2, 3},
		"2,3,4": {2, 3, 4},
		"1,3,4": {1, 3, 4},
		"1,2,4": {1, 2, 4},
	} {
		subsetSigs := map[int]tbls.Signature{}
		for _, idx := range subset {
			subsetSigs[idx] = sigsByIdx[idx]
		}

		agg, err := tbls.ThresholdAggregate(subsetSigs)
		if err != nil {
			panic(err)
		}

		aggregates[name] = hex.EncodeToString(agg[:])
	}

	out["threshold_aggregates"] = aggregates

	// --- Recovery of the group key from a quorum.
	recoveredSecret, err := tbls.RecoverSecret(
		map[int]tbls.PrivateKey{1: secsByIdx[1], 2: secsByIdx[2], 3: secsByIdx[3]}, 4, 3)
	if err != nil {
		panic(err)
	}

	recoveredPubkey, err := tbls.RecoverPubkey(
		map[int]tbls.PublicKey{1: pubsByIdx[1], 2: pubsByIdx[2], 3: pubsByIdx[3]})
	if err != nil {
		panic(err)
	}

	out["recovered_secret_hex"] = hex.EncodeToString(recoveredSecret[:])
	out["recovered_pubkey_hex"] = hex.EncodeToString(recoveredPubkey[:])

	// --- Plain (non-threshold) aggregation, as used for the cluster lock hash.
	plainAgg, err := tbls.Aggregate([]tbls.Signature{
		sigsByIdx[1], sigsByIdx[2], sigsByIdx[3], sigsByIdx[4],
	})
	if err != nil {
		panic(err)
	}

	out["plain_aggregate_hex"] = hex.EncodeToString(plainAgg[:])

	// --- secp256k1 in charon's R||S||V form.
	secretBytes, err := hex.DecodeString(k1SecretHex)
	if err != nil {
		panic(err)
	}

	privkey := k1.PrivKeyFromBytes(secretBytes)

	var k1Cases []k1Case
	for name, rootHex := range map[string]string{
		"qbft_attester_pre_prepare": qbftRootHex,
		"zero_hash":                 zeroRootHex,
	} {
		hash, err := hex.DecodeString(rootHex)
		if err != nil {
			panic(err)
		}

		sig, err := k1util.Sign(privkey, hash)
		if err != nil {
			panic(err)
		}

		recovered, err := k1util.Recover(hash, sig)
		if err != nil {
			panic(err)
		}

		k1Cases = append(k1Cases, k1Case{
			Name:         name,
			HashHex:      rootHex,
			SignatureHex: hex.EncodeToString(sig),
			PubkeyHex:    hex.EncodeToString(recovered.SerializeCompressed()),
		})
	}

	out["secp256k1"] = map[string]any{
		"secret_hex": k1SecretHex,
		"pubkey_hex": hex.EncodeToString(privkey.PubKey().SerializeCompressed()),
		"cases":      k1Cases,
	}

	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")
	if err := e.Encode(out); err != nil {
		panic(err)
	}
}
