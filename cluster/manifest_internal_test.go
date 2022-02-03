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

package cluster

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"net"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/crypto"
)

func TestManifestJSON(t *testing.T) {
	// Create new random manifest.
	_, pubPoly := crypto.NewTBLSPoly(3)
	manifest := Manifest{
		TSS:     crypto.TBLSScheme{PubPoly: pubPoly},
		Members: make([]crypto.BLSPubkeyHex, 4),
		ENRs:    make([]string, 4),
	}
	for i := range manifest.Members {
		_, pubkey := crypto.NewKeyPair()
		manifest.Members[i] = crypto.BLSPubkeyHex{KyberG1: pubkey}
	}
	for i := range manifest.ENRs {
		manifest.ENRs[i] = newRandomENR(t)
	}
	// Check pubkey.
	dvPubkey := manifest.Pubkey()
	require.True(t, pubPoly.Commit().Equal(dvPubkey))
	// Check if ENRs work.
	records, err := manifest.ParsedENRs()
	require.NoError(t, err)
	require.Len(t, records, len(manifest.ENRs))
	// Marshal to JSON.
	data, err := json.MarshalIndent(&manifest, "", "\t")
	require.NoError(t, err)
	t.Log(crypto.BLSPointToHex(dvPubkey))
	t.Log(string(data))
	// Unmarshal from JSON.
	var manifest2 Manifest
	err = json.Unmarshal(data, &manifest2)
	require.NoError(t, err)
	// Marshal to JSON (again).
	data2, err := json.Marshal(&manifest2)
	require.NoError(t, err)
	// Check if result is the same.
	require.Equal(t, &manifest, &manifest2)
	require.JSONEq(t, string(data), string(data2))
}

func newRandomENR(t *testing.T) (res string) {
	t.Helper() // test helper function should start from t.Helper()
	privkey, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	require.NoError(t, err)

	var r enr.Record

	r.Set(enr.IPv4(newRandomIP()))
	r.Set(enr.TCP(9877))
	r.SetSeq(1)

	err = enode.SignV4(&r, privkey)
	require.NoError(t, err)

	res, err = EncodeENR(&r)
	require.NoError(t, err)

	return
}

func newRandomIP() net.IP {
	buf := make([]byte, 4)
	_, err := rand.Read(buf)
	if err != nil {
		panic(err.Error())
	}

	return buf
}

func TestDecodeENR_Equal(t *testing.T) {
	randEnr := newRandomENR(t)
	t.Log(randEnr)
	record, err := DecodeENR(randEnr)
	require.NoError(t, err)
	require.NotNil(t, record)
	reencodedEnr, err := EncodeENR(record)
	require.Equal(t, randEnr, reencodedEnr)
	require.NoError(t, err)
	record2, err := DecodeENR(reencodedEnr)
	require.NoError(t, err)
	require.NotNil(t, record2)
	require.Equal(t, record, record2)
}

func TestDecodeENR_InvalidBase64(t *testing.T) {
	record, err := DecodeENR("enr:###")
	require.Error(t, err)
	require.Contains(t, err.Error(), "illegal base64 data at input byte 0")
	require.Nil(t, record)
}

func TestDecodeENR_InvalidRLP(t *testing.T) {
	record, err := DecodeENR("enr:AAAAAAAA")
	require.Error(t, err)
	require.Contains(t, err.Error(), "rlp: expected List")
	require.Nil(t, record)
}

func TestDecodeENR_Oversize(t *testing.T) {
	record, err := DecodeENR("enr:-IS4QBnEa-Oftjk7-sGRAY7IrvL5YjATdcHbqR5l2aXX2M25CiawfwaXh0k9hm98dCfdnqhz9mE-BfemFdjuL9KtHqgBgmlkgnY0gmlwhB72zxGJc2VjcDI1NmsxoQMaK8SspTrUgB8IYVI3qDgFYsHymPVsWlvIW477kxaKUIN0Y3CCJpUAAAA=")
	require.Error(t, err)
	require.Contains(t, err.Error(), "leftover garbage bytes in ENR")
	require.Nil(t, record)
}

func TestKnownClusters(t *testing.T) {
	// Load testdata cluster dir file.
	clustersDir := filepath.Join("testdata", "clusters")
	knownClusters, err := LoadKnownClustersFromDir(clustersDir)
	require.NoError(t, err)
	require.Len(t, knownClusters.Clusters(), 3)

	// Select cluster by pubkey.
	pubkey1, err := crypto.BLSPointFromHex("83def2bde67a3e02449ff109b4d53e0126222bdc7a911c3f5bec00a44e4ba9c548cd7c55e1ecdef549a270af11fccb9e")
	require.NoError(t, err)
	cluster1, ok := knownClusters.GetCluster(pubkey1)
	require.True(t, ok)
	require.Equal(t, pubkey1, cluster1.Pubkey())

	// Select nonexistent cluster by pubkey.
	pubkey2, err := crypto.BLSPointFromHex("8a1e64c5fac393516e59574c65030149d2ef76e70d8a98e8203eabfdeeccbb490a36e5d146a64692cb56aa6f5573e06e")
	require.NoError(t, err)
	cluster2, ok := knownClusters.GetCluster(pubkey2)
	require.False(t, ok)
	require.Nil(t, cluster2)
}
