package cluster

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"net"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/obolnetwork/charon/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	assert.True(t, pubPoly.Commit().Equal(dvPubkey))
	// Check if ENRs work.
	records, err := manifest.ParsedENRs()
	require.NoError(t, err)
	assert.Len(t, records, len(manifest.ENRs))
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
	assert.Equal(t, &manifest, &manifest2)
	assert.JSONEq(t, string(data), string(data2))
}

func newRandomENR(t *testing.T) (res string) {
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
	assert.Equal(t, randEnr, reencodedEnr)
	require.NoError(t, err)
	record2, err := DecodeENR(reencodedEnr)
	require.NoError(t, err)
	require.NotNil(t, record2)
	assert.Equal(t, record, record2)
}

func TestDecodeENR_InvalidBase64(t *testing.T) {
	record, err := DecodeENR("enr:###")
	assert.EqualError(t, err, "illegal base64 data at input byte 0")
	assert.Nil(t, record)
}

func TestDecodeENR_InvalidRLP(t *testing.T) {
	record, err := DecodeENR("enr:AAAAAAAA")
	assert.EqualError(t, err, "rlp: expected List")
	assert.Nil(t, record)
}

func TestDecodeENR_Oversize(t *testing.T) {
	record, err := DecodeENR("enr:-IS4QBnEa-Oftjk7-sGRAY7IrvL5YjATdcHbqR5l2aXX2M25CiawfwaXh0k9hm98dCfdnqhz9mE-BfemFdjuL9KtHqgBgmlkgnY0gmlwhB72zxGJc2VjcDI1NmsxoQMaK8SspTrUgB8IYVI3qDgFYsHymPVsWlvIW477kxaKUIN0Y3CCJpUAAAA=")
	assert.EqualError(t, err, "leftover garbage bytes in ENR")
	assert.Nil(t, record)
}

func TestKnownClusters(t *testing.T) {
	// Load test cluster dir file.
	_, srcPath, _, ok := runtime.Caller(0)
	require.True(t, ok)
	clustersDir := filepath.Join(filepath.Dir(srcPath), "tests", "clusters")
	knownClusters, err := LoadKnownClustersFromDir(clustersDir)
	require.NoError(t, err)
	require.NotNil(t, knownClusters)
	assert.Len(t, knownClusters.Clusters(), 3)
	// Select cluster by pubkey.
	pubkey1 := crypto.MustBLSPointFromHex("83def2bde67a3e02449ff109b4d53e0126222bdc7a911c3f5bec00a44e4ba9c548cd7c55e1ecdef549a270af11fccb9e")
	cluster1 := knownClusters.GetCluster(pubkey1)
	assert.NotNil(t, cluster1)
	// Select nonexistent cluster by pubkey.
	pubkey2 := crypto.MustBLSPointFromHex("8a1e64c5fac393516e59574c65030149d2ef76e70d8a98e8203eabfdeeccbb490a36e5d146a64692cb56aa6f5573e06e")
	cluster2 := knownClusters.GetCluster(pubkey2)
	assert.Nil(t, cluster2)
}
