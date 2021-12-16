package cluster

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
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
	// Marshal to JSON.
	data, err := json.MarshalIndent(&manifest, "", "\t")
	require.NoError(t, err)
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

func newRandomENR(t *testing.T) string {
	privkey, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	require.NoError(t, err)

	var r enr.Record
	r.Set(enr.IPv4(newRandomIP()))
	r.Set(enr.TCP(9877))
	r.SetSeq(1)
	err = enode.SignV4(&r, privkey)
	require.NoError(t, err)
	var buf bytes.Buffer
	err = r.EncodeRLP(&buf)
	require.NoError(t, err)
	return "enr:" + base64.URLEncoding.EncodeToString(buf.Bytes())
}

func newRandomIP() net.IP {
	buf := make([]byte, 4)
	_, err := rand.Read(buf)
	if err != nil {
		panic(err.Error())
	}
	return buf
}
