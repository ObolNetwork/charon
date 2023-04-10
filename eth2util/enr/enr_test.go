// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package enr_test

import (
	"encoding/base64"
	"fmt"
	"net"
	"testing"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/eth2util/rlp"
	"github.com/obolnetwork/charon/testutil"
)

func TestParse(t *testing.T) {
	// Figure obtained from example cluster definition and public key verified with https://enr-viewer.com/.
	r, err := enr.Parse("enr:-Iu4QJyserRukhG0Vgi2csu7GjpHYUGufNEbZ8Q7ZBrcZUb0KqpL5QzHonkh1xxHlxatTxrIcX_IS5J3SEWR_sa0ptGAgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQMAUgEqczOjevyculnUIofhCj0DkgJudErM7qCYIvIkzIN0Y3CCDhqDdWRwgg4u")
	require.NoError(t, err)
	require.Equal(t,
		"0x030052012a7333a37afc9cba59d42287e10a3d0392026e744acceea09822f224cc",
		fmt.Sprintf("%#x", r.PubKey.SerializeCompressed()),
	)
	ip, ok := r.IP()
	require.True(t, ok)
	require.Equal(t, net.IPv4(127, 0, 0, 1).To4(), ip)

	tcp, ok := r.TCP()
	require.True(t, ok)
	require.Equal(t, 3610, tcp)

	udp, ok := r.UDP()
	require.True(t, ok)
	require.Equal(t, 3630, udp)
}

func TestEncodeDecode(t *testing.T) {
	privkey, err := k1.GeneratePrivateKey()
	require.NoError(t, err)

	r1, err := enr.New(privkey)
	require.NoError(t, err)

	r2, err := enr.Parse(r1.String())
	require.NoError(t, err)

	require.Equal(t, r1, r2)

	_, ok := r1.IP()
	require.False(t, ok)

	_, ok = r1.TCP()
	require.False(t, ok)
}

func TestIPTCP(t *testing.T) {
	privkey, err := k1.GeneratePrivateKey()
	require.NoError(t, err)

	expectIP := net.IPv4(1, 2, 3, 4)
	expectTCP := 8000
	expectUDP := 9000

	r1, err := enr.New(privkey, enr.WithIP(expectIP), enr.WithTCP(expectTCP), enr.WithUDP(expectUDP))
	require.NoError(t, err)

	ip, ok := r1.IP()
	require.True(t, ok)
	require.Equal(t, expectIP.To4(), ip)

	tcp, ok := r1.TCP()
	require.True(t, ok)
	require.Equal(t, expectTCP, tcp)

	udp, ok := r1.UDP()
	require.True(t, ok)
	require.Equal(t, expectUDP, udp)

	r2, err := enr.Parse(r1.String())
	require.NoError(t, err)

	ip, ok = r2.IP()
	require.True(t, ok)
	require.Equal(t, expectIP.To4(), ip)

	tcp, ok = r2.TCP()
	require.True(t, ok)
	require.Equal(t, expectTCP, tcp)

	udp, ok = r2.UDP()
	require.True(t, ok)
	require.Equal(t, expectUDP, udp)
}

func TestNew(t *testing.T) {
	privkey := testutil.GenerateInsecureK1Key(t, 0)

	r, err := enr.New(privkey)
	require.NoError(t, err)

	require.Equal(t, "enr:-HW4QEp-BLhP30tqTGFbR9n2PdUKWP9qc0zphIRmn8_jpm4BYkgekztXQaPA_znRW8RvNYHo0pUwyPEwUGGeZu26XlKAgmlkgnY0iXNlY3AyNTZrMaEDG4TFVnsSZECZXT7VqroFZdceGDRgSBn_nBf16dXdB48", r.String())
}

const (
	keyID = "id"
	valID = "v4"
)

func TestParseDuplicateKeys(t *testing.T) {
	kvs := map[string][]byte{
		keyID: []byte(valID),
	}
	r := duplicateRecord{kvs: kvs}

	_, err := enr.Parse(r.String())
	require.ErrorContains(t, err, "duplicate enr key found")
}

// duplicateRecord is a duplicate for enr.Record.
type duplicateRecord struct {
	kvs map[string][]byte
}

// String returns the base64 encoded string representation of the record.
func (r duplicateRecord) String() string {
	return "enr:" + base64.RawURLEncoding.EncodeToString(encodeElements(r.kvs))
}

// encodeElements returns the RLP encoding of a minimal set of record elements adding two duplicate keys.
func encodeElements(kvs map[string][]byte) []byte {
	const duplicateKey = "duplicate_key"

	var elements [][]byte
	elements = append(elements, []byte(keyID), kvs[keyID])

	// Append duplicate key and value pairs to encoded bytes list
	elements = append(elements, []byte(duplicateKey), testutil.RandomBytes32())
	elements = append(elements, []byte(duplicateKey), testutil.RandomBytes32())

	return rlp.EncodeBytesList(elements)
}
