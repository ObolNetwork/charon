// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package enr provides a minimal implementation of Ethereum Node Records (ENR).
package enr

import (
	"encoding/base64"
	"net"
	"sort"
	"strings"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/sha3"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util/rlp"
)

const (
	// keySecp256k1 is the key used to store the secp256k1 public key in the record.
	keySecp256k1 = "secp256k1"

	// keyID is the key used to store the identity scheme in the record, only v4 supported.
	keyID = "id"
	valID = "v4"

	// keyIP is the key used to store the IP v4 address in the record.
	keyIP = "ip"
	// keyTCP is the key used to store the TCP port in the record.
	keyTCP = "tcp"
	// keyUDP is the key used to store the UDP port in the record.
	keyUDP = "udp"
)

// Parse parses the given base64 encoded string into a record.
func Parse(enrStr string) (Record, error) {
	if !strings.HasPrefix(enrStr, "enr:") {
		return Record{}, errors.New("missing 'enr:' prefix")
	}

	// Ensure backwards compatibility with older versions with encoded ENR strings.
	// ENR strings in older versions of charon (<= v0.9.0) were base64 padded strings with "=" as the padding character.
	// Refer: https://github.com/ObolNetwork/charon/issues/970
	enrStr = strings.TrimRight(enrStr, "=")

	raw, err := base64.RawURLEncoding.DecodeString(enrStr[4:])
	if err != nil {
		return Record{}, errors.Wrap(err, "invalid base64 encoding")
	}

	elements, err := rlp.DecodeBytesList(raw)
	if err != nil {
		return Record{}, errors.Wrap(err, "invalid rlp encoding")
	}

	if len(elements) < 4 {
		return Record{}, errors.New("invalid enr record, too few elements")
	}
	if len(elements)%2 != 0 {
		return Record{}, errors.New("invalid enr record, odd number of elements")
	}

	r := Record{
		Signature: elements[0],
		kvs:       make(map[string][]byte),
	}

	for i := 2; i < len(elements); i += 2 {
		key, val := string(elements[i]), elements[i+1]
		if _, ok := r.kvs[key]; ok {
			return Record{}, errors.New("duplicate enr key found", z.Str("key", key))
		}

		r.kvs[key] = val

		switch key {
		case keySecp256k1:
			r.PubKey, err = k1.ParsePubKey(val)
			if err != nil {
				return Record{}, errors.Wrap(err, "invalid secp256k1 public key")
			}
		case keyID:
			if string(val) != valID {
				return Record{}, errors.New("non-v4 identity scheme not supported")
			}
		}
	}

	if r.PubKey == nil {
		return Record{}, errors.New("missing secp256k1 public key")
	}

	if err := verify(r.PubKey, r.Signature, rlp.EncodeBytesList(elements[1:])); err != nil {
		return Record{}, err
	}

	return r, nil
}

// Option is a function that sets a key-value pair in the record.
type Option func(elements map[string][]byte)

// WithIP returns an option that sets the IP address of the record.
func WithIP(ip net.IP) Option {
	return func(kvs map[string][]byte) {
		kvs[keyIP] = ip.To4()
	}
}

// WithTCP returns an option that sets the TCP port of the record.
func WithTCP(port int) Option {
	return func(kvs map[string][]byte) {
		kvs[keyTCP] = toBigEndian(port)
	}
}

// WithUDP returns an option that sets the TCP port of the record.
func WithUDP(port int) Option {
	return func(kvs map[string][]byte) {
		kvs[keyUDP] = toBigEndian(port)
	}
}

// New returns a new enr record for the given private key and provided options.
func New(privkey *k1.PrivateKey, opts ...Option) (Record, error) {
	kvs := map[string][]byte{
		keyID:        []byte(valID),
		keySecp256k1: privkey.PubKey().SerializeCompressed(),
	}

	for _, opt := range opts {
		opt(kvs)
	}

	sig, err := sign(privkey, kvs)
	if err != nil {
		return Record{}, err
	}

	return Record{
		PubKey:    privkey.PubKey(),
		Signature: sig,
		kvs:       kvs,
	}, nil
}

// Record represents an Ethereum Node Record.
type Record struct {
	// Node public key (identity).
	PubKey *k1.PublicKey
	// Signature of the record.
	Signature []byte

	kvs map[string][]byte
}

// IP returns the IP address of the record or false if not present.
func (r Record) IP() (net.IP, bool) {
	ip, ok := r.kvs[keyIP]
	return ip, ok
}

// TCP returns the TCP port of the record or false if not present.
func (r Record) TCP() (int, bool) {
	b, ok := r.kvs[keyTCP]
	return fromBigEndian(b), ok
}

// UDP returns the UDP port of the record or false if not present.
func (r Record) UDP() (int, bool) {
	b, ok := r.kvs[keyUDP]
	return fromBigEndian(b), ok
}

// String returns the base64 encoded string representation of the record.
func (r Record) String() string {
	return "enr:" + base64.RawURLEncoding.EncodeToString(encodeElements(r.Signature, r.kvs))
}

// encodeElements returns the RLP encoding of a minimal set of record elements including optional signature.
func encodeElements(signature []byte, kvs map[string][]byte) []byte {
	var keys []string
	for k := range kvs {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	elements := [][]byte{toBigEndian(0)} // Sequence number=0
	for _, key := range keys {
		elements = append(elements, []byte(key), kvs[key])
	}

	if len(signature) > 0 {
		elements = append([][]byte{signature}, elements...)
	}

	return rlp.EncodeBytesList(elements)
}

// sign returns a enr record signature.
func sign(privkey *k1.PrivateKey, kvs map[string][]byte) ([]byte, error) {
	h := sha3.NewLegacyKeccak256()
	_, _ = h.Write(encodeElements(nil, kvs))
	digest := h.Sum(nil)

	sig, err := k1util.Sign(privkey, digest)
	if err != nil {
		return nil, errors.Wrap(err, "sign enr")
	}

	return sig[:len(sig)-1], nil // remove v (recovery id)
}

// verify return an error if the record signature verification fails.
func verify(pubkey *k1.PublicKey, signature, rawExclSig []byte) error {
	h := sha3.NewLegacyKeccak256()
	h.Write(rawExclSig)
	digest := h.Sum(nil)

	if ok, err := k1util.Verify(pubkey, digest, signature); err != nil {
		return err
	} else if !ok {
		return errors.New("invalid enr signature")
	}

	return nil
}

// toBigEndian returns the big endian representation of the given integer without leading zeros.
func toBigEndian(i int) []byte {
	var resp []byte
	for i > 0 {
		resp = append([]byte{byte(i)}, resp...)
		i >>= 8
	}

	return resp
}

// fromBigEndian returns the integer encoded as big endian byte slice.
func fromBigEndian(b []byte) int {
	var x uint64
	for i := 0; i < len(b); i++ {
		x = x<<8 | uint64(b[i])
	}

	return int(x)
}
