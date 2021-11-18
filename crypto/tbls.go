package crypto

import (
	"fmt"

	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/share"
	"github.com/drand/kyber/util/random"
)

var BLSPairing = bls.NewBLS12381Suite()
var BLSKeyGroup = BLSPairing.G1()

// TBLSScheme wraps drand/share.PubPoly, the public commitments of a BLS secret sharing scheme
// required to recover BLS threshold signatures from signature shares.
type TBLSScheme struct {
	*share.PubPoly
	T int // number of key shares required to produce a signature
	N int // total number of key shares
}

// TBLSSchemeEncoded is the serialized form of TBLSScheme suitable for JSON encoding.
type TBLSSchemeEncoded struct {
	Commits [][]byte `json:"commitments"`
	N       int      `json:"n"`
}

// NewTBLSScheme creates the threshold BLS info struct
// given the public polynomial commitments and the total number of key shares.
func NewTBLSScheme(pubPoly *share.PubPoly, n int) (*TBLSScheme, error) {
	t := pubPoly.Threshold()
	if n < t {
		return nil, fmt.Errorf("n<t (%d<%d), aborting", n, t)
	}
	return &TBLSScheme{
		PubPoly: pubPoly,
		T:       t,
		N:       n,
	}, nil
}

// Encode serializes cryptographic data.
func (t *TBLSScheme) Encode() (*TBLSSchemeEncoded, error) {
	base, commits := t.Info()
	if !base.Equal(BLSKeyGroup.Point().Base()) {
		return nil, fmt.Errorf("pubkey commits do not use standard base point")
	}
	enc := &TBLSSchemeEncoded{N: t.N}
	enc.Commits = make([][]byte, len(commits))
	for i, c := range commits {
		var err error
		enc.Commits[i], err = c.MarshalBinary()
		if err != nil {
			return nil, err
		}
	}
	return enc, nil
}

// Decode reconstructs the threshold BLS commitment data.
func (t *TBLSSchemeEncoded) Decode() (*TBLSScheme, error) {
	if t.N < len(t.Commits) {
		return nil, fmt.Errorf("n<t (%d<%d), aborting", t.N, len(t.Commits))
	}
	points := make([]kyber.Point, len(t.Commits))
	for i, commit := range t.Commits {
		p := BLSKeyGroup.Point()
		if err := p.UnmarshalBinary(commit); err != nil {
			return nil, fmt.Errorf("invalid commit %d: %w", i, err)
		}
		points[i] = p
	}
	pubPoly := share.NewPubPoly(BLSKeyGroup, BLSKeyGroup.Point().Base(), points)
	return &TBLSScheme{
		PubPoly: pubPoly,
		T:       len(points),
		N:       t.N,
	}, nil
}

// NewTBLSPoly creates a new secret sharing polynomial for a BLS12-381 threshold signature scheme.
// Note that this function is not particularly secure as it constructs the root key in memory.
func NewTBLSPoly(t uint) (pri *share.PriPoly, pub *share.PubPoly) {
	stream := random.New()
	secret := BLSKeyGroup.Scalar().Pick(stream)
	pri = share.NewPriPoly(BLSKeyGroup, int(t), secret, stream)
	pub = pri.Commit(BLSKeyGroup.Point().Base())
	return
}
