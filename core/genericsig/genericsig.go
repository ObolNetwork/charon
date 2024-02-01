package genericsig

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"net/http"
	"strings"
	"sync"
)

func hexStrToBytes(s string) ([]byte, error) {
	if strings.HasPrefix(s, "0x") {
		return nil, errors.New("string doesn't begin with 0x")
	}

	s = s[2:]

	sb, err := hex.DecodeString(s)
	if err != nil {
		return nil, errors.Wrap(err, "hex decode")
	}

	return sb, nil
}

type genericSignatureJSON struct {
	Hash            string `json:"hash"`
	Signature       string `json:"signature"`
	ValidatorPubkey string `json:"validator_pubkey"`
}

type genericSignature struct {
	Hash            []byte         `json:"hash"`
	Signature       tbls.Signature `json:"signature"`
	ValidatorPubkey tbls.PublicKey `json:"validator_pubkey"`
}

func (g *genericSignature) UnmarshalJSON(bytes []byte) error {
	var gj genericSignatureJSON

	if err := json.Unmarshal(bytes, &gj); err != nil {
		return err
	}

	// TODO(gsora): add size checks maybe?

	hashBytes, err := hexStrToBytes(gj.Hash)
	if err != nil {
		return err
	}

	rawSigBytes, err := hexStrToBytes(gj.Signature)
	if err != nil {
		return err
	}

	sigBytes, err := tblsconv.SignatureFromBytes(rawSigBytes)
	if err != nil {
		return errors.Wrap(err, "bad signature")
	}

	rawPubkeyBytes, err := hexStrToBytes(gj.ValidatorPubkey)
	if err != nil {
		return err
	}

	pubkeyBytes, err := tblsconv.PubkeyFromBytes(rawPubkeyBytes)
	if err != nil {
		return errors.Wrap(err, "bad validator pubkey")
	}

	g.Hash = hashBytes
	g.Signature = sigBytes
	g.ValidatorPubkey = pubkeyBytes

	return nil
}

type fullSignatureJSON struct {
	Signature string `json:"signature"`
}

type fullSignature struct {
	Signature tbls.Signature `json:"signature"`
}

func (f fullSignature) MarshalJSON() ([]byte, error) {
	fStr := "0x" + hex.EncodeToString(f.Signature[:])

	ret := fullSignatureJSON{Signature: fStr}

	return json.Marshal(ret)
}

type GenericSignature struct {
	store      map[tbls.PublicKey]map[string]tbls.Signature
	storeMutex sync.RWMutex

	parsigDBStoreInternal func(context.Context, core.Duty, core.ParSignedDataSet) error
}

func (gs *GenericSignature) storeFullSignatures(ctx context.Context, duty core.Duty, data core.SignedDataSet) error {
	if duty.Type != core.DutyGenericSignature {
		return errors.New(
			"wrong duty type",
			z.Str("expected", core.DutyGenericSignature.String()),
			z.Str("got", duty.String()),
		)
	}

	gs.storeMutex.Lock()
	defer gs.storeMutex.Unlock()

	for pubKey, content := range data {
		gs.
	}
}

func (gs *GenericSignature) storePartialSignature(rw http.ResponseWriter, r *http.Request) {
	// TODO(gsora): get the genericSignature object from r, and send it to parsigDB
}

func (gs *GenericSignature) getFullSignature(rw http.ResponseWriter, r *http.Request) {
	gs.storeMutex.RLock()
	defer gs.storeMutex.RUnlock()

	// TODO(gsora): get Authorization header, validator pubkey, hash from path
	// check k1Sig(validator pubkey+hash) comes from the configured Charon identity key
	// check that there's data for gs.store[validator pubkey][hash]
	// if yes, return a fullSignature object with that inside
}
