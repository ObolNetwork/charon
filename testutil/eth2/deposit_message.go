package eth2

import (
	ssz "github.com/ferranbt/fastssz"

	"github.com/obolnetwork/charon/app/errors"
)

// DepositMessage contains the basic information necessary to activate a validator. The fields are
// hashed to get the DepositMessageRoot. This root is signed and the signature is added to DepositData.
type DepositMessage struct {
	PubKey                string `json:"pubkey"`
	Amount                uint64 `json:"amount"`
	WithdrawalCredentials string `json:"withdrawal_credentials"`
}

func (d DepositMessage) HashTreeRoot() ([32]byte, error) {
	b, err := ssz.HashWithDefaultHasher(d)
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "hash deposit message")
	}

	return b, nil
}

func (d DepositMessage) HashTreeRootWith(hh *ssz.Hasher) error {
	idx := hh.Index()

	// Field 0 'PubKey`
	hh.PutBytes([]byte(d.PubKey))

	// Field 1 'Amount'
	hh.PutUint64(d.Amount)

	// Field 2 'WithdrawalCredentials'
	hh.PutBytes([]byte(d.WithdrawalCredentials))

	hh.Merkleize(idx)

	return nil
}
