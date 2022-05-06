package eth2

import (
	ssz "github.com/ferranbt/fastssz"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/cluster"
)

// DepositData contains all the information required for activating validators on the Ethereum Network.
type DepositData struct {
	PubKey                string `json:"pubkey"`
	Amount                uint64 `json:"amount"`
	WithdrawalCredentials string `json:"withdrawal_credentials"`
	DepositDataRoot       string `json:"deposit_data_root"`
	DepositMessageRoot    string `json:"deposit_message_root"`
	Signature             string `json:"signature"`
	ForkVersion           string `json:"fork_version"`
	NetworkName           string `json:"network_name"`
}

// GenerateDepositData generates a deposit data object by populating the required fields.
func GenerateDepositData(def cluster.Definition, pubkey string) (DepositData, error) {
	amount := uint64(32000000000) // 32 Ether in Gwei
	depositMessage := DepositMessage{
		PubKey:                pubkey,
		Amount:                amount,
		WithdrawalCredentials: def.WithdrawalAddress,
	}
	depositMessageRoot := ""
	depositDataRoot := ""
	signature := "" // sign the depositMsgRoot with the bls key

	deposit_data := DepositData{
		PubKey:                pubkey,
		Amount:                amount,
		WithdrawalCredentials: def.WithdrawalAddress,
		DepositDataRoot:       depositDataRoot,
		DepositMessageRoot:    depositMessageRoot,
		Signature:             signature,
		ForkVersion:           def.ForkVersion,
		NetworkName:           forkVersionToNetwork(def.ForkVersion),
	}

	return deposit_data, nil
}

// forkVersionToNetwork returns the name of the ethereum network corresponding
// to a given fork version.
func forkVersionToNetwork(forkVersion string) string {
	switch forkVersion {
	case "00000000":
		return "mainnet"
	case "00001020":
		return "prater"
	case "60000069":
		return "kintsugi"
	case "70000069":
		return "kiln"
	case "00000064":
		return "gnosis"
	default:
		return "mainnet"
	}
}

func (d DepositData) HashTreeRoot() ([32]byte, error) {
	b, err := ssz.HashWithDefaultHasher(d)
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "hash deposit data")
	}

	return b, nil
}

func (d DepositData) HashTreeRootWith(hh *ssz.Hasher) error {
	idx := hh.Index()

	// Field 0 'PubKey`
	hh.PutBytes([]byte(d.PubKey))

	// Field 1 'Amount'
	hh.PutUint64(d.Amount)

	// Field 2 'WithdrawalCredentials'
	hh.PutBytes([]byte(d.WithdrawalCredentials))

	// Field 3 'DepositDataRoot'
	if len(d.DepositDataRoot) != 32 {
		return errors.Wrap(ssz.ErrBytesLength, "deposit data root")
	}
	hh.PutBytes([]byte(d.DepositDataRoot))

	// Field 4 'DepositMessageRoot'
	if len(d.DepositMessageRoot) != 32 {
		return errors.Wrap(ssz.ErrBytesLength, "deposit message root")
	}
	hh.PutBytes([]byte(d.DepositMessageRoot))

	// Field 5 'Signature'
	hh.PutBytes([]byte(d.Signature))

	// Field 6 'ForkVersion'
	hh.PutBytes([]byte(d.ForkVersion))

	// Field 7 'NetworkName'
	hh.PutBytes([]byte(d.NetworkName))

	hh.Merkleize(idx)

	return nil
}
