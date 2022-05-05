package eth2

import (
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/cluster"
	"github.com/prysmaticlabs/prysm/v2/beacon-chain/core/signing"
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

// DepositMessage contains the basic information necessary to activate a validator. The fields are
// hashed to get the DepositMessageRoot. This root is signed and the signature is added to DepositData.
type DepositMessage struct {
	PubKey                string `json:"pubkey"`
	Amount                uint64 `json:"amount"`
	WithdrawalCredentials string `json:"withdrawal_credentials"`
}

// GenerateDepositData generates a deposit data object by populating the required fields.
func GenerateDepositData(def cluster.Definition, pubkey string) (DepositData, error) {
	amount := uint64(32000000000) // 32 Ether in Gwei
	depositMessage := DepositMessage{
		PubKey:                pubkey,
		Amount:                amount,
		WithdrawalCredentials: def.WithdrawalAddress,
	}

	domainType := [4]byte{1, 2, 3, 4}
	domain, err := signing.ComputeDomain(domainType, nil, nil)
	depositMessageRoot, err := signing.ComputeSigningRoot(depositMessage, domain)
	if err != nil {
		return DepositData{}, errors.Wrap(err, "compute domain")
	}

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
