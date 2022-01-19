package validatorapi

import eth2client "github.com/attestantio/go-eth2-client"

type Handler interface {
	eth2client.AttesterDutiesProvider
	eth2client.ProposerDutiesProvider
	// TODO(corver): Add more...
}
