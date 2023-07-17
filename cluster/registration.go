// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cluster

import (
	"time"
)

// BuilderRegistration defines pre-generated signed validator builder registration to be sent to builder network.
type BuilderRegistration struct {
	Message   Registration `json:"message" ssz:"Composite" lock_hash:"0"`
	Signature []byte       `json:"signature" ssz:"Bytes96" lock_hash:"1"`
}

// Registration defines unsigned validator registration message.
type Registration struct {
	FeeRecipient []byte    `json:"fee_recipient"  ssz:"Bytes20" lock_hash:"0"`
	GasLimit     int       `json:"gas_limit"  ssz:"uint64" lock_hash:"1"`
	Timestamp    time.Time `json:"timestamp"  ssz:"uint64" lock_hash:"2"`
	PubKey       []byte    `json:"pubkey"  ssz:"Bytes48" lock_hash:"3"`
}

// builderRegistrationJSON is the json formatter of BuilderRegistration.
type builderRegistrationJSON struct {
	Message   registrationJSON `json:"message"`
	Signature ethHex           `json:"signature"`
}

// registrationJSON is the json formatter of Registration.
type registrationJSON struct {
	FeeRecipient ethHex `json:"fee_recipient"`
	GasLimit     int    `json:"gas_limit"`
	Timestamp    int    `json:"timestamp"`
	PubKey       ethHex `json:"pubkey"`
}

// registrationToJSON converts BuilderRegistration to builderRegistrationJSON.
func registrationToJSON(b BuilderRegistration) builderRegistrationJSON {
	return builderRegistrationJSON{
		Message: registrationJSON{
			FeeRecipient: b.Message.FeeRecipient,
			GasLimit:     b.Message.GasLimit,
			Timestamp:    int(b.Message.Timestamp.Unix()),
			PubKey:       b.Message.PubKey,
		},
		Signature: b.Signature,
	}
}

// registrationFromJSON converts registrationFromJSON to BuilderRegistration.
func registrationFromJSON(b builderRegistrationJSON) BuilderRegistration {
	return BuilderRegistration{
		Message: Registration{
			FeeRecipient: b.Message.FeeRecipient,
			GasLimit:     b.Message.GasLimit,
			Timestamp:    time.Unix(int64(b.Message.Timestamp), 0),
			PubKey:       b.Message.PubKey,
		},
		Signature: b.Signature,
	}
}
