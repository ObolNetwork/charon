// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package fetcher

import (
	"errors"
	"fmt"
	"slices"

	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/core"
)

const obolSignature = " OB"

// GraffitiFunc is a type that describes a function that returns a graffiti for a validator.
type GraffitiFunc func(pubkeys []core.PubKey, pubkey core.PubKey, graffiti []string, disable bool) [32]byte

// GetGraffitiFunc returns a GraffitiFunc based on the number of validators and CLI graffiti flags provided.
func GetGraffitiFunc(pubkeys []core.PubKey, graffiti []string, disableClientAppend bool) (GraffitiFunc, error) {
	if graffiti == nil {
		return getDefaultGraffiti, nil
	}

	if len(graffiti) > len(pubkeys) {
		return nil, errors.New("graffiti length is greater than the number of validators")
	}

	for _, g := range graffiti {
		if len(g) > 32 {
			return nil, errors.New("graffiti length is greater than 32 characters")
		}
	}

	if len(graffiti) == 1 {
		if len(graffiti[0])+len(obolSignature) > 32 || disableClientAppend {
			return getEqualGraffitiWithoutAppend, nil
		}

		return getEqualGraffitiWithAppend, nil
	}

	return getGraffitiPerValidator, nil
}

// getDefaultGraffiti returns a graffiti with the version and commit hash.
func getDefaultGraffiti(pubkeys []core.PubKey, pubkey core.PubKey, graffiti []string, _ bool) [32]byte {
	var graffitiBytes [32]byte
	commitSHA, _ := version.GitCommit()
	copy(graffitiBytes[:], fmt.Sprintf("charon/%v-%s", version.Version, commitSHA))

	return graffitiBytes
}

// getEqualGraffitiWithAppend returns a graffiti with the first graffiti string and Obol appended.
func getEqualGraffitiWithAppend(pubkeys []core.PubKey, pubkey core.PubKey, graffiti []string, _ bool) [32]byte {
	var graffitiBytes [32]byte
	copy(graffitiBytes[:], graffiti[0]+obolSignature)

	return graffitiBytes
}

// getEqualGraffitiWithoutAppend returns a graffiti with the first graffiti string.
func getEqualGraffitiWithoutAppend(pubkeys []core.PubKey, pubkey core.PubKey, graffiti []string, _ bool) [32]byte {
	var graffitiBytes [32]byte
	copy(graffitiBytes[:], graffiti[0])

	return graffitiBytes
}

// getGraffitiPerValidator returns a graffiti based on the validator's public key.
func getGraffitiPerValidator(pubkeys []core.PubKey, pubkey core.PubKey, graffiti []string, disableClientAppend bool) [32]byte {
	var graffitiBytes [32]byte

	idx := slices.Index(pubkeys, pubkey)
	if idx == -1 {
		return getDefaultGraffiti(pubkeys, pubkey, graffiti, disableClientAppend)
	}

	if len(graffiti[idx])+len(obolSignature) > 32 || disableClientAppend {
		copy(graffitiBytes[:], graffiti[idx])
	} else {
		copy(graffitiBytes[:], graffiti[idx]+obolSignature)
	}

	return graffitiBytes
}
