// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package fetcher

import (
	"errors"
	"fmt"

	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/core"
)

const obolSignature = " OB"

type GraffitiBuilder struct {
	defaultGraffiti [32]byte
	graffiti        map[core.PubKey][32]byte
}

func NewGraffitiBuilder(pubkeys []core.PubKey, graffiti []string, disableClientAppend bool) (*GraffitiBuilder, error) {
	builder := &GraffitiBuilder{
		defaultGraffiti: defaultGraffiti(),
		graffiti:        make(map[core.PubKey][32]byte, len(pubkeys)),
	}

	// Handle nil graffiti
	if graffiti == nil {
		for _, pubkey := range pubkeys {
			builder.graffiti[pubkey] = builder.defaultGraffiti
		}

		return builder, nil
	}

	if len(graffiti) > 1 && len(graffiti) != len(pubkeys) {
		return nil, errors.New("graffiti length must match the number of validators or be a single value")
	}

	for _, g := range graffiti {
		if len(g) > 32 {
			return nil, errors.New("graffiti length is greater than 32 characters")
		}
	}

	// Handle single graffiti case
	if len(graffiti) == 1 {
		singleGraffiti := graffiti[0]
		for _, pubkey := range pubkeys {
			builder.graffiti[pubkey] = buildGraffiti(singleGraffiti, disableClientAppend)
		}

		return builder, nil
	}

	// Handle multiple graffiti case
	for idx, pubkey := range pubkeys {
		builder.graffiti[pubkey] = buildGraffiti(graffiti[idx], disableClientAppend)
	}

	return builder, nil
}

// getGraffiti returns the graffiti for a given pubkey or the default graffiti
func (g *GraffitiBuilder) GetGraffiti(pubkey core.PubKey) [32]byte {
	if graffiti, ok := g.graffiti[pubkey]; !ok {
		return g.defaultGraffiti
	} else {
		return graffiti
	}
}

// buildGraffiti builds the graffiti with optional obolSignature
func buildGraffiti(graffiti string, disableClientAppend bool) [32]byte {
	var graffitiBytes [32]byte
	if len(graffiti)+len(obolSignature) > 32 || disableClientAppend {
		copy(graffitiBytes[:], graffiti)
	} else {
		copy(graffitiBytes[:], graffiti+obolSignature)
	}

	return graffitiBytes
}

// defaultGraffiti returns the default graffiti
func defaultGraffiti() [32]byte {
	var graffitiBytes [32]byte
	commitSHA, _ := version.GitCommit()
	copy(graffitiBytes[:], fmt.Sprintf("charon/%v-%s", version.Version, commitSHA))

	return graffitiBytes
}
