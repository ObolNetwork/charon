// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package fetcher

import (
	"context"
	"fmt"
	"strings"

	eth2api "github.com/attestantio/go-eth2-client/api"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/core"
)

const obolToken = "OB"

func ClientGraffitiMappings() map[string]string {
	return map[string]string{
		"Teku":       "TK",
		"Lighthouse": "LH",
		"Lodestar":   "LS",
		"Prysm":      "PY",
		"Nimbus":     "NB",
		"Grandine":   "GD",
	}
}

type GraffitiBuilder struct {
	defaultGraffiti [32]byte
	graffiti        map[core.PubKey][32]byte
}

func NewGraffitiBuilder(pubkeys []core.PubKey, graffiti []string, disableClientAppend bool, eth2Cl eth2wrap.Client) (*GraffitiBuilder, error) {
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

	token := fetchBeaconNodeToken(eth2Cl)

	// Handle single graffiti case
	if len(graffiti) == 1 {
		singleGraffiti := graffiti[0]
		for _, pubkey := range pubkeys {
			builder.graffiti[pubkey] = buildGraffiti(singleGraffiti, token, disableClientAppend)
		}

		return builder, nil
	}

	// Handle multiple graffiti case
	for idx, pubkey := range pubkeys {
		builder.graffiti[pubkey] = buildGraffiti(graffiti[idx], token, disableClientAppend)
	}

	return builder, nil
}

// GetGraffiti returns the graffiti for a given pubkey or the default graffiti
func (g *GraffitiBuilder) GetGraffiti(pubkey core.PubKey) [32]byte {
	graffiti, ok := g.graffiti[pubkey]
	if !ok {
		return g.defaultGraffiti
	}

	return graffiti
}

// buildGraffiti builds the graffiti with optional Obol and beacon node token.
func buildGraffiti(graffiti string, token string, disableClientAppend bool) [32]byte {
	var graffitiBytes [32]byte

	if disableClientAppend {
		copy(graffitiBytes[:], graffiti)
	} else {
		copy(graffitiBytes[:], graffiti+obolToken+token)
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

// fetchBeaconNodeToken queries the beacon node for the product token
func fetchBeaconNodeToken(eth2Cl eth2wrap.Client) string {
	eth2Resp, err := eth2Cl.NodeVersion(context.Background(), &eth2api.NodeVersionOpts{})
	if err != nil {
		return ""
	}

	productToken := strings.Split(eth2Resp.Data, "/")[0]
	token, ok := ClientGraffitiMappings()[productToken]
	if !ok {
		return ""
	}

	return token
}
