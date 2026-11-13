// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package vcbundle renders the files a validator client consumes from a node's keystores and proposer config.
package vcbundle

import (
	"slices"
	"strings"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

// Client is a supported validator client.
type Client string

const (
	Teku       Client = "teku"
	Prysm      Client = "prysm"
	Lodestar   Client = "lodestar"
	Nimbus     Client = "nimbus"
	Lighthouse Client = "lighthouse"
)

var clients = []Client{Teku, Prysm, Lodestar, Nimbus, Lighthouse}

// ParseClient returns the client of the given name.
func ParseClient(s string) (Client, error) {
	c := Client(s)
	if !slices.Contains(clients, c) {
		return "", errors.New("unknown validator client, use one of: "+join(clients), z.Str("client", s))
	}

	return c, nil
}

// Part is a part of the bundle that can be written on its own.
type Part string

const (
	PartKeystores        Part = "keystores"
	PartProposerSettings Part = "proposer-settings"
	PartVCFlags          Part = "vc-flags"
)

// AllParts returns every part, in the order they are written.
func AllParts() []Part {
	return []Part{PartKeystores, PartProposerSettings, PartVCFlags}
}

// ParseParts returns the parts of the given names, deduplicated and in AllParts order.
func ParseParts(values []string) ([]Part, error) {
	if len(values) == 0 {
		return nil, errors.New("nothing to write, include at least one of: " + join(AllParts()))
	}

	for _, v := range values {
		if !slices.Contains(AllParts(), Part(v)) {
			return nil, errors.New("unknown bundle part, use any of: "+join(AllParts()), z.Str("part", v))
		}
	}

	var parts []Part

	for _, p := range AllParts() {
		if slices.Contains(values, string(p)) {
			parts = append(parts, p)
		}
	}

	return parts, nil
}

// join returns the values comma-separated.
func join[T ~string](values []T) string {
	var resp []string
	for _, v := range values {
		resp = append(resp, string(v))
	}

	return strings.Join(resp, ", ")
}
