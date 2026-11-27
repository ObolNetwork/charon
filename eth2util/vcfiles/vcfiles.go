// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package vcfiles renders the files a validator client consumes from a node's keystores and proposer config:
// its keys in its layout, and its proposer settings and flags.
package vcfiles

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

// clientVersions are the client versions the files are made for. Teku reads builders from its proposer config file
// only from 26.11.0.
var clientVersions = map[Client]string{
	Teku:       "26.11.0",
	Prysm:      "v7.3.1",
	Lodestar:   "v1.50.1",
	Nimbus:     "v26.10.2",
	Lighthouse: "v8.3.3",
}

// ParseClient returns the client of the given name.
func ParseClient(s string) (Client, error) {
	c := Client(s)
	if !slices.Contains(clients, c) {
		return "", errors.New("unknown validator client, use one of: "+join(clients), z.Str("client", s))
	}

	return c, nil
}

// join returns the values comma-separated.
func join[T ~string](values []T) string {
	var resp []string
	for _, v := range values {
		resp = append(resp, string(v))
	}

	return strings.Join(resp, ", ")
}
