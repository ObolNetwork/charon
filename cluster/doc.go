// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package cluster provides the cluster configuration API. It defines the `Definition` type that is
// the output of the Launchpad and `charon create dkg` commands.
// `Definition` is also the input to `charon dkg`. If defines the `Lock` type that is
// the output of the `charon dkg` and `charon create cluster` commands. `Lock` is also the input
// to `charon run` command.
//
//	launchpad.obol.net ─┐
//	                    ├─► cluster-definition.json ──► charon dkg ─┐
//	 charon create dkg ─┘                                           ├─► cluster-lock.json ──► charon run
//	                                         charon create cluster ─┘
package cluster
