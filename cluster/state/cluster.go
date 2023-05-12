// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package state

// Cluster represents the state of a cluster after applying a sequence of mutations.
type Cluster struct {
	Name         string
	Threshold    int
	DKGAlgorithm string
	ForkVersion  []byte
	Operators    []Operator
	Validators   []Validator
}

// Operator represents the operator of a node in the cluster.
type Operator struct {
	Address string
	ENR     string
}

// Validator represents a validator in the cluster.
type Validator struct {
	PubKey              []byte
	PubShares           [][]byte
	FeeRecipientAddress string
	WithdrawalAddress   string
}
