// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"time"

	eth2http "github.com/attestantio/go-eth2-client/http"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/eth2util/signing"
	"github.com/obolnetwork/charon/tbls"
)

type exitConfig struct {
	BeaconNodeURL   string
	ValidatorAddr   string
	DataDir         string
	ObolAPIEndpoint string
	ExitEpoch       uint64

	PlaintextOutput bool

	Log log.Config
}

func newExitCmd(cmds ...*cobra.Command) *cobra.Command {
	root := &cobra.Command{
		Use:   "exit",
		Short: "Exit a distributed validator.",
		Long:  "Exit a distributed validator through the Obol API.",
	}

	root.AddCommand(cmds...)

	return root
}

func bindGenericExitFlags(cmd *cobra.Command, config *exitConfig) {
	cmd.Flags().StringVar(&config.ObolAPIEndpoint, "obol-api-endpoint", "https://api.obol.tech", "Endpoint of the Obol API instance.")
	cmd.Flags().StringVar(&config.BeaconNodeURL, "beacon-node-url", "", "Beacon node URL.")
	cmd.Flags().StringVar(&config.DataDir, "data-dir", ".charon", "The directory where charon will read lock file and partial validator keys.")

	mustMarkFlagRequired(cmd, "beacon-node-url")
}

func bindExitRelatedFlags(cmd *cobra.Command, config *exitConfig) {
	cmd.Flags().StringVar(&config.ValidatorAddr, "validator-address", "", "Validator to exit, must be present in the cluster lock manifest.")
	cmd.Flags().Uint64Var(&config.ExitEpoch, "exit-epoch", 162304, "Exit epoch at which the validator will exit, must be the same across all the partial exits.")

	mustMarkFlagRequired(cmd, "validator-address")
}

func eth2Client(ctx context.Context, u string) (eth2wrap.Client, error) {
	bnHTTPClient, err := eth2http.New(ctx,
		eth2http.WithAddress(u),
		eth2http.WithLogLevel(1), // zerolog.InfoLevel
	)
	if err != nil {
		return nil, errors.Wrap(err, "can't connect to beacon node")
	}

	bnClient := bnHTTPClient.(*eth2http.Service)

	return eth2wrap.AdaptEth2HTTP(bnClient, 10*time.Second), nil
}

// signExit signs a voluntary exit message for valIdx with the given keyShare.
func signExit(ctx context.Context, eth2Cl eth2wrap.Client, valIdx eth2p0.ValidatorIndex, keyShare tbls.PrivateKey, exitEpoch eth2p0.Epoch) (eth2p0.SignedVoluntaryExit, error) {
	exit := &eth2p0.VoluntaryExit{
		Epoch:          exitEpoch,
		ValidatorIndex: valIdx,
	}

	sigData, err := sigDataForExit(ctx, *exit, eth2Cl, exitEpoch)
	if err != nil {
		return eth2p0.SignedVoluntaryExit{}, errors.Wrap(err, "exit hash tree root")
	}

	sig, err := tbls.Sign(keyShare, sigData[:])
	if err != nil {
		return eth2p0.SignedVoluntaryExit{}, errors.Wrap(err, "signing error")
	}

	return eth2p0.SignedVoluntaryExit{
		Message:   exit,
		Signature: eth2p0.BLSSignature(sig),
	}, nil
}

// sigDataForExit returns the hash tree root for the given exit message, at the given exit epoch.
func sigDataForExit(ctx context.Context, exit eth2p0.VoluntaryExit, eth2Cl eth2wrap.Client, exitEpoch eth2p0.Epoch) ([32]byte, error) {
	sigRoot, err := exit.HashTreeRoot()
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "exit hash tree root")
	}

	domain, err := signing.GetDomain(ctx, eth2Cl, signing.DomainExit, exitEpoch)
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "get domain")
	}

	sigData, err := (&eth2p0.SigningData{ObjectRoot: sigRoot, Domain: domain}).HashTreeRoot()
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "signing data hash tree root")
	}

	return sigData, nil
}
