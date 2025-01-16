// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/signing"
	"github.com/obolnetwork/charon/tbls"
)

type exitConfig struct {
	BeaconNodeEndpoints   []string
	ValidatorPubkey       string
	ValidatorIndex        uint64
	ValidatorIndexPresent bool
	SkipBeaconNodeCheck   bool
	PrivateKeyPath        string
	ValidatorKeysDir      string
	LockFilePath          string
	PublishAddress        string
	PublishTimeout        time.Duration
	ExitEpoch             uint64
	FetchedExitPath       string
	PlaintextOutput       bool
	BeaconNodeTimeout     time.Duration
	ExitFromFilePath      string
	ExitFromFileDir       string
	Log                   log.Config
	All                   bool
	testnetConfig         eth2util.Network
}

func newExitCmd(cmds ...*cobra.Command) *cobra.Command {
	root := &cobra.Command{
		Use:   "exit",
		Short: "Exit a distributed validator.",
		Long:  "Sign and broadcast distributed validator exit messages using a remote API.",
	}

	root.AddCommand(cmds...)

	return root
}

type exitFlag int

const (
	publishAddress exitFlag = iota
	beaconNodeEndpoints
	privateKeyPath
	lockFilePath
	validatorKeysDir
	validatorPubkey
	exitEpoch
	exitFromFile
	exitFromDir
	beaconNodeTimeout
	fetchedExitPath
	publishTimeout
	validatorIndex
	all
	testnetName
	testnetForkVersion
	testnetChainID
	testnetGenesisTimestamp
	testnetCapellaHardFork
)

func (ef exitFlag) String() string {
	switch ef {
	case publishAddress:
		return "publish-address"
	case beaconNodeEndpoints:
		return "beacon-node-endpoints"
	case privateKeyPath:
		return "private-key-file"
	case lockFilePath:
		return "lock-file"
	case validatorKeysDir:
		return "validator-keys-dir"
	case validatorPubkey:
		return "validator-public-key"
	case exitEpoch:
		return "exit-epoch"
	case exitFromFile:
		return "exit-from-file"
	case exitFromDir:
		return "exit-from-dir"
	case beaconNodeTimeout:
		return "beacon-node-timeout"
	case fetchedExitPath:
		return "fetched-exit-path"
	case publishTimeout:
		return "publish-timeout"
	case validatorIndex:
		return "validator-index"
	case all:
		return "all"
	case testnetName:
		return "testnet-name"
	case testnetForkVersion:
		return "testnet-fork-version"
	case testnetChainID:
		return "testnet-chain-id"
	case testnetGenesisTimestamp:
		return "testnet-genesis-timestamp"
	case testnetCapellaHardFork:
		return "testnet-capella-hard-fork"
	default:
		return "unknown"
	}
}

type exitCLIFlag struct {
	flag     exitFlag
	required bool
}

func bindExitFlags(cmd *cobra.Command, config *exitConfig, flags []exitCLIFlag) {
	for _, f := range flags {
		flag := f.flag

		maybeRequired := func(s string) string {
			if f.required {
				return s + " [REQUIRED]"
			}

			return s
		}

		switch flag {
		case publishAddress:
			cmd.Flags().StringVar(&config.PublishAddress, publishAddress.String(), "https://api.obol.tech/v1", maybeRequired("The URL of the remote API."))
		case beaconNodeEndpoints:
			cmd.Flags().StringSliceVar(&config.BeaconNodeEndpoints, beaconNodeEndpoints.String(), nil, maybeRequired("Comma separated list of one or more beacon node endpoint URLs."))
		case privateKeyPath:
			cmd.Flags().StringVar(&config.PrivateKeyPath, privateKeyPath.String(), ".charon/charon-enr-private-key", maybeRequired("The path to the charon enr private key file. "))
		case lockFilePath:
			cmd.Flags().StringVar(&config.LockFilePath, lockFilePath.String(), ".charon/cluster-lock.json", maybeRequired("The path to the cluster lock file defining the distributed validator cluster."))
		case validatorKeysDir:
			cmd.Flags().StringVar(&config.ValidatorKeysDir, validatorKeysDir.String(), ".charon/validator_keys", maybeRequired("Path to the directory containing the validator private key share files and passwords."))
		case validatorPubkey:
			cmd.Flags().StringVar(&config.ValidatorPubkey, validatorPubkey.String(), "", maybeRequired("Public key of the validator to exit, must be present in the cluster lock manifest. If --validator-index is also provided, validator liveliness won't be checked on the beacon chain."))
		case exitEpoch:
			cmd.Flags().Uint64Var(&config.ExitEpoch, exitEpoch.String(), 162304, maybeRequired("Exit epoch at which the validator will exit, must be the same across all the partial exits."))
		case exitFromFile:
			cmd.Flags().StringVar(&config.ExitFromFilePath, exitFromFile.String(), "", maybeRequired("Retrieves a signed exit message from a pre-prepared file instead of --publish-address."))
		case exitFromDir:
			cmd.Flags().StringVar(&config.ExitFromFileDir, exitFromDir.String(), "", maybeRequired("Retrieves a signed exit messages from a pre-prepared files in a directory instead of --publish-address."))
		case beaconNodeTimeout:
			cmd.Flags().DurationVar(&config.BeaconNodeTimeout, beaconNodeTimeout.String(), 30*time.Second, maybeRequired("Timeout for beacon node HTTP calls."))
		case fetchedExitPath:
			cmd.Flags().StringVar(&config.FetchedExitPath, fetchedExitPath.String(), "./", maybeRequired("Path to store fetched signed exit messages."))
		case publishTimeout:
			cmd.Flags().DurationVar(&config.PublishTimeout, publishTimeout.String(), 5*time.Minute, "Timeout for publishing a signed exit to the publish-address API.")
		case validatorIndex:
			cmd.Flags().Uint64Var(&config.ValidatorIndex, validatorIndex.String(), 0, "Validator index of the validator to exit, the associated public key must be present in the cluster lock manifest. If --validator-public-key is also provided, validator existence won't be checked on the beacon chain.")
		case all:
			cmd.Flags().BoolVar(&config.All, all.String(), false, "Exit all currently active validators in the cluster.")
		case testnetName:
			cmd.Flags().StringVar(&config.testnetConfig.Name, testnetName.String(), "", "Name of the custom test network.")
		case testnetForkVersion:
			cmd.Flags().StringVar(&config.testnetConfig.GenesisForkVersionHex, testnetForkVersion.String(), "", "Genesis fork version of the custom test network (in hex).")
		case testnetChainID:
			cmd.Flags().Uint64Var(&config.testnetConfig.ChainID, "testnet-chain-id", 0, "Chain ID of the custom test network.")
		case testnetGenesisTimestamp:
			cmd.Flags().Int64Var(&config.testnetConfig.GenesisTimestamp, "testnet-genesis-timestamp", 0, "Genesis timestamp of the custom test network.")
		case testnetCapellaHardFork:
			cmd.Flags().StringVar(&config.testnetConfig.CapellaHardFork, "testnet-capella-hard-fork", "", "Capella hard fork version of the custom test network.")
		}

		if f.required {
			mustMarkFlagRequired(cmd, flag.String())
		}
	}
}

func eth2Client(ctx context.Context, u []string, timeout time.Duration, forkVersion [4]byte) (eth2wrap.Client, error) {
	cl, err := eth2wrap.NewMultiHTTP(timeout, forkVersion, u...)
	if err != nil {
		return nil, err
	}

	if _, err = cl.NodeVersion(ctx, &eth2api.NodeVersionOpts{}); err != nil {
		return nil, errors.Wrap(err, "connect to beacon node")
	}

	return cl, nil
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
