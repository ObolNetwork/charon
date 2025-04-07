// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	crand "crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"time"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth1wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/obolapi"
	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core/consensus/protocols"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/deposit"
	"github.com/obolnetwork/charon/eth2util/enr"
)

type createDKGConfig struct {
	OutputDir           string
	Name                string
	NumValidators       int
	Threshold           int
	FeeRecipientAddrs   []string
	WithdrawalAddrs     []string
	Network             string
	DKGAlgo             string
	DepositAmounts      []int // Amounts specified in ETH (integers).
	OperatorENRs        []string
	ConsensusProtocol   string
	TargetGasLimit      uint
	Compounding         bool
	ExecutionEngineAddr string
	Publish             bool
	PublishAddress      string
	OperatorsAddresses  []string
}

func newCreateDKGCmd(runFunc func(context.Context, createDKGConfig) error) *cobra.Command {
	var config createDKGConfig

	cmd := &cobra.Command{
		Use:   "dkg",
		Short: "Create the configuration for a new Distributed Key Generation ceremony using charon dkg",
		Long:  `Create a cluster definition file that will be used by all participants of a DKG.`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error { //nolint:revive // keep args variable name for clarity
			return runFunc(cmd.Context(), config)
		},
	}

	bindCreateDKGFlags(cmd, &config)

	wrapPreRunE(cmd, func(cmd *cobra.Command, _ []string) error {
		thresholdPresent := cmd.Flags().Lookup("threshold").Changed

		if thresholdPresent {
			if config.Threshold < minThreshold {
				return errors.New("threshold must be greater than 1", z.Int("threshold", config.Threshold), z.Int("min", minThreshold))
			}
			if config.Threshold > len(config.OperatorENRs) {
				return errors.New("threshold cannot be greater than number of operators",
					z.Int("threshold", config.Threshold), z.Int("operators", len(config.OperatorENRs)))
			}
		}

		if config.Publish {
			mustMarkFlagRequired(cmd, "publish-address")
			mustMarkFlagRequired(cmd, "operator-addresses")
		} else {
			mustMarkFlagRequired(cmd, "operator-enrs")
		}

		if len(config.OperatorENRs) != 0 && len(config.OperatorsAddresses) != 0 {
			return errors.New("cannot provide both --operator-enrs and --operator-addresses")
		}

		return nil
	})

	return cmd
}

func bindCreateDKGFlags(cmd *cobra.Command, config *createDKGConfig) {
	cmd.Flags().StringVar(&config.Name, "name", "", "Optional cosmetic cluster name")
	cmd.Flags().StringVar(&config.OutputDir, "output-dir", ".charon", "The folder to write the output cluster-definition.json file to.")
	cmd.Flags().IntVar(&config.NumValidators, "num-validators", 1, "The number of distributed validators the cluster will manage (32ETH+ staked for each).")
	cmd.Flags().IntVarP(&config.Threshold, "threshold", "t", 0, "Optional override of threshold required for signature reconstruction. Defaults to ceil(n*2/3) if zero. Warning, non-default values decrease security.")
	cmd.Flags().StringSliceVar(&config.FeeRecipientAddrs, "fee-recipient-addresses", nil, "Comma separated list of Ethereum addresses of the fee recipient for each validator. Either provide a single fee recipient address or fee recipient addresses for each validator.")
	cmd.Flags().StringSliceVar(&config.WithdrawalAddrs, "withdrawal-addresses", nil, "Comma separated list of Ethereum addresses to receive the returned stake and accrued rewards for each validator. Either provide a single withdrawal address or withdrawal addresses for each validator.")
	cmd.Flags().StringVar(&config.Network, "network", defaultNetwork, "Ethereum network to create validators for. Options: mainnet, goerli, sepolia, hoodi, holesky, gnosis, chiado.")
	cmd.Flags().StringVar(&config.DKGAlgo, "dkg-algorithm", "default", "DKG algorithm to use; default, frost")
	cmd.Flags().IntSliceVar(&config.DepositAmounts, "deposit-amounts", nil, "List of partial deposit amounts (integers) in ETH. Values must sum up to at least 32ETH.")
	cmd.Flags().StringSliceVar(&config.OperatorENRs, "operator-enrs", nil, "Comma-separated list of each operator's Charon ENR address.")
	cmd.Flags().StringVar(&config.ConsensusProtocol, "consensus-protocol", "", "Preferred consensus protocol name for the cluster. Selected automatically when not specified.")
	cmd.Flags().UintVar(&config.TargetGasLimit, "target-gas-limit", 36000000, "Preferred target gas limit for transactions.")
	cmd.Flags().BoolVar(&config.Compounding, "compounding", false, "Enable compounding rewards for validators by using 0x02 withdrawal credentials.")
	cmd.Flags().StringVar(&config.ExecutionEngineAddr, "execution-client-rpc-endpoint", "", "The address of the execution engine JSON-RPC API.")
	cmd.Flags().BoolVar(&config.Publish, "publish", false, "Creates an invitation to the DKG ceremony on the DV Launchpad. Terms and conditions apply.")
	cmd.Flags().StringVar(&config.PublishAddress, "publish-address", "https://api.obol.tech/v1", "The URL to publish the cluster to.")
	cmd.Flags().StringSliceVar(&config.OperatorsAddresses, "operator-addresses", nil, "Comma-separated list of each operator's Ethereum address.")
}

func mustMarkFlagRequired(cmd *cobra.Command, flag string) {
	if err := cmd.MarkFlagRequired(flag); err != nil {
		panic(err) // Panic is ok since this is unexpected and covered by unit tests.
	}
}

func runCreateDKG(ctx context.Context, conf createDKGConfig) (err error) {
	// Map prater to goerli to ensure backwards compatibility with older cluster definitions.
	if conf.Network == eth2util.Prater {
		conf.Network = eth2util.Goerli.Name
	}

	var operatorsLen int
	if len(conf.OperatorENRs) > 0 {
		operatorsLen = len(conf.OperatorENRs)
	} else {
		operatorsLen = len(conf.OperatorsAddresses)
	}

	if err = validateDKGConfig(operatorsLen, conf.Network, conf.DepositAmounts, conf.ConsensusProtocol, conf.Compounding); err != nil {
		return err
	}

	conf.FeeRecipientAddrs, conf.WithdrawalAddrs, err = validateAddresses(conf.NumValidators, conf.FeeRecipientAddrs, conf.WithdrawalAddrs)
	if err != nil {
		return err
	}

	if err = validateWithdrawalAddrs(conf.WithdrawalAddrs, conf.Network); err != nil {
		return err
	}

	version.LogInfo(ctx, "Charon create DKG starting")

	if _, err := os.Stat(path.Join(conf.OutputDir, "cluster-definition.json")); err == nil {
		return errors.New("existing cluster-definition.json found. Try again after deleting it")
	}

	var operators []cluster.Operator
	for i, opENR := range conf.OperatorENRs {
		_, err := enr.Parse(opENR)
		if err != nil {
			return errors.Wrap(err, "invalid ENR", z.Int("operator", i))
		}
		operators = append(operators, cluster.Operator{
			ENR: opENR,
		})
	}
	for i, opAddr := range conf.OperatorsAddresses {
		checksumAddr, err := eth2util.ChecksumAddress(opAddr)
		if err != nil {
			return errors.Wrap(err, "invalid operator address", z.Int("operator", i))
		}
		operators = append(operators, cluster.Operator{
			Address: checksumAddr,
		})
	}

	var safeThreshold int
	if len(conf.OperatorENRs) == 0 {
		safeThreshold = cluster.Threshold(len(conf.OperatorsAddresses))
	} else {
		safeThreshold = cluster.Threshold(len(conf.OperatorENRs))
	}
	if conf.Threshold == 0 {
		conf.Threshold = safeThreshold
	} else {
		log.Warn(ctx, "Non standard `--threshold` flag provided, this will affect cluster safety", nil, z.Int("threshold", conf.Threshold), z.Int("safe_threshold", safeThreshold))
	}

	forkVersion, err := eth2util.NetworkToForkVersion(conf.Network)
	if err != nil {
		return err
	}

	var privKey *k1.PrivateKey
	creator := cluster.Creator{}

	// Populate creator field
	if conf.Publish {
		// TODO(diogo): Should we store this private key in the disk?
		// Temporary creator address
		privKey, err = k1.GeneratePrivateKey()
		if err != nil {
			return errors.Wrap(err, "generate private key")
		}
		creator = cluster.Creator{
			Address: eth2util.PublicKeyToAddress(privKey.PubKey()),
		}
	}

	var opts []func(*cluster.Definition)
	opts = append(opts, cluster.WithDKGAlgorithm(conf.DKGAlgo))
	def, err := cluster.NewDefinition(
		conf.Name, conf.NumValidators, conf.Threshold,
		conf.FeeRecipientAddrs, conf.WithdrawalAddrs,
		forkVersion, creator, operators, conf.DepositAmounts,
		conf.ConsensusProtocol, conf.TargetGasLimit, conf.Compounding,
		crand.Reader, opts...)
	if err != nil {
		return err
	}
	if err := def.VerifyHashes(); err != nil {
		return err
	}

	// Generate creator signature after hashes have been populated
	if conf.Publish {
		def.Creator.ConfigSignature, err = cluster.SignClusterDefinitionHash(privKey, def)
		if err != nil {
			return errors.Wrap(err, "sign cluster definition")
		}
	}

	eth1Cl := eth1wrap.NewDefaultEthClientRunner(conf.ExecutionEngineAddr)
	go eth1Cl.Run(ctx)

	if !conf.Publish {
		if err := def.VerifySignatures(eth1Cl); err != nil {
			return err
		}
	}

	if conf.Publish {
		return publishPartialDefinition(ctx, conf, privKey, def)
	}

	b, err := json.MarshalIndent(def, "", " ")
	if err != nil {
		return errors.Wrap(err, "marshal definition")
	}

	// Best effort creation of output dir, but error when writing the file.
	_ = os.MkdirAll(conf.OutputDir, 0o755)

	//nolint:gosec // File needs to be read-only for everybody
	if err := os.WriteFile(path.Join(conf.OutputDir, "cluster-definition.json"), b, 0o444); err != nil {
		return errors.Wrap(err, "write definition")
	}

	return nil
}

// validateWithdrawalAddrs returns an error if any of the provided withdrawal addresses is invalid.
func validateWithdrawalAddrs(addrs []string, network string) error {
	for _, addr := range addrs {
		checksumAddr, err := eth2util.ChecksumAddress(addr)
		if err != nil {
			return errors.Wrap(err, "invalid withdrawal address", z.Str("addr", addr))
		} else if checksumAddr != addr {
			return errors.New("invalid checksummed address", z.Str("addr", addr))
		}

		// We cannot allow a zero withdrawal address on mainnet or gnosis.
		if isMainOrGnosis(network) && addr == zeroAddress {
			return errors.New("zero address forbidden on this network", z.Str("network", network))
		}
	}

	return nil
}

// validateDKGConfig returns an error if any of the provided config parameter is invalid.
func validateDKGConfig(numOperators int, network string, depositAmounts []int, consensusProtocol string, compounding bool) error {
	// Don't allow cluster size to be less than 3.
	if numOperators < minNodes {
		return errors.New("number of operators is below minimum", z.Int("operators", numOperators), z.Int("min", minNodes))
	}

	if !eth2util.ValidNetwork(network) {
		return errors.New("unsupported network", z.Str("network", network))
	}

	if len(depositAmounts) > 0 {
		amounts := deposit.EthsToGweis(depositAmounts)

		if err := deposit.VerifyDepositAmounts(amounts, compounding); err != nil {
			return err
		}
	}

	if len(consensusProtocol) > 0 && !protocols.IsSupportedProtocolName(consensusProtocol) {
		return errors.New("unsupported consensus protocol", z.Str("protocol", consensusProtocol))
	}

	return nil
}

// isMainOrGnosis returns true if the network is either mainnet or gnosis.
func isMainOrGnosis(network string) bool {
	return network == eth2util.Mainnet.Name || network == eth2util.Gnosis.Name
}

func publishPartialDefinition(ctx context.Context, conf createDKGConfig, privKey *k1.PrivateKey, def cluster.Definition) error {
	apiClient, err := obolapi.New(conf.PublishAddress, obolapi.WithTimeout(10*time.Second))
	if err != nil {
		return errors.Wrap(err, "create Obol API client")
	}

	sig, err := cluster.SignTermsAndConditions(privKey, def)
	if err != nil {
		return errors.Wrap(err, "sign terms")
	}

	err = apiClient.SignTermsAndConditions(ctx, def.Creator.Address, def.ForkVersion, sig)
	if err != nil {
		return errors.Wrap(err, "submit sign terms")
	}

	log.Info(ctx, "Creator successfully signed Obol's terms and conditions")

	err = apiClient.PublishDefinition(ctx, def, def.Creator.ConfigSignature)
	if err != nil {
		return errors.Wrap(err, "publish cluster definition")
	}

	log.Info(ctx, "Cluster Invitation Prepared")
	log.Info(ctx, "Direct the Node Operators to: https://launchpad.obol.org/dv#"+fmt.Sprintf("%#x", def.ConfigHash)+" to review the cluster configuration and begin the distributed key generation ceremony.")

	return nil
}
