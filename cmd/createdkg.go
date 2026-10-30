// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	crand "crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
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

	testnetConfig eth2util.Network
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
	bindNetworkFlags(cmd.Flags(), &config.Network, &config.testnetConfig)

	wrapPreRunE(cmd, func(cmd *cobra.Command, _ []string) error {
		thresholdPresent := cmd.Flags().Lookup("threshold").Changed

		if thresholdPresent {
			if config.Threshold < minThreshold {
				return errors.New("threshold below minimum", z.Int("threshold", config.Threshold), z.Int("min", minThreshold))
			}

			if config.Threshold > len(config.OperatorENRs) {
				return errors.New("threshold exceeds number of nodes",
					z.Int("threshold", config.Threshold), z.Int("nodes", len(config.OperatorENRs)))
			}
		}

		if config.Publish {
			cmd.MarkFlagsOneRequired("operator-addresses", "operator-enrs")
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
	cmd.Flags().StringVar(&config.DKGAlgo, "dkg-algorithm", "default", "DKG algorithm to use; default, frost or pedersen.")
	cmd.Flags().IntSliceVar(&config.DepositAmounts, "deposit-amounts", nil, "List of partial deposit amounts (integers) in ETH. Values must sum up to at least 32ETH.")
	cmd.Flags().StringSliceVar(&config.OperatorENRs, "operator-enrs", nil, "Comma-separated list of each operator's Charon ENR address.")
	cmd.Flags().StringVar(&config.ConsensusProtocol, "consensus-protocol", "", "Preferred consensus protocol name for the cluster. Selected automatically when not specified.")
	cmd.Flags().UintVar(&config.TargetGasLimit, "target-gas-limit", 200000000, "Preferred target gas limit for transactions.")
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

	if err = validateDKGConfig(operatorsLen, conf.Network, conf.testnetConfig, conf.DepositAmounts, conf.ConsensusProtocol, conf.Compounding); err != nil {
		return err
	}

	conf.FeeRecipientAddrs, conf.WithdrawalAddrs, err = validateAddresses(conf.NumValidators, conf.FeeRecipientAddrs, conf.WithdrawalAddrs)
	if err != nil {
		return err
	}

	conf.FeeRecipientAddrs, conf.WithdrawalAddrs, err = checksumValidatorAddrs(ctx, conf.FeeRecipientAddrs, conf.WithdrawalAddrs, conf.Network, true)
	if err != nil {
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

	var forkVersion string
	if conf.testnetConfig.IsNonZero() {
		// Custom testnet config takes precedence (already registered in validateDKGConfig via validateNetworkConfig).
		forkVersion = conf.testnetConfig.GenesisForkVersionHex
	} else {
		forkVersion, err = eth2util.NetworkToForkVersion(conf.Network)
		if err != nil {
			return err
		}
	}

	var privKey *k1.PrivateKey

	creator := cluster.Creator{}

	// Populate creator field
	if conf.Publish {
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
	if err := eth1wrap.RunAndWait(ctx, eth1Cl); err != nil {
		return err
	}

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

// checksumAddress validates an Ethereum address and returns its EIP-55 checksummed form.
// The address must be "0x" followed by 40 hex characters. All-lowercase and all-uppercase hex
// is accepted (no checksum); mixed case must match the EIP-55 checksum exactly.
func checksumAddress(addr string) (string, error) {
	checksummed, err := eth2util.ChecksumAddress(addr)
	if err != nil {
		return "", err
	}

	hexPart := strings.TrimPrefix(addr, "0x")
	if hexPart != strings.ToLower(hexPart) && hexPart != strings.ToUpper(hexPart) && addr != checksummed {
		return "", errors.New("address does not match its EIP-55 checksum; use all-lowercase or the checksummed form",
			z.Str("addr", addr), z.Str("checksummed", checksummed))
	}

	return checksummed, nil
}

// checksumAddrs validates the provided addresses (see checksumAddress) of the given kind
// (e.g. "withdrawal" or "fee recipient") and returns their EIP-55 checksummed forms.
// The zero address on mainnet or gnosis is an error if rejectZero is set, otherwise a warning:
// it is legitimate when the generated deposit data is never used, e.g. split existing keys of
// validators that are already active.
func checksumAddrs(ctx context.Context, addrs []string, kind string, network string, rejectZero bool) ([]string, error) {
	resp := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		checksummed, err := checksumAddress(addr)
		if err != nil {
			return nil, errors.Wrap(err, "invalid "+kind+" address", z.Str("addr", addr))
		}

		if isMainOrGnosis(network) && checksummed == zeroAddress {
			if rejectZero {
				return nil, errors.New("zero "+kind+" address forbidden on this network", z.Str("network", network))
			}

			log.Warn(ctx, "Zero "+kind+" address on "+network+": only continue if the generated deposit data and registrations will never be used", nil, z.Str("network", network))
		}

		resp = append(resp, checksummed)
	}

	return resp, nil
}

// checksumValidatorAddrs validates and checksums both fee recipient and withdrawal addresses.
// A zero fee recipient only warns; a zero withdrawal address on mainnet or gnosis is an error
// if rejectZeroWithdrawal is set, otherwise a warning.
func checksumValidatorAddrs(ctx context.Context, feeRecipientAddrs, withdrawalAddrs []string, network string, rejectZeroWithdrawal bool) (checksummedFeeRecipients []string, checksummedWithdrawals []string, err error) {
	checksummedFeeRecipients, err = checksumAddrs(ctx, feeRecipientAddrs, "fee recipient", network, false)
	if err != nil {
		return nil, nil, err
	}

	checksummedWithdrawals, err = checksumAddrs(ctx, withdrawalAddrs, "withdrawal", network, rejectZeroWithdrawal)
	if err != nil {
		return nil, nil, err
	}

	return checksummedFeeRecipients, checksummedWithdrawals, nil
}

// validateDKGConfig returns an error if any of the provided config parameter is invalid.
func validateDKGConfig(numOperators int, network string, testnet eth2util.Network, depositAmounts []int, consensusProtocol string, compounding bool) error {
	// Don't allow cluster size to be less than 3.
	if numOperators < minNodes {
		return errors.New("number of operators is below minimum", z.Int("operators", numOperators), z.Int("min", minNodes))
	}

	if err := validateNetworkConfig(network, testnet); err != nil {
		return errors.Wrap(err, "unsupported network", z.Str("network", network))
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

func generateLaunchpadLink(configHash []byte, network string) string {
	var networkLink string

	//nolint:revive // `case "mainnet"` and `default` having same result is not an issue, it improves readability.
	switch network {
	case "mainnet":
		networkLink = ""
	case "hoodi":
		networkLink = "hoodi."
	case "sepolia":
		networkLink = "sepolia."
	default:
		networkLink = ""
	}

	return "https://" + networkLink + "launchpad.obol.org/dv#" + fmt.Sprintf("%#x", configHash)
}

func generateAPILink(configHash []byte) string {
	return "https://api.obol.tech/v1/definition/" + fmt.Sprintf("%#x", configHash)
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

	if len(conf.OperatorENRs) == 0 {
		log.Info(ctx, "Direct the Node Operators to: "+generateLaunchpadLink(def.ConfigHash, conf.Network)+" to review the cluster configuration and begin the distributed key generation ceremony.")
	} else {
		log.Info(ctx, "Distributed Key Generation configuration created. Run one of the following commands from the directories where the associated .charon/charon-enr-private-key(s) that match these ENRs are: "+
			"(Without docker): `charon dkg --definition-file="+generateAPILink(def.ConfigHash)+"` "+
			"(With docker): `docker run --rm -v \"$(pwd)/.charon:/opt/charon/.charon\" obolnetwork/charon:latest dkg --definition-file="+generateAPILink(def.ConfigHash)+"`")
	}

	return nil
}
