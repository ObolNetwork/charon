// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"bytes"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/state"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/eth2util/registration"
	"github.com/obolnetwork/charon/tbls"
)

// addValidatorsConfig is config for the `add-validators` command.
type addValidatorsConfig struct {
	Lockfile          string
	EnrPrivKeyfiles   []string
	NumVals           int
	WithdrawalAddrs   []string
	FeeRecipientAddrs []string

	TestConfig TestConfig
}

type TestConfig struct {
	Lock    *cluster.Lock
	P2PKeys []*k1.PrivateKey
}

func newAddValidatorsCmd(runFunc func(addValidatorsConfig) error) *cobra.Command {
	var config addValidatorsConfig

	cmd := &cobra.Command{
		Use:   "add-validators-solo",
		Short: "Creates and adds new validators to a solo distributed validator cluster",
		Long:  `Creates and adds new validators to a distributed validator cluster. It generates keys for the new validators and also generates a new cluster state file with the legacy_lock and add_validators mutations. It is executed by a solo operator cluster.`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFunc(config)
		},
	}

	bindAddValidatorsFlags(cmd, &config)

	return cmd
}

// bindAddValidatorsFlags binds command line flags for the `add-validators` command.
func bindAddValidatorsFlags(cmd *cobra.Command, config *addValidatorsConfig) {
	cmd.Flags().IntVar(&config.NumVals, "num-validators", 1, "The count of new distributed validators to add in the cluster.")
	cmd.Flags().StringVar(&config.Lockfile, "lock-file", ".charon/cluster-lock.json", "The path to the legacy cluster lock file defining distributed validator cluster.")
	cmd.Flags().StringSliceVar(&config.EnrPrivKeyfiles, "private-key-files", nil, "Comma separated list of paths to charon enr private key files. This should be in the same order as the operators, ie, first private key file should correspond to the first operator and so on.")
	cmd.Flags().StringSliceVar(&config.FeeRecipientAddrs, "fee-recipient-addresses", nil, "Comma separated list of Ethereum addresses of the fee recipient for each new validator. Either provide a single fee recipient address or fee recipient addresses for each validator.")
	cmd.Flags().StringSliceVar(&config.WithdrawalAddrs, "withdrawal-addresses", nil, "Comma separated list of Ethereum addresses to receive the returned stake and accrued rewards for each new validator. Either provide a single withdrawal address or withdrawal addresses for each validator.")
}

func runAddValidatorsSolo(conf addValidatorsConfig) (err error) {
	// Read lock file to load mutable cluster state.
	cState, err := loadClusterState(conf)
	if err != nil {
		return err
	}

	if err = validateConf(conf, cState.Operators); err != nil {
		return err
	}

	// If a single address is provided, use the same address for all the validators.
	if len(conf.FeeRecipientAddrs) == 1 {
		var feeRecipients, withdrawalAddrs []string
		for i := 0; i < conf.NumVals; i++ {
			feeRecipients = append(feeRecipients, conf.FeeRecipientAddrs[0])
			withdrawalAddrs = append(withdrawalAddrs, conf.WithdrawalAddrs[0])
		}

		conf.FeeRecipientAddrs = feeRecipients
		conf.WithdrawalAddrs = withdrawalAddrs
	}

	// Generate new validators
	var vals []state.Validator
	for i := 0; i < conf.NumVals; i++ {
		// Generate private/public keypair
		secret, err := tbls.GenerateSecretKey()
		if err != nil {
			return errors.Wrap(err, "generate secret key")
		}

		pubkey, err := tbls.SecretToPublicKey(secret)
		if err != nil {
			return errors.Wrap(err, "generate public key")
		}

		// Split private key and generate public keyshares
		shares, err := tbls.ThresholdSplit(secret, uint(len(cState.Operators)), uint(cState.Threshold))
		if err != nil {
			return errors.Wrap(err, "threshold split key")
		}

		var pubshares [][]byte
		for _, share := range shares {
			pubshare, err := tbls.SecretToPublicKey(share)
			if err != nil {
				return errors.Wrap(err, "generate public key")
			}

			pubshares = append(pubshares, pubshare[:])
		}

		feeRecipientAddr, err := eth2util.ChecksumAddress(conf.FeeRecipientAddrs[i])
		if err != nil {
			return errors.Wrap(err, "invalid fee recipient address")
		}

		withdrawalAddr, err := eth2util.ChecksumAddress(conf.WithdrawalAddrs[i])
		if err != nil {
			return errors.Wrap(err, "invalid withdrawal address")
		}

		// Generate builder registration
		builderReg, err := builderRegistration(secret, pubkey, feeRecipientAddr, cState.ForkVersion)
		if err != nil {
			return err
		}

		vals = append(vals, state.Validator{
			PubKey:              pubkey[:],
			PubShares:           pubshares,
			FeeRecipientAddress: feeRecipientAddr,
			WithdrawalAddress:   withdrawalAddr,
			BuilderRegistration: builderReg,
		})
	}

	// Perform a `gen_validators/v0.0.1` mutation using the newly created validators.
	genVals, err := state.NewGenValidators(cState.Hash, vals)
	if err != nil {
		return errors.Wrap(err, "generate validators")
	}

	genValsHash, err := genVals.Hash()
	if err != nil {
		return err
	}

	var (
		enrKeys   []*k1.PrivateKey
		approvals []state.SignedMutation
	)
	for _, enrKeyFile := range conf.EnrPrivKeyfiles {
		enrKey, err := k1util.Load(enrKeyFile)
		if err != nil {
			return errors.Wrap(err, "load enr private key")
		}

		enrKeys = append(enrKeys, enrKey)
	}

	if conf.TestConfig.Lock != nil {
		enrKeys = conf.TestConfig.P2PKeys
	}

	// Perform individual `node_approval/v0.0.1` mutation using each operator's enr private key.
	for _, enrKey := range enrKeys {
		approval, err := state.SignNodeApproval(genValsHash, enrKey)
		if err != nil {
			return err
		}

		approvals = append(approvals, approval)
	}

	// Perform a `node_approvals/v0.0.1` parallel composite mutation using above approvals.
	nodeApprovals, err := state.NewNodeApprovalsComposite(approvals)
	if err != nil {
		return errors.Wrap(err, "node approvals")
	}

	// Perform a `add_validators/v0.0.1` linear composite mutation using `gen_validators` and `node_approvals` mutations.
	addVals, err := state.NewAddValidators(genVals, nodeApprovals)
	if err != nil {
		return errors.Wrap(err, "add validators")
	}

	// Finally, perform a cluster transformation.
	_, err = addVals.Transform(cState)
	if err != nil {
		return errors.Wrap(err, "transform cluster state")
	}

	// TODO(xenowits): Write new cluster state to disk, see issue https://github.com/ObolNetwork/charon/issues/1887.

	return nil
}

// builderRegistration returns a builder registration object using the provided inputs.
func builderRegistration(secret tbls.PrivateKey, pubkey tbls.PublicKey, feeRecipientAddr string, forkVersion []byte) (state.BuilderRegistration, error) {
	timestamp, err := eth2util.ForkVersionToGenesisTime(forkVersion)
	if err != nil {
		return state.BuilderRegistration{}, errors.Wrap(err, "invalid fork version")
	}

	reg, err := registration.NewMessage(
		eth2p0.BLSPubKey(pubkey),
		feeRecipientAddr,
		registration.DefaultGasLimit,
		timestamp,
	)
	if err != nil {
		return state.BuilderRegistration{}, errors.Wrap(err, "create registration message")
	}

	sigRoot, err := registration.GetMessageSigningRoot(reg, eth2p0.Version(forkVersion))
	if err != nil {
		return state.BuilderRegistration{}, errors.Wrap(err, "registration signing root")
	}

	sig, err := tbls.Sign(secret, sigRoot[:])
	if err != nil {
		return state.BuilderRegistration{}, errors.Wrap(err, "sign registration root")
	}

	return state.BuilderRegistration{
		Message: state.Registration{
			FeeRecipient: reg.FeeRecipient[:],
			GasLimit:     int(reg.GasLimit),
			Timestamp:    timestamp,
			PubKey:       reg.Pubkey[:],
		},
		Signature: sig[:],
	}, nil
}

// loadClusterState returns the cluster state from the given file path.
func loadClusterState(conf addValidatorsConfig) (state.Cluster, error) {
	if conf.TestConfig.Lock != nil {
		return state.NewClusterFromLock(*conf.TestConfig.Lock)
	}

	clusterState, err := state.Load(conf.Lockfile, nil)
	if err != nil {
		return state.Cluster{}, errors.Wrap(err, "load cluster state")
	}

	return clusterState, nil
}

// validateConf returns an error if the provided validators config fails validation checks.
func validateConf(conf addValidatorsConfig, ops []state.Operator) error {
	if conf.NumVals <= 0 {
		return errors.New("insufficient validator count", z.Int("validators", conf.NumVals))
	}

	if len(conf.FeeRecipientAddrs) == 0 {
		return errors.New("empty fee recipient addresses")
	}

	if len(conf.WithdrawalAddrs) == 0 {
		return errors.New("empty withdrawal addresses")
	}

	if len(conf.FeeRecipientAddrs) != len(conf.WithdrawalAddrs) {
		return errors.New("fee recipient and withdrawal addresses lengths mismatch",
			z.Int("fee_recipients", len(conf.FeeRecipientAddrs)),
			z.Int("withdrawal_addresses", len(conf.WithdrawalAddrs)),
		)
	}

	privKeysCount := len(conf.EnrPrivKeyfiles)
	if conf.TestConfig.Lock != nil {
		privKeysCount = len(conf.TestConfig.P2PKeys)
	}
	if privKeysCount != len(ops) {
		return errors.New("insufficient enr private key files", z.Int("num_operators", len(ops)), z.Int("num_keyfiles", len(conf.EnrPrivKeyfiles)))
	}

	// Ensure ENR private keys are ordered by peer index.
	// TODO(xenowits): Add unit test for this.
	for i, op := range ops {
		var enrKey *k1.PrivateKey
		if conf.TestConfig.Lock != nil {
			enrKey = conf.TestConfig.P2PKeys[i]
		} else {
			key, err := k1util.Load(conf.EnrPrivKeyfiles[i])
			if err != nil {
				return errors.Wrap(err, "load enr private key")
			}
			enrKey = key
		}

		record, err := enr.Parse(op.ENR)
		if err != nil {
			return err
		}

		if !bytes.Equal(enrKey.PubKey().SerializeCompressed(), record.PubKey.SerializeCompressed()) {
			return errors.New("invalid order of enr private key files", z.Int("peer_index", i), z.Str("private_keyfile", conf.EnrPrivKeyfiles[i]))
		}
	}

	if conf.NumVals > 1 {
		// There can be a single address for n validators.
		if len(conf.FeeRecipientAddrs) == 1 {
			return nil
		}

		// Or, there can be n addresses for n validators.
		if conf.NumVals != len(conf.FeeRecipientAddrs) {
			return errors.New("count of validators and addresses mismatch", z.Int("num_addresses", len(conf.FeeRecipientAddrs)), z.Int("num_validators", conf.NumVals))
		}

		return nil
	}

	// There can only be a single address for a single validator.
	if len(conf.FeeRecipientAddrs) != 1 {
		return errors.New("count of validators and addresses mismatch", z.Int("num_addresses", len(conf.FeeRecipientAddrs)), z.Int("num_validators", conf.NumVals))
	}

	return nil
}
