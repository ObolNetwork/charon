// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"bytes"
	"context"
	"encoding/json"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/state"
	pbv1 "github.com/obolnetwork/charon/cluster/statepb/v1"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/eth2util/registration"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
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

// TestConfig defines additional test-only config.
type TestConfig struct {
	// Lock provides the lock explicitly, skips loading from disk.
	Lock *cluster.Lock
	// P2PKeys provides the p2p private keys explicitly, skips loading keystores from disk.
	P2PKeys []*k1.PrivateKey
}

func newAddValidatorsCmd(runFunc func(context.Context, addValidatorsConfig) error) *cobra.Command {
	var config addValidatorsConfig

	cmd := &cobra.Command{
		Use:   "add-validators-solo",
		Short: "Creates and adds new validators to a solo distributed validator cluster",
		Long:  `Creates and adds new validators to a distributed validator cluster. It generates keys for the new validators and also generates a new cluster state file with the legacy_lock and add_validators mutations. It is executed by a solo operator cluster.`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFunc(cmd.Context(), config)
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

func runAddValidatorsSolo(_ context.Context, conf addValidatorsConfig) (err error) {
	// Read lock file to load mutable cluster state.
	cState, err := loadClusterState(conf)
	if err != nil {
		return err
	}

	if err = validateConf(conf, len(cState.Operators)); err != nil {
		return errors.Wrap(err, "validate config")
	}

	p2pKeys, err := getP2PKeys(conf)
	if err != nil {
		return errors.Wrap(err, "load p2p keys")
	}

	if err := validateP2PKeysOrder(p2pKeys, cState.Operators); err != nil {
		return err
	}

	// If a single address is provided, use the same address for all the validators.
	if len(conf.FeeRecipientAddrs) == 1 {
		conf.FeeRecipientAddrs = repeatAddr(conf.FeeRecipientAddrs[0], conf.NumVals)
		conf.WithdrawalAddrs = repeatAddr(conf.WithdrawalAddrs[0], conf.NumVals)
	}

	vals, err := genNewVals(len(cState.Operators), int(cState.Threshold), cState.ForkVersion, conf)
	if err != nil {
		return err
	}

	// Perform a `gen_validators/v0.0.1` mutation using the newly created validators.
	genVals, err := state.NewGenValidators(cState.Hash, vals)
	if err != nil {
		return errors.Wrap(err, "generate validators")
	}

	genValsHash, err := state.Hash(genVals)
	if err != nil {
		return errors.Wrap(err, "hash gen vals")
	}

	var approvals []*pbv1.SignedMutation
	for _, p2pKey := range p2pKeys {
		// Perform individual `node_approval/v0.0.1` mutation using each operator's enr private key.
		approval, err := state.SignNodeApproval(genValsHash, p2pKey)
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
	_, err = state.Transform(cState, addVals)
	if err != nil {
		return errors.Wrap(err, "transform cluster state")
	}

	// TODO(xenowits): Write new cluster state to disk, see issue https://github.com/ObolNetwork/charon/issues/1887.

	return nil
}

// builderRegistration returns a builder registration object using the provided inputs.
func builderRegistration(secret tbls.PrivateKey, pubkey tbls.PublicKey, feeRecipientAddr string, forkVersion []byte) (*eth2v1.SignedValidatorRegistration, error) {
	timestamp, err := eth2util.ForkVersionToGenesisTime(forkVersion)
	if err != nil {
		return nil, errors.Wrap(err, "invalid fork version")
	}

	reg, err := registration.NewMessage(
		eth2p0.BLSPubKey(pubkey),
		feeRecipientAddr,
		registration.DefaultGasLimit,
		timestamp,
	)
	if err != nil {
		return nil, errors.Wrap(err, "create registration message")
	}

	sigRoot, err := registration.GetMessageSigningRoot(reg, eth2p0.Version(forkVersion))
	if err != nil {
		return nil, errors.Wrap(err, "registration signing root")
	}

	sig, err := tbls.Sign(secret, sigRoot[:])
	if err != nil {
		return nil, errors.Wrap(err, "sign registration root")
	}

	return &eth2v1.SignedValidatorRegistration{
		Message:   reg,
		Signature: tblsconv.SigToETH2(sig),
	}, nil
}

// loadClusterState returns the cluster state from the given file path.
func loadClusterState(conf addValidatorsConfig) (*pbv1.Cluster, error) {
	if conf.TestConfig.Lock != nil {
		return state.NewClusterFromLock(*conf.TestConfig.Lock)
	}

	verifyLock := func(lock cluster.Lock) error {
		if err := lock.VerifyHashes(); err != nil {
			return errors.Wrap(err, "cluster lock hash verification failed")
		}

		if err := lock.VerifySignatures(); err != nil {
			return errors.Wrap(err, "cluster lock signature verification failed")
		}

		return nil
	}

	clusterState, err := state.Load(conf.Lockfile, verifyLock)
	if err != nil {
		return nil, errors.Wrap(err, "load cluster state")
	}

	return clusterState, nil
}

// validateConf returns an error if the provided validators config fails validation checks.
func validateConf(conf addValidatorsConfig, numOps int) error {
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
	if len(conf.TestConfig.P2PKeys) > 0 {
		privKeysCount = len(conf.TestConfig.P2PKeys)
	}
	if privKeysCount != numOps {
		return errors.New("insufficient enr private key files", z.Int("num_operators", numOps), z.Int("num_keyfiles", len(conf.EnrPrivKeyfiles)))
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

// genNewVals returns a list of new validators from the provided config.
func genNewVals(numOps, threshold int, forkVersion []byte, conf addValidatorsConfig) ([]*pbv1.Validator, error) {
	// Generate new validators
	var vals []*pbv1.Validator
	for i := 0; i < conf.NumVals; i++ {
		// Generate private/public keypair
		secret, err := tbls.GenerateSecretKey()
		if err != nil {
			return []*pbv1.Validator{}, errors.Wrap(err, "generate secret key")
		}

		pubkey, err := tbls.SecretToPublicKey(secret)
		if err != nil {
			return []*pbv1.Validator{}, errors.Wrap(err, "generate public key")
		}

		// Split private key and generate public keyshares
		shares, err := tbls.ThresholdSplit(secret, uint(numOps), uint(threshold))
		if err != nil {
			return []*pbv1.Validator{}, errors.Wrap(err, "threshold split key")
		}

		var pubshares [][]byte
		for _, share := range shares {
			pubshare, err := tbls.SecretToPublicKey(share)
			if err != nil {
				return []*pbv1.Validator{}, errors.Wrap(err, "generate public key")
			}

			pubshares = append(pubshares, pubshare[:])
		}

		feeRecipientAddr, err := eth2util.ChecksumAddress(conf.FeeRecipientAddrs[i])
		if err != nil {
			return []*pbv1.Validator{}, errors.Wrap(err, "invalid fee recipient address")
		}

		withdrawalAddr, err := eth2util.ChecksumAddress(conf.WithdrawalAddrs[i])
		if err != nil {
			return []*pbv1.Validator{}, errors.Wrap(err, "invalid withdrawal address")
		}

		// Generate builder registration
		builderReg, err := builderRegistration(secret, pubkey, feeRecipientAddr, forkVersion)
		if err != nil {
			return []*pbv1.Validator{}, err
		}

		builderRegJSON, err := json.Marshal(builderReg)
		if err != nil {
			return []*pbv1.Validator{}, errors.Wrap(err, "marshal builder registration")
		}

		vals = append(vals, &pbv1.Validator{
			PublicKey:               pubkey[:],
			PubShares:               pubshares,
			FeeRecipientAddress:     feeRecipientAddr,
			WithdrawalAddress:       withdrawalAddr,
			BuilderRegistrationJson: builderRegJSON,
		})
	}

	return vals, nil
}

// getP2PKeys returns a list of p2p private keys either by loading from disk or from test config.
func getP2PKeys(conf addValidatorsConfig) ([]*k1.PrivateKey, error) {
	if len(conf.TestConfig.P2PKeys) > 0 {
		return conf.TestConfig.P2PKeys, nil
	}

	var p2pKeys []*k1.PrivateKey
	for _, enrKeyFile := range conf.EnrPrivKeyfiles {
		p2pKey, err := k1util.Load(enrKeyFile)
		if err != nil {
			return nil, errors.Wrap(err, "load enr private key")
		}

		p2pKeys = append(p2pKeys, p2pKey)
	}

	return p2pKeys, nil
}

// validateP2PKeysOrder ensures that the provided p2p private keys are ordered correctly by peer index.
func validateP2PKeysOrder(p2pKeys []*k1.PrivateKey, ops []*pbv1.Operator) error {
	var enrs []string
	for _, enrStr := range ops {
		enrs = append(enrs, enrStr.Enr)
	}

	if len(p2pKeys) != len(enrs) {
		return errors.New("length of p2p keys and enrs don't match", z.Int("p2pkeys", len(p2pKeys)), z.Int("enrs", len(enrs)))
	}

	for i, enrStr := range enrs {
		record, err := enr.Parse(enrStr)
		if err != nil {
			return err
		}

		if !bytes.Equal(p2pKeys[i].PubKey().SerializeCompressed(), record.PubKey.SerializeCompressed()) {
			return errors.New("invalid p2p key order", z.Int("peer_index", i))
		}
	}

	return nil
}

// repeatAddr repeats the same address for all the validators.
func repeatAddr(addr string, numVals int) []string {
	var addrs []string
	for i := 0; i < numVals; i++ {
		addrs = append(addrs, addr)
	}

	return addrs
}
