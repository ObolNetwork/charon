// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"

	libp2plog "github.com/ipfs/go-log/v2"
	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/dkg"
	"github.com/obolnetwork/charon/dkg/pedersen"
	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/tbls"
)

func newAddOperatorsCmd(runFunc func(context.Context, dkg.AddOperatorsDKGConfig) error) *cobra.Command {
	var config dkg.AddOperatorsDKGConfig

	cmd := &cobra.Command{
		Use:   "add-operators",
		Short: "Add new operators to the existing cluster",
		Long:  `Adds new operators to the existing cluster, leaving all validators intact.`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error { //nolint:revive // keep args variable name for clarity
			if err := log.InitLogger(config.DKG.Log); err != nil {
				return err
			}

			libp2plog.SetPrimaryCore(log.LoggerCore()) // Set libp2p logger to use charon logger

			return runFunc(cmd.Context(), config)
		},
	}

	// Bind `add-operators` flags.
	cmd.Flags().StringVar(&config.DataDir, "data-dir", ".charon", "The source charon folder with existing cluster data (lock, validator_keys, etc.). The new operators will only have the lock and enr private key files.")
	cmd.Flags().StringVar(&config.OutputDir, "output-dir", "distributed_validator", "The destination folder for the new cluster data. Must be empty.")
	cmd.Flags().StringSliceVar(&config.NewENRs, "new-operator-enrs", nil, "Comma-separated list of the new operators (Charon ENR addresses).")
	cmd.Flags().IntVar(&config.NewThreshold, "new-threshold", 0, "The new threshold for the cluster. Evaluated automatically if not specified. All operators (old and new) must agree on the new threshold.")

	// Bind `dkg` flags.
	bindNoVerifyFlag(cmd.Flags(), &config.DKG.NoVerify)
	bindP2PFlags(cmd, &config.DKG.P2P)
	bindLogFlags(cmd.Flags(), &config.DKG.Log)
	bindEth1Flag(cmd.Flags(), &config.DKG.ExecutionEngineAddr)
	bindShutdownDelayFlag(cmd.Flags(), &config.DKG.ShutdownDelay)

	return cmd
}

func runAddOperators(ctx context.Context, conf dkg.AddOperatorsDKGConfig) error {
	if err := validateAddOperatorsConfig(&conf); err != nil {
		return err
	}

	log.Info(ctx, "Running add-operators", z.Str("dataDir", conf.DataDir), z.Str("outputDir", conf.OutputDir))

	lock, err := loadLockJSON(ctx, conf.DataDir, conf.DKG)
	if err != nil {
		return err
	}

	oldENRs := getLockENRs(lock)
	oldThreshold := lock.Threshold

	thisPeerENR, err := getThisNodeENR(conf.DataDir)
	if err != nil {
		return err
	}

	var allENRs []string

	allENRs = append(allENRs, oldENRs...)

	allENRs = append(allENRs, conf.NewENRs...)
	if hasDuplicates(allENRs) {
		return errors.New("duplicate ENRs found between existing cluster and new operators")
	}

	isNew := slices.Contains(conf.NewENRs, thisPeerENR)
	if !isNew && !slices.Contains(oldENRs, thisPeerENR) {
		return errors.New("this node's ENR not found in the existing cluster or the new operators", z.Str("this_enr", thisPeerENR))
	}

	newN := len(oldENRs) + len(conf.NewENRs)
	newT := newN - (newN-1)/3

	if conf.NewThreshold != 0 {
		if conf.NewThreshold >= newN || conf.NewThreshold < newT {
			return errors.New("new-threshold is invalid", z.Int("recommendedThreshold", newT))
		}

		newT = conf.NewThreshold
	} else {
		conf.NewThreshold = newT
	}

	log.Info(ctx, "Configuration verified",
		z.Bool("isNew", isNew), z.Str("thisENR", thisPeerENR),
		z.Int("oldN", len(oldENRs)), z.Int("newN", newN),
		z.Int("oldT", oldThreshold), z.Int("newT", newT),
		z.Str("lockHash", app.Hex7(lock.LockHash)))

	var (
		secrets []tbls.PrivateKey
		shares  []*pedersen.Share
	)

	if !isNew {
		// Loading the existing cluster keystore only if this is not a new operator.
		secrets, err = loadSecrets(ctx, conf.DataDir)
		if err != nil {
			return err
		}
	}

	// Prepare output directory.
	if err := app.CreateNewEmptyDir(conf.OutputDir); err != nil {
		return err
	}

	if err := app.CopyFile(filepath.Join(conf.DataDir, enrPrivateKeyFile), filepath.Join(conf.OutputDir, enrPrivateKeyFile)); err != nil {
		return err
	}

	// Preparing the existing shares only for old operators.
	if !isNew {
		shares = make([]*pedersen.Share, len(secrets))
		for i := range shares {
			shares[i] = &pedersen.Share{
				PubKey:      tbls.PublicKey(lock.Validators[i].PubKey),
				SecretShare: secrets[i],
			}
		}
	}

	// Finally running the resharing DKG.
	if err := dkg.RunAddOperatorsDKG(ctx, &conf, lock, shares); err != nil {
		return errors.Wrap(err, "run add operators DKG")
	}

	log.Info(ctx, "Successfully completed add-operators ceremony 🎉")
	log.Info(ctx, "IMPORTANT:")
	log.Info(ctx, "You need to shut down your node (charon and VC) and restart it with the new data directory: "+conf.OutputDir)

	return nil
}

func validateAddOperatorsConfig(config *dkg.AddOperatorsDKGConfig) error {
	if config.OutputDir == "" {
		return errors.New("output-dir is required")
	}

	if len(config.NewENRs) == 0 {
		return errors.New("new-operator-enrs is required")
	}

	if !app.FileExists(config.DataDir) {
		return errors.New("data-dir is required")
	}

	lockFile := filepath.Join(config.DataDir, clusterLockFile)
	if !app.FileExists(lockFile) {
		return errors.New("data-dir must contain a cluster-lock.json file")
	}

	return nil
}

func getLockENRs(lock *cluster.Lock) []string {
	var ens []string
	for _, op := range lock.Operators {
		ens = append(ens, op.ENR)
	}

	return ens
}

func getThisNodeENR(dataDir string) (string, error) {
	thisNodePrivateKey, err := p2p.LoadPrivKey(dataDir)
	if err != nil {
		return "", err
	}

	enrRec, err := enr.New(thisNodePrivateKey)
	if err != nil {
		return "", err
	}

	return enrRec.String(), nil
}

func hasDuplicates(enrs []string) bool {
	seen := make(map[string]struct{}, len(enrs))
	for _, enr := range enrs {
		if _, exists := seen[enr]; exists {
			return true
		}

		seen[enr] = struct{}{}
	}

	return false
}

func loadSecrets(ctx context.Context, dataDir string) ([]tbls.PrivateKey, error) {
	var secrets []tbls.PrivateKey

	keyStorePath := filepath.Join(dataDir, validatorKeysSubDir)
	log.Info(ctx, "Loading keystore", z.Str("path", keyStorePath))

	privateKeyFiles, err := keystore.LoadFilesUnordered(keyStorePath)
	if err != nil {
		return nil, errors.Wrap(err, "cannot load private key share", z.Str("path", keyStorePath))
	}

	secrets, err = privateKeyFiles.SequencedKeys()
	if err != nil {
		return nil, errors.Wrap(err, "order private key shares")
	}

	return secrets, nil
}

func loadLockJSON(ctx context.Context, dataDir string, conf dkg.Config) (*cluster.Lock, error) {
	lockFilePath := filepath.Join(dataDir, clusterLockFile)

	b, err := os.ReadFile(lockFilePath)
	if err != nil {
		return nil, errors.Wrap(err, "read cluster-lock.json", z.Str("path", lockFilePath))
	}

	var lock cluster.Lock
	if err := json.Unmarshal(b, &lock); err != nil {
		return nil, errors.Wrap(err, "unmarshal cluster-lock.json", z.Str("path", lockFilePath))
	}

	if err := verifyLock(ctx, lock, conf); err != nil {
		return nil, err
	}

	return &lock, nil
}
