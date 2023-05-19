// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"strings"
	"testing"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/obolapi"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/deposit"
	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/eth2util/keymanager"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/eth2util/registration"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

const (
	// zeroAddress is not owned by any user, is often associated with token burn & mint/genesis events and used as a generic null address.
	// See https://etherscan.io/address/0x0000000000000000000000000000000000000000.
	zeroAddress    = "0x0000000000000000000000000000000000000000"
	defaultNetwork = "mainnet"
	minNodes       = 4
)

type clusterConfig struct {
	Name       string
	ClusterDir string
	DefFile    string
	Clean      bool

	KeymanagerAddrs      []string
	KeymanagerAuthTokens []string

	NumNodes          int
	Threshold         int
	FeeRecipientAddrs []string
	WithdrawalAddrs   []string
	Network           string
	NumDVs            int

	SplitKeys    bool
	SplitKeysDir string

	InsecureKeys bool

	PublishAddr string
	Publish     bool
}

func newCreateClusterCmd(runFunc func(context.Context, io.Writer, clusterConfig) error) *cobra.Command {
	var conf clusterConfig

	cmd := &cobra.Command{
		Use:   "cluster",
		Short: "Create private keys and configuration files needed to run a distributed validator cluster locally",
		Long: "Creates a local charon cluster configuration including validator keys, charon p2p keys, cluster-lock.json and a deposit-data.json. " +
			"See flags for supported features.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFunc(cmd.Context(), cmd.OutOrStdout(), conf)
		},
	}

	bindClusterFlags(cmd.Flags(), &conf)
	bindInsecureFlags(cmd.Flags(), &conf.InsecureKeys)

	return cmd
}

func bindClusterFlags(flags *pflag.FlagSet, config *clusterConfig) {
	flags.StringVar(&config.Name, "name", "", "The cluster name")
	flags.StringVar(&config.ClusterDir, "cluster-dir", ".charon/cluster", "The target folder to create the cluster in.")
	flags.StringVar(&config.DefFile, "definition-file", "", "Optional path to a cluster definition file or an HTTP URL. This overrides all other configuration flags.")
	flags.StringSliceVar(&config.KeymanagerAddrs, "keymanager-addresses", nil, "Comma separated list of keymanager URLs to import validator key shares to. Note that multiple addresses are required, one for each node in the cluster, with node0's keyshares being imported to the first address, node1's keyshares to the second, and so on.")
	flags.StringSliceVar(&config.KeymanagerAuthTokens, "keymanager-auth-tokens", nil, "Authentication bearer tokens to interact with the keymanager URLs. Don't include the \"Bearer\" symbol, only include the api-token.")
	flags.IntVarP(&config.NumNodes, "nodes", "", minNodes, "The number of charon nodes in the cluster. Minimum is 4.")
	flags.IntVarP(&config.Threshold, "threshold", "", 0, "Optional override of threshold required for signature reconstruction. Defaults to ceil(n*2/3) if zero. Warning, non-default values decrease security.")
	flags.StringSliceVar(&config.FeeRecipientAddrs, "fee-recipient-addresses", nil, "Comma separated list of Ethereum addresses of the fee recipient for each validator. Either provide a single fee recipient address or fee recipient addresses for each validator.")
	flags.StringSliceVar(&config.WithdrawalAddrs, "withdrawal-addresses", nil, "Comma separated list of Ethereum addresses to receive the returned stake and accrued rewards for each validator. Either provide a single withdrawal address or withdrawal addresses for each validator.")
	flags.StringVar(&config.Network, "network", defaultNetwork, "Ethereum network to create validators for. Options: mainnet, gnosis, goerli, kiln, ropsten, sepolia.")
	flags.BoolVar(&config.Clean, "clean", false, "Delete the cluster directory before generating it.")
	flags.IntVar(&config.NumDVs, "num-validators", 1, "The number of distributed validators needed in the cluster.")
	flags.BoolVar(&config.SplitKeys, "split-existing-keys", false, "Split an existing validator's private key into a set of distributed validator private key shares. Does not re-create deposit data for this key.")
	flags.StringVar(&config.SplitKeysDir, "split-keys-dir", "", "Directory containing keys to split. Expects keys in keystore-*.json and passwords in keystore-*.txt. Requires --split-existing-keys.")
	flags.StringVar(&config.PublishAddr, "publish-address", "https://api.obol.tech", "The URL to publish the lock file to.")
	flags.BoolVar(&config.Publish, "publish", false, "Publish lock file to obol-api.")
}

func bindInsecureFlags(flags *pflag.FlagSet, insecureKeys *bool) {
	flags.BoolVar(insecureKeys, "insecure-keys", false, "Generates insecure keystore files. This should never be used. It is not supported on mainnet.")
}

func runCreateCluster(ctx context.Context, w io.Writer, conf clusterConfig) error {
	var err error
	if conf.Clean {
		// Remove previous directories
		if err = os.RemoveAll(conf.ClusterDir); err != nil {
			return errors.Wrap(err, "remove cluster dir")
		}
	} else if _, err = os.Stat(path.Join(nodeDir(conf.ClusterDir, 0), "cluster-lock.json")); err == nil {
		return errors.New("existing cluster found. Try again with --clean")
	}

	// Map prater to goerli to ensure backwards compatibility with older cluster definitions and cluster locks.
	if conf.Network == eth2util.Prater {
		conf.Network = eth2util.Goerli.Name
	}

	// Ensure sufficient auth tokens are provided for the keymanager addresses
	if len(conf.KeymanagerAddrs) != len(conf.KeymanagerAuthTokens) {
		return errors.New("number of --keymanager-addresses do not match --keymanager-auth-tokens. Please fix configuration flags")
	}

	var def cluster.Definition
	if conf.DefFile != "" { // Load definition from DefFile
		def, err = loadDefinition(ctx, conf.DefFile)
		if err != nil {
			return err
		}
	} else { // Create new definition from cluster config
		def, err = newDefFromConfig(ctx, conf)
		if err != nil {
			return err
		}
	}

	numNodes := len(def.Operators)

	if !conf.SplitKeys && def.NumValidators == 0 {
		return errors.New("num-validators cannot be equal to 0")
	}

	// Get root bls secrets
	secrets, err := getKeys(conf.SplitKeys, conf.SplitKeysDir, def.NumValidators)
	if err != nil {
		return err
	}

	// Check if NumValidators provided in the given definition file mismatches with the number of split-keys provided.
	if conf.DefFile != "" && conf.SplitKeys && def.NumValidators != len(secrets) {
		return errors.New("number of keystores provided in split-keys-dir does not matches with NumValidators in the given definition file")
	}

	// Check if provided --num-validators mismatches with the number of secrets obtained from split-keys-dir.
	if conf.SplitKeys && def.NumValidators != len(secrets) {
		if def.NumValidators > 1 {
			return errors.New("num-validators provided is not equal to keystores provided in split-keys-dir",
				z.Int("num-validators", def.NumValidators), z.Int("split-keys", len(secrets)))
		}

		// Override definition according to the secrets obtained from split-keys-dir if num-validators are 0 or 1 (default).
		def.NumValidators = len(secrets)
		feeRecipientAddrs, withdrawalAddrs, err := validateAddresses(def.NumValidators, conf.FeeRecipientAddrs, conf.WithdrawalAddrs)
		if err != nil {
			return err
		}

		def.ValidatorAddresses = []cluster.ValidatorAddresses{}
		for i := 0; i < def.NumValidators; i++ {
			def.ValidatorAddresses = append(def.ValidatorAddresses, cluster.ValidatorAddresses{
				FeeRecipientAddress: feeRecipientAddrs[i],
				WithdrawalAddress:   withdrawalAddrs[i],
			})
		}

		// Update config and definition hash.
		def, err = def.SetDefinitionHashes()
		if err != nil {
			return err
		}
	}

	// Validate definition
	err = validateDef(ctx, conf.InsecureKeys, conf.KeymanagerAddrs, def)
	if err != nil {
		return err
	}

	// Generate threshold bls key shares
	pubkeys, shareSets, err := getTSSShares(secrets, def.Threshold, numNodes)
	if err != nil {
		return err
	}

	// Create cluster directory at the given location.
	if err := os.MkdirAll(conf.ClusterDir, 0o755); err != nil {
		return errors.Wrap(err, "mkdir")
	}

	// Create operators
	ops, err := getOperators(numNodes, conf.ClusterDir)
	if err != nil {
		return err
	}
	def.Operators = ops

	keysToDisk := len(conf.KeymanagerAddrs) == 0
	if keysToDisk { // Save keys to disk
		if err = writeKeysToDisk(numNodes, conf.ClusterDir, conf.InsecureKeys, shareSets); err != nil {
			return err
		}
	} else { // Or else save keys to keymanager
		if err = writeKeysToKeymanager(ctx, conf, numNodes, shareSets); err != nil {
			return err
		}
	}

	network, err := eth2util.ForkVersionToNetwork(def.ForkVersion)
	if err != nil {
		return err
	}

	depositDatas, err := createDepositDatas(def.WithdrawalAddresses(), network, secrets)
	if err != nil {
		return err
	}

	// Write deposit-data file
	if err = writeDepositData(depositDatas, network, conf.ClusterDir, numNodes); err != nil {
		return err
	}

	valRegs, err := createValidatorRegistrations(def.WithdrawalAddresses(), secrets)
	if err != nil {
		return err
	}

	vals, err := getValidators(pubkeys, shareSets, depositDatas, valRegs)
	if err != nil {
		return err
	}

	lock := cluster.Lock{
		Definition: def,
		Validators: vals,
	}
	lock, err = lock.SetLockHash()
	if err != nil {
		return err
	}

	lock.SignatureAggregate, err = aggSign(shareSets, lock.LockHash)
	if err != nil {
		return err
	}

	// Write cluster-lock file
	if conf.Publish {
		if err = writeLockToAPI(ctx, conf.PublishAddr, lock); err != nil {
			log.Warn(ctx, "Couldn't publish lock file to Obol API", err)
		}
	}

	if err = writeLock(lock, conf.ClusterDir, numNodes); err != nil {
		return err
	}

	if conf.SplitKeys {
		writeWarning(w)
	}

	writeOutput(w, conf.SplitKeys, conf.ClusterDir, numNodes, keysToDisk)

	return nil
}

// signDepositDatas returns Distributed Validator pubkeys and deposit data signatures corresponding to each pubkey.
func signDepositDatas(secrets []tbls.PrivateKey, withdrawalAddresses []string, network string) ([]eth2p0.DepositData, error) {
	if len(secrets) != len(withdrawalAddresses) {
		return nil, errors.New("insufficient withdrawal addresses")
	}

	var datas []eth2p0.DepositData
	for i, secret := range secrets {
		withdrawalAddr, err := eth2util.ChecksumAddress(withdrawalAddresses[i])
		if err != nil {
			return nil, err
		}

		pk, err := tbls.SecretToPublicKey(secret)
		if err != nil {
			return nil, errors.Wrap(err, "secret to pubkey")
		}

		msg, err := deposit.NewMessage(eth2p0.BLSPubKey(pk), withdrawalAddr)
		if err != nil {
			return nil, err
		}

		sigRoot, err := deposit.GetMessageSigningRoot(msg, network)
		if err != nil {
			return nil, err
		}

		sig, err := tbls.Sign(secret, sigRoot[:])
		if err != nil {
			return nil, err
		}

		datas = append(datas, eth2p0.DepositData{
			PublicKey:             msg.PublicKey,
			WithdrawalCredentials: msg.WithdrawalCredentials,
			Amount:                msg.Amount,
			Signature:             tblsconv.SigToETH2(sig),
		})
	}

	return datas, nil
}

// signValidatorRegistrations returns a slice of validator registrations for each private key in secrets.
func signValidatorRegistrations(secrets []tbls.PrivateKey, feeAddresses []string) ([]core.VersionedSignedValidatorRegistration, error) {
	if len(secrets) != len(feeAddresses) {
		return nil, errors.New("insufficient fee addresses")
	}

	var datas []core.VersionedSignedValidatorRegistration
	for i, secret := range secrets {
		feeAddress, err := eth2util.ChecksumAddress(feeAddresses[i])
		if err != nil {
			return nil, err
		}

		pk, err := tbls.SecretToPublicKey(secret)
		if err != nil {
			return nil, errors.Wrap(err, "secret to pubkey")
		}

		unsignedReg, err := registration.NewMessage(
			eth2p0.BLSPubKey(pk),
			feeAddress,
			registration.DefaultGasLimit,
			registration.DefaultRegistrationTime,
		)
		if err != nil {
			return nil, errors.Wrap(err, "registration creation")
		}

		sigRoot, err := registration.GetMessageSigningRoot(unsignedReg)
		if err != nil {
			return nil, err
		}

		sig, err := tbls.Sign(secret, sigRoot[:])
		if err != nil {
			return nil, err
		}

		reg, err := core.NewVersionedSignedValidatorRegistration(&eth2api.VersionedSignedValidatorRegistration{
			Version: eth2spec.BuilderVersionV1,
			V1: &eth2v1.SignedValidatorRegistration{
				Message:   unsignedReg,
				Signature: tblsconv.SigToETH2(sig),
			},
		})
		if err != nil {
			return nil, errors.Wrap(err, "versioned signed validator registration creation")
		}

		datas = append(datas, reg)
	}

	return datas, nil
}

// getTSSShares splits the secrets and returns the threshold key shares.
func getTSSShares(secrets []tbls.PrivateKey, threshold, numNodes int) ([]tbls.PublicKey, [][]tbls.PrivateKey, error) {
	var (
		dvs    []tbls.PublicKey
		splits [][]tbls.PrivateKey
	)
	for _, secret := range secrets {
		shares, err := tbls.ThresholdSplit(secret, uint(numNodes), uint(threshold))
		if err != nil {
			return nil, nil, err
		}

		// preserve order when transforming from map of private shares to array of private keys
		secretSet := make([]tbls.PrivateKey, len(shares))
		for i := 1; i <= len(shares); i++ {
			secretSet[i-1] = shares[i]
		}

		splits = append(splits, secretSet)

		pubkey, err := tbls.SecretToPublicKey(secret)
		if err != nil {
			return nil, nil, err
		}

		dvs = append(dvs, pubkey)
	}

	return dvs, splits, nil
}

func writeWarning(w io.Writer) {
	var sb strings.Builder
	_, _ = sb.WriteString("\n")
	_, _ = sb.WriteString("***************** WARNING: Splitting keys **********************\n")
	_, _ = sb.WriteString(" Please make sure any existing validator has been shut down for\n")
	_, _ = sb.WriteString(" at least 2 finalised epochs before starting the charon cluster,\n")
	_, _ = sb.WriteString(" otherwise slashing could occur.                               \n")
	_, _ = sb.WriteString("****************************************************************\n")
	_, _ = sb.WriteString("\n")

	_, _ = w.Write([]byte(sb.String()))
}

// getKeys fetches secret keys for each distributed validator.
func getKeys(splitKeys bool, splitKeysDir string, numDVs int) ([]tbls.PrivateKey, error) {
	if splitKeys {
		if splitKeysDir == "" {
			return nil, errors.New("--split-keys-dir required when splitting keys")
		}

		return keystore.LoadKeys(splitKeysDir)
	}

	var secrets []tbls.PrivateKey
	for i := 0; i < numDVs; i++ {
		secret, err := tbls.GenerateSecretKey()
		if err != nil {
			return nil, err
		}

		secrets = append(secrets, secret)
	}

	return secrets, nil
}

// createDepositDatas creates a slice of deposit datas using the provided parameters and returns it.
func createDepositDatas(withdrawalAddresses []string, network string, secrets []tbls.PrivateKey) ([]eth2p0.DepositData, error) {
	if len(secrets) != len(withdrawalAddresses) {
		return nil, errors.New("insufficient withdrawal addresses")
	}

	return signDepositDatas(secrets, withdrawalAddresses, network)
}

// writeDepositData writes deposit data to disk for the DVs for all peers in a cluster.
func writeDepositData(depositDatas []eth2p0.DepositData, network string, clusterDir string, numNodes int) error {
	// Serialize the deposit data into bytes
	bytes, err := deposit.MarshalDepositData(depositDatas, network)
	if err != nil {
		return err
	}

	for i := 0; i < numNodes; i++ {
		depositPath := path.Join(nodeDir(clusterDir, i), "deposit-data.json")
		err = os.WriteFile(depositPath, bytes, 0o400) // read-only
		if err != nil {
			return errors.Wrap(err, "write deposit data")
		}
	}

	return nil
}

// createValidatorRegistrations creates a slice of builder validator registrations using the provided parameters and returns it.
func createValidatorRegistrations(feeAddresses []string, secrets []tbls.PrivateKey) ([]core.VersionedSignedValidatorRegistration, error) {
	if len(feeAddresses) != len(secrets) {
		return nil, errors.New("insufficient fee addresses")
	}

	return signValidatorRegistrations(secrets, feeAddresses)
}

// writeLock creates a cluster lock and writes it to disk for all peers.
func writeLock(lock cluster.Lock, clusterDir string, numNodes int) error {
	b, err := json.MarshalIndent(lock, "", " ")
	if err != nil {
		return errors.Wrap(err, "marshal cluster lock")
	}

	for i := 0; i < numNodes; i++ {
		lockPath := path.Join(nodeDir(clusterDir, i), "cluster-lock.json")
		err = os.WriteFile(lockPath, b, 0o400) // read-only
		if err != nil {
			return errors.Wrap(err, "write cluster lock")
		}
	}

	return nil
}

// getValidators returns distributed validators from the provided dv public keys and keyshares.
// It creates new peers from the provided config and saves validator keys to disk for each peer.
func getValidators(
	dvsPubkeys []tbls.PublicKey,
	dvPrivShares [][]tbls.PrivateKey,
	depositDatas []eth2p0.DepositData,
	valRegs []core.VersionedSignedValidatorRegistration,
) ([]cluster.DistValidator, error) {
	var vals []cluster.DistValidator
	for idx, dv := range dvsPubkeys {
		dv := dv
		privShares := dvPrivShares[idx]
		var pubshares [][]byte
		for _, ps := range privShares {
			pubk, err := tbls.SecretToPublicKey(ps)
			if err != nil {
				return nil, errors.Wrap(err, "public key generation")
			}

			pubshares = append(pubshares, pubk[:])
		}

		depositIdx := -1
		for i, dd := range depositDatas {
			if [48]byte(dd.PublicKey) != dv {
				continue
			}
			depositIdx = i

			break
		}
		if depositIdx == -1 {
			return nil, errors.New("deposit data not found")
		}

		regIdx := -1
		for i, reg := range valRegs {
			pubkey, err := reg.PubKey()
			if err != nil {
				return nil, err
			}

			if !bytes.Equal(dv[:], pubkey[:]) {
				continue
			}

			regIdx = i

			break
		}

		if regIdx == -1 {
			return nil, errors.New("validator registration not found")
		}

		clusterReg, err := builderRegistrationFromETH2(valRegs[regIdx])
		if err != nil {
			return nil, errors.Wrap(err, "builder registration to cluster object")
		}

		vals = append(vals, cluster.DistValidator{
			PubKey:    dv[:],
			PubShares: pubshares,
			DepositData: cluster.DepositData{
				PubKey:                depositDatas[depositIdx].PublicKey[:],
				WithdrawalCredentials: depositDatas[depositIdx].WithdrawalCredentials,
				Amount:                int(depositDatas[depositIdx].Amount),
				Signature:             depositDatas[depositIdx].Signature[:],
			},
			BuilderRegistration: clusterReg,
		})
	}

	return vals, nil
}

// writeKeysToKeymanager writes validator keys to the provided keymanager addresses.
func writeKeysToKeymanager(ctx context.Context, conf clusterConfig, numNodes int, shareSets [][]tbls.PrivateKey) error {
	// Ping all keymanager addresses to check if they are accessible to avoid partial writes
	var clients []keymanager.Client
	for i := 0; i < numNodes; i++ {
		cl := keymanager.New(conf.KeymanagerAddrs[i], conf.KeymanagerAuthTokens[i])
		if err := cl.VerifyConnection(ctx); err != nil {
			return err
		}
		clients = append(clients, cl)
	}

	for i := 0; i < numNodes; i++ {
		var (
			keystores []keystore.Keystore
			passwords []string
		)
		for _, shares := range shareSets {
			password, err := randomHex64()
			if err != nil {
				return err
			}
			passwords = append(passwords, password)

			var opts []keystorev4.Option
			if conf.InsecureKeys {
				opts = append(opts, keystorev4.WithCost(new(testing.T), 4))
			}
			store, err := keystore.Encrypt(shares[i], password, rand.Reader, opts...)
			if err != nil {
				return err
			}
			keystores = append(keystores, store)
		}

		err := clients[i].ImportKeystores(ctx, keystores, passwords)
		if err != nil {
			log.Error(ctx, "Failed to import keys", err, z.Str("addr", conf.KeymanagerAddrs[i]))
			return err
		}

		log.Info(ctx, "Imported key shares to keymanager",
			z.Str("node", fmt.Sprintf("node%d", i)), z.Str("addr", conf.KeymanagerAddrs[i]))
	}

	log.Info(ctx, "Imported all validator keys to respective keymanagers")

	return nil
}

// writeKeysToDisk writes validator keyshares to disk. It assumes that the directory for each node already exists.
func writeKeysToDisk(numNodes int, clusterDir string, insecureKeys bool, shareSets [][]tbls.PrivateKey) error {
	for i := 0; i < numNodes; i++ {
		var secrets []tbls.PrivateKey
		for _, shares := range shareSets {
			secrets = append(secrets, shares[i])
		}

		keysDir := path.Join(nodeDir(clusterDir, i), "/validator_keys")
		if err := os.MkdirAll(keysDir, 0o755); err != nil {
			return errors.Wrap(err, "mkdir validator_keys")
		}

		if insecureKeys {
			if err := keystore.StoreKeysInsecure(secrets, keysDir, keystore.ConfirmInsecureKeys); err != nil {
				return err
			}
		} else {
			if err := keystore.StoreKeys(secrets, keysDir); err != nil {
				return err
			}
		}
	}

	return nil
}

// getOperators returns a list of `n` operators. It also creates a new directory corresponding to each node.
func getOperators(n int, clusterDir string) ([]cluster.Operator, error) {
	var ops []cluster.Operator
	for i := 0; i < n; i++ {
		record, err := newPeer(clusterDir, i)
		if err != nil {
			return nil, err
		}

		ops = append(ops, cluster.Operator{ENR: record.String()})
	}

	return ops, nil
}

// newDefFromConfig returns a new cluster definition using the provided config values.
func newDefFromConfig(ctx context.Context, conf clusterConfig) (cluster.Definition, error) {
	feeRecipientAddrs, withdrawalAddrs, err := validateAddresses(conf.NumDVs, conf.FeeRecipientAddrs, conf.WithdrawalAddrs)
	if err != nil {
		return cluster.Definition{}, err
	}

	forkVersion, err := eth2util.NetworkToForkVersion(conf.Network)
	if err != nil {
		return cluster.Definition{}, err
	}

	var ops []cluster.Operator
	for i := 0; i < conf.NumNodes; i++ {
		ops = append(ops, cluster.Operator{})
	}
	threshold := safeThreshold(ctx, conf.NumNodes, conf.Threshold)

	def, err := cluster.NewDefinition(conf.Name, conf.NumDVs, threshold, feeRecipientAddrs,
		withdrawalAddrs, forkVersion, cluster.Creator{}, ops, rand.Reader)
	if err != nil {
		return cluster.Definition{}, err
	}

	return def, nil
}

// newPeer returns a new peer ENR, generating a p2pkey in node directory.
func newPeer(clusterDir string, peerIdx int) (enr.Record, error) {
	dir := nodeDir(clusterDir, peerIdx)

	p2pKey, err := p2p.NewSavedPrivKey(dir)
	if err != nil {
		return enr.Record{}, errors.Wrap(err, "create charon-enr-private-key")
	}

	return enr.New(p2pKey)
}

// writeOutput writes the cluster generation output.
func writeOutput(out io.Writer, splitKeys bool, clusterDir string, numNodes int, keysToDisk bool) {
	var sb strings.Builder
	_, _ = sb.WriteString("Created charon cluster:\n")
	_, _ = sb.WriteString(fmt.Sprintf(" --split-existing-keys=%v\n", splitKeys))
	_, _ = sb.WriteString("\n")
	_, _ = sb.WriteString(strings.TrimSuffix(clusterDir, "/") + "/\n")
	_, _ = sb.WriteString(fmt.Sprintf("├─ node[0-%d]/\t\t\tDirectory for each node\n", numNodes-1))
	_, _ = sb.WriteString("│  ├─ charon-enr-private-key\tCharon networking private key for node authentication\n")
	_, _ = sb.WriteString("│  ├─ cluster-lock.json\t\tCluster lock defines the cluster lock file which is signed by all nodes\n")
	_, _ = sb.WriteString("│  ├─ deposit-data.json\t\tDeposit data file is used to activate a Distributed Validator on DV Launchpad\n")
	if keysToDisk {
		_, _ = sb.WriteString("│  ├─ validator_keys\t\tValidator keystores and password\n")
		_, _ = sb.WriteString("│  │  ├─ keystore-*.json\tValidator private share key for duty signing\n")
		_, _ = sb.WriteString("│  │  ├─ keystore-*.txt\t\tKeystore password files for keystore-*.json\n")
	}

	_, _ = fmt.Fprint(out, sb.String())
}

// nodeDir returns a node directory.
func nodeDir(clusterDir string, i int) string {
	return fmt.Sprintf("%s/node%d", clusterDir, i)
}

// validateDef returns an error if the provided cluster definition is invalid.
func validateDef(ctx context.Context, insecureKeys bool, keymanagerAddrs []string, def cluster.Definition) error {
	if def.NumValidators == 0 {
		return errors.New("cannot create cluster with zero validators, specify at least one")
	}

	if len(def.Operators) < minNodes {
		return errors.New("insufficient number of nodes (min = 4)", z.Int("num_nodes", len(def.Operators)))
	}

	if len(keymanagerAddrs) > 0 && (len(keymanagerAddrs) != len(def.Operators)) {
		return errors.New("insufficient no of keymanager addresses", z.Int("expected", len(def.Operators)), z.Int("got", len(keymanagerAddrs)))
	}

	network, err := eth2util.ForkVersionToNetwork(def.ForkVersion)
	if err != nil {
		return err
	}

	if insecureKeys && isMainOrGnosis(network) {
		return errors.New("insecure keys not supported on mainnet")
	} else if insecureKeys {
		log.Warn(ctx, "Insecure keystores configured. ONLY DO THIS DURING TESTING", nil)
	}

	if def.Name == "" {
		return errors.New("name not provided")
	}

	if err = def.VerifyHashes(); err != nil {
		return err
	}

	if err = def.VerifySignatures(); err != nil {
		return err
	}

	if !eth2util.ValidNetwork(network) {
		return errors.New("unsupported network", z.Str("network", network))
	}

	return validateWithdrawalAddrs(def.WithdrawalAddresses(), network)
}

// aggSign returns a bls aggregate signatures of the message signed by all the shares.
func aggSign(secrets [][]tbls.PrivateKey, message []byte) ([]byte, error) {
	var sigs []tbls.Signature
	for _, shares := range secrets {
		for _, share := range shares {
			sig, err := tbls.Sign(share, message)
			if err != nil {
				return nil, err
			}
			sigs = append(sigs, sig)
		}
	}

	aggSig, err := tbls.Aggregate(sigs)
	if err != nil {
		return nil, errors.Wrap(err, "aggregate signatures")
	}

	return aggSig[:], nil
}

// loadDefinition returns the cluster definition from disk or an HTTP URL. It also verifies signatures
// and hashes before returning the definition.
func loadDefinition(ctx context.Context, defFile string) (cluster.Definition, error) {
	var def cluster.Definition

	// Fetch definition from network if URI is provided
	if validURI(defFile) {
		var err error
		def, err = cluster.FetchDefinition(ctx, defFile)
		if err != nil {
			return cluster.Definition{}, errors.Wrap(err, "read definition")
		}

		log.Info(ctx, "Cluster definition downloaded from URL", z.Str("URL", defFile),
			z.Str("definition_hash", fmt.Sprintf("%#x", def.DefinitionHash)))
	} else { // Fetch definition from disk
		buf, err := os.ReadFile(defFile)
		if err != nil {
			return cluster.Definition{}, errors.Wrap(err, "read definition")
		}

		if err = json.Unmarshal(buf, &def); err != nil {
			return cluster.Definition{}, errors.Wrap(err, "unmarshal definition")
		}

		log.Info(ctx, "Cluster definition loaded from disk", z.Str("path", defFile),
			z.Str("definition_hash", fmt.Sprintf("%#x", def.DefinitionHash)))
	}

	if err := def.VerifySignatures(); err != nil {
		return cluster.Definition{}, err
	}
	if err := def.VerifyHashes(); err != nil {
		return cluster.Definition{}, err
	}

	if def.NumValidators == 0 {
		return cluster.Definition{}, errors.New("no validators specified in the given definition")
	}

	return def, nil
}

// validURI returns true if the input string is a valid HTTP/HTTPS URI.
func validURI(str string) bool {
	u, err := url.Parse(str)

	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// safeThreshold logs a warning when a non-standard threshold is provided.
func safeThreshold(ctx context.Context, numNodes, threshold int) int {
	safe := cluster.Threshold(numNodes)
	if threshold == 0 {
		return safe
	}
	if threshold != safe {
		log.Warn(ctx, "Non standard threshold provided, this will affect cluster safety", nil,
			z.Int("num_nodes", numNodes), z.Int("threshold", threshold), z.Int("safe_threshold", safe))
	}

	return threshold
}

// randomHex64 returns a random 64 character hex string. It uses crypto/rand.
func randomHex64() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", errors.Wrap(err, "read random")
	}

	return hex.EncodeToString(b), nil
}

// writeLockToAPI posts the lock file to obol-api.
func writeLockToAPI(ctx context.Context, publishAddr string, lock cluster.Lock) error {
	cl := obolapi.New(publishAddr)

	if err := cl.PublishLock(ctx, lock); err != nil {
		return err
	}

	log.Info(ctx, "Published lock file", z.Str("addr", publishAddr))

	return nil
}

// validateAddresses checks if we have sufficient addresses. It also fills addresses slices if only one is provided.
func validateAddresses(numVals int, feeRecipientAddrs []string, withdrawalAddrs []string) ([]string, []string, error) {
	if len(feeRecipientAddrs) != numVals && len(feeRecipientAddrs) != 1 {
		return nil, nil, errors.New("insufficient fee recipient addresses")
	}

	if len(withdrawalAddrs) != numVals && len(withdrawalAddrs) != 1 {
		return nil, nil, errors.New("insufficient withdrawal addresses")
	}

	if len(feeRecipientAddrs) == 1 {
		for i := 1; i < numVals; i++ {
			feeRecipientAddrs = append(feeRecipientAddrs, feeRecipientAddrs[0])
		}
	}

	if len(withdrawalAddrs) == 1 {
		for i := 1; i < numVals; i++ {
			withdrawalAddrs = append(withdrawalAddrs, withdrawalAddrs[0])
		}
	}

	return feeRecipientAddrs, withdrawalAddrs, nil
}

func builderRegistrationFromETH2(reg core.VersionedSignedValidatorRegistration) (cluster.BuilderRegistration, error) {
	feeRecipient, err := reg.FeeRecipient()
	if err != nil {
		return cluster.BuilderRegistration{}, errors.Wrap(err, "get fee recipient")
	}

	gasLimit, err := reg.GasLimit()
	if err != nil {
		return cluster.BuilderRegistration{}, errors.Wrap(err, "get gasLimit")
	}

	timestamp, err := reg.Timestamp()
	if err != nil {
		return cluster.BuilderRegistration{}, errors.Wrap(err, "get timestamp")
	}

	pubKey, err := reg.PubKey()
	if err != nil {
		return cluster.BuilderRegistration{}, errors.Wrap(err, "get pubKey")
	}

	return cluster.BuilderRegistration{
		Message: cluster.Registration{
			FeeRecipient: feeRecipient[:],
			GasLimit:     int(gasLimit),
			Timestamp:    timestamp,
			PubKey:       pubKey[:],
		},
		Signature: reg.Signature(),
	}, nil
}
