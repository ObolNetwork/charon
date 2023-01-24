// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/deposit"
	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

const (
	defaultWithdrawalAddr = "0x0000000000000000000000000000000000000000"
	defaultNetwork        = "goerli"
	minNodes              = 4
)

type clusterConfig struct {
	Name            string
	ClusterDir      string
	DefFile         string
	KeymanagerAddrs []string
	Clean           bool

	NumNodes       int
	Threshold      int
	FeeRecipient   string
	WithdrawalAddr string
	Network        string
	NumDVs         int

	SplitKeys    bool
	SplitKeysDir string

	InsecureKeys bool
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
	flags.StringSliceVar(&config.KeymanagerAddrs, "keymanager-addresses", nil, "Comma separated list of keymanager URLs to push validator key shares to. Note that multiple addresses are required, one for each node in the cluster, with node0's keyshares being pushed to the first address, node1's keyshares to the second, and so on.")
	flags.IntVarP(&config.NumNodes, "nodes", "", minNodes, "The number of charon nodes in the cluster. Minimum is 4.")
	flags.IntVarP(&config.Threshold, "threshold", "", 0, "Optional override of threshold required for signature reconstruction. Defaults to ceil(n*2/3) if zero. Warning, non-default values decrease security.")
	flags.StringVar(&config.FeeRecipient, "fee-recipient-address", "", "Optional Ethereum address of the fee recipient")
	flags.StringVar(&config.WithdrawalAddr, "withdrawal-address", defaultWithdrawalAddr, "Ethereum address to receive the returned stake and accrued rewards.")
	flags.StringVar(&config.Network, "network", defaultNetwork, "Ethereum network to create validators for. Options: mainnet, gnosis, goerli, kiln, ropsten, sepolia.")
	flags.BoolVar(&config.Clean, "clean", false, "Delete the cluster directory before generating it.")
	flags.IntVar(&config.NumDVs, "num-validators", 1, "The number of distributed validators needed in the cluster.")
	flags.BoolVar(&config.SplitKeys, "split-existing-keys", false, "Split an existing validator's private key into a set of distributed validator private key shares. Does not re-create deposit data for this key.")
	flags.StringVar(&config.SplitKeysDir, "split-keys-dir", "", "Directory containing keys to split. Expects keys in keystore-*.json and passwords in keystore-*.txt. Requires --split-existing-keys.")
}

func bindInsecureFlags(flags *pflag.FlagSet, insecureKeys *bool) {
	flags.BoolVar(insecureKeys, "insecure-keys", false, "Generates insecure keystore files. This should never be used. It is not supported on mainnet.")
}

func runCreateCluster(ctx context.Context, w io.Writer, conf clusterConfig) error {
	if conf.Clean {
		// Remove previous directories
		if err := os.RemoveAll(conf.ClusterDir); err != nil {
			return errors.Wrap(err, "remove cluster dir")
		}
	} else if _, err := os.Stat(path.Join(nodeDir(conf.ClusterDir, 0), "cluster-lock.json")); err == nil {
		return errors.New("existing cluster found. Try again with --clean")
	}

	// Create cluster directory at the given location.
	if err := os.MkdirAll(conf.ClusterDir, 0o755); err != nil {
		return errors.Wrap(err, "mkdir")
	}

	// Map prater to goerli to ensure backwards compatibility with older cluster definitions and cluster locks.
	// TODO(xenowits): Remove the mapping later.
	if conf.Network == eth2util.Prater {
		conf.Network = eth2util.Goerli.Name
	}

	var (
		def cluster.Definition
		err error
	)
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
	// Validate definition
	err = validateDef(ctx, conf.InsecureKeys, conf.KeymanagerAddrs, def)
	if err != nil {
		return err
	}

	// Get root bls secrets
	secrets, err := getKeys(conf.SplitKeys, conf.SplitKeysDir, def.NumValidators)
	if err != nil {
		return err
	}
	// Generate threshold bls key shares
	dvs, shareSets, err := getTSSShares(secrets, def.Threshold, numNodes)
	if err != nil {
		return err
	}

	// Create validators
	vals, err := getValidators(dvs)
	if err != nil {
		return err
	}

	// Create operators
	ops, err := getOperators(numNodes, conf.ClusterDir)
	if err != nil {
		return err
	}
	def.Operators = ops

	keysToDisk := len(conf.KeymanagerAddrs) == 0
	if keysToDisk { // Write keys to disk
		if err = writeKeysToDisk(numNodes, conf.ClusterDir, conf.InsecureKeys, shareSets); err != nil {
			return err
		}
	} else { // Or else push keys to keymanager
		if err = writeKeysToKeymanager(ctx, conf.KeymanagerAddrs, numNodes, shareSets); err != nil {
			return err
		}
	}

	// TODO(corver): Refactor writeDepositData to take a slice of withdrawal addresses.
	vaddrs, err := def.LegacyValidatorAddresses()
	if err != nil {
		return err
	}

	// Write deposit-data file
	if err = writeDepositData(vaddrs.WithdrawalAddress, conf.ClusterDir, def.ForkVersion, numNodes, secrets); err != nil {
		return err
	}

	// Create cluster-lock
	lock := cluster.Lock{
		Definition: def,
		Validators: vals,
	}
	lock, err = lock.SetLockHash()
	if err != nil {
		return err
	}

	// Write cluster-lock file
	if err = writeLock(lock, conf.ClusterDir, numNodes, shareSets); err != nil {
		return err
	}

	if conf.SplitKeys {
		writeWarning(w)
	}

	writeOutput(w, conf.SplitKeys, conf.ClusterDir, numNodes, keysToDisk)

	return nil
}

// signDepositDatas returns a map of deposit data signatures by DV pubkey.
func signDepositDatas(secrets []*bls_sig.SecretKey, withdrawalAddr string, network string) (map[eth2p0.BLSPubKey]eth2p0.BLSSignature, error) {
	withdrawalAddr, err := checksumAddr(withdrawalAddr)
	if err != nil {
		return nil, err
	}

	resp := make(map[eth2p0.BLSPubKey]eth2p0.BLSSignature)
	for _, secret := range secrets {
		pk, err := secret.GetPublicKey()
		if err != nil {
			return nil, errors.Wrap(err, "secret to pubkey")
		}

		pubkey, err := tblsconv.KeyToETH2(pk)
		if err != nil {
			return nil, err
		}

		msgRoot, err := deposit.GetMessageSigningRoot(pubkey, withdrawalAddr, network)
		if err != nil {
			return nil, err
		}

		sig, err := tbls.Sign(secret, msgRoot[:])
		if err != nil {
			return nil, err
		}

		resp[pubkey] = tblsconv.SigToETH2(sig)
	}

	return resp, nil
}

// getTSSShares splits the secrets and returns the threshold key shares.
func getTSSShares(secrets []*bls_sig.SecretKey, threshold, numNodes int) ([]tbls.TSS, [][]*bls_sig.SecretKeyShare, error) {
	var (
		dvs    []tbls.TSS
		splits [][]*bls_sig.SecretKeyShare
	)
	for _, secret := range secrets {
		shares, verifier, err := tbls.SplitSecret(secret, threshold, numNodes, rand.Reader)
		if err != nil {
			return nil, nil, err
		}

		splits = append(splits, shares)

		tss, err := tbls.NewTSS(verifier, len(shares))
		if err != nil {
			return nil, nil, err
		}

		dvs = append(dvs, tss)
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
func getKeys(splitKeys bool, splitKeysDir string, numDVs int) ([]*bls_sig.SecretKey, error) {
	if splitKeys {
		if splitKeysDir == "" {
			return nil, errors.New("--split-keys-dir required when splitting keys")
		}

		return keystore.LoadKeys(splitKeysDir)
	}

	var secrets []*bls_sig.SecretKey
	for i := 0; i < numDVs; i++ {
		_, secret, err := tbls.KeygenWithSeed(rand.Reader)
		if err != nil {
			return nil, err
		}

		secrets = append(secrets, secret)
	}

	return secrets, nil
}

// writeDepositData writes deposit data to disk for the DVs for all peers in a cluster.
func writeDepositData(withdrawalAddr, clusterDir string, forkVersion []byte, numNodes int, secrets []*bls_sig.SecretKey) error {
	network, err := eth2util.ForkVersionToNetwork(forkVersion)
	if err != nil {
		return err
	}

	// Create deposit message signatures
	msgSigs, err := signDepositDatas(secrets, withdrawalAddr, network)
	if err != nil {
		return err
	}

	// Serialize the deposit data into bytes
	bytes, err := deposit.MarshalDepositData(msgSigs, withdrawalAddr, network)
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

// writeLock creates a cluster lock and writes it to disk for all peers.
func writeLock(lock cluster.Lock, clusterDir string, numNodes int, shareSets [][]*bls_sig.SecretKeyShare) error {
	var err error
	lock.SignatureAggregate, err = aggSign(shareSets, lock.LockHash)
	if err != nil {
		return err
	}

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
func getValidators(dvs []tbls.TSS) ([]cluster.DistValidator, error) {
	var vals []cluster.DistValidator
	for _, dv := range dvs {
		pk, err := dv.PublicKey().MarshalBinary()
		if err != nil {
			return []cluster.DistValidator{}, errors.Wrap(err, "marshal pubkey")
		}

		var pubshares [][]byte
		for i := 0; i < dv.NumShares(); i++ {
			share := dv.PublicShare(i + 1) // Shares are 1-indexed.
			b, err := share.MarshalBinary()
			if err != nil {
				return []cluster.DistValidator{}, errors.Wrap(err, "marshal pubshare")
			}
			pubshares = append(pubshares, b)
		}

		vals = append(vals, cluster.DistValidator{
			PubKey:    pk,
			PubShares: pubshares,
		})
	}

	return vals, nil
}

// writeKeysToKeymanager writes validator keys to the provided keymanager addresses.
func writeKeysToKeymanager(ctx context.Context, addrs []string, numNodes int, shareSets [][]*bls_sig.SecretKeyShare) error {
	// Ping all keymanager addresses to check if they are accessible to avoid partial writes
	for i := 0; i < numNodes; i++ {
		if err := verifyConnection(ctx, addrs[i]); err != nil {
			return err
		}
	}

	for i := 0; i < numNodes; i++ {
		var secrets []*bls_sig.SecretKey
		for _, shares := range shareSets {
			secret, err := tblsconv.ShareToSecret(shares[i])
			if err != nil {
				return err
			}
			secrets = append(secrets, secret)
		}

		err := postKeysToKeymanager(ctx, addrs[i], secrets)
		if err != nil {
			log.Error(ctx, "Failed to push keys", err, z.Str("addr", addrs[i]))
			return err
		}

		log.Debug(ctx, "Pushed keys to keymanager", z.Str("addr", addrs[i]))
	}

	log.Info(ctx, "Pushed all validator keys to respective keymanagers")

	return nil
}

// postKeysToKeymanager pushes the secrets to the provided keymanager address. The HTTP request times out after 10s.
func postKeysToKeymanager(ctx context.Context, addr string, secrets []*bls_sig.SecretKey) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	reqBody, err := keystore.KeymanagerReqBody(secrets)
	if err != nil {
		return err
	}

	reqBytes, err := json.Marshal(reqBody)
	if err != nil {
		return errors.New("marshal keymanager request body")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, addr, bytes.NewReader(reqBytes))
	if err != nil {
		return errors.Wrap(err, "new post request", z.Str("url", addr))
	}
	req.Header.Add("Content-Type", `application/json`)

	resp, err := new(http.Client).Do(req)
	if err != nil {
		return errors.Wrap(err, "post validator keys to keymanager")
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "read response")
	}
	resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return errors.New("failed posting keys", z.Int("status", resp.StatusCode), z.Str("body", string(data)))
	}

	return nil
}

// writeKeysToDisk writes validator keyshares to disk. It assumes that the directory for each node already exists.
func writeKeysToDisk(numNodes int, clusterDir string, insecureKeys bool, shareSets [][]*bls_sig.SecretKeyShare) error {
	for i := 0; i < numNodes; i++ {
		var secrets []*bls_sig.SecretKey
		for _, shares := range shareSets {
			secret, err := tblsconv.ShareToSecret(shares[i])
			if err != nil {
				return err
			}
			secrets = append(secrets, secret)
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
	forkVersion, err := eth2util.NetworkToForkVersion(conf.Network)
	if err != nil {
		return cluster.Definition{}, err
	}

	var ops []cluster.Operator
	for i := 0; i < conf.NumNodes; i++ {
		ops = append(ops, cluster.Operator{})
	}
	threshold := safeThreshold(ctx, conf.NumNodes, conf.Threshold)

	def, err := cluster.NewDefinition(conf.Name, conf.NumDVs, threshold, conf.FeeRecipient,
		conf.WithdrawalAddr, forkVersion, cluster.Creator{}, ops, rand.Reader)
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

// checksumAddr returns a valid EIP55-compliant checksummed ethereum address. Returns an error if a valid address cannot be constructed.
func checksumAddr(a string) (string, error) {
	if !common.IsHexAddress(a) {
		return "", errors.New("invalid address", z.Str("address", a))
	}

	return common.HexToAddress(a).Hex(), nil
}

// validateDef returns an error if the provided cluster definition is invalid.
func validateDef(ctx context.Context, insecureKeys bool, keymanagerAddrs []string, def cluster.Definition) error {
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

	if insecureKeys && isMainNetwork(network) {
		return errors.New("insecure keys not supported on mainnet")
	} else if insecureKeys {
		log.Warn(ctx, "Insecure keystores configured. ONLY DO THIS DURING TESTING", nil)
	}

	if def.Name == "" {
		return errors.New("name not provided")
	}

	if !eth2util.ValidNetwork(network) {
		return errors.New("unsupported network", z.Str("network", network))
	}

	// TODO(corver): Refactor validateWithdrawalAddr to take a slice of withdrawal addresses.
	vaddrs, err := def.LegacyValidatorAddresses()
	if err != nil {
		return err
	}

	return validateWithdrawalAddr(vaddrs.WithdrawalAddress, network)
}

// aggSign returns a bls aggregate signatures of the message signed by all the shares.
func aggSign(secrets [][]*bls_sig.SecretKeyShare, message []byte) ([]byte, error) {
	var sigs []*bls_sig.Signature
	for _, shares := range secrets {
		for _, share := range shares {
			secret, err := tblsconv.ShareToSecret(share)
			if err != nil {
				return nil, err
			}
			sig, err := tbls.Sign(secret, message)
			if err != nil {
				return nil, err
			}
			sigs = append(sigs, sig)
		}
	}

	aggSig, err := tbls.Scheme().AggregateSignatures(sigs...)
	if err != nil {
		return nil, errors.Wrap(err, "aggregate signatures")
	}

	b, err := aggSig.MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "marshal signature")
	}

	return b, nil
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

// verifyConnection returns an error if the provided HTTP address is not reachable.
func verifyConnection(ctx context.Context, addr string) error {
	u, err := url.Parse(addr)
	if err != nil {
		return errors.Wrap(err, "parse address")
	}

	var d net.Dialer
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	conn, err := d.DialContext(ctx, "tcp", u.Host)
	if err != nil {
		return errors.Wrap(err, "cannot ping address", z.Str("addr", addr))
	}
	conn.Close()

	return nil
}
