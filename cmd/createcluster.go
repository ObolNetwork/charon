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
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/deposit"
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
	Name       string
	ClusterDir string
	Clean      bool

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
	flags.IntVarP(&config.NumNodes, "nodes", "n", minNodes, "The number of charon nodes in the cluster. Minimum is 4.")
	flags.IntVarP(&config.Threshold, "threshold", "t", 0, "Optional override of threshold required for signature reconstruction. Defaults to ceil(n*2/3) if zero. Warning, non-default values decrease security.")
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
	} else if _, err := os.Stat(path.Join(conf.ClusterDir, "cluster-lock.json")); err == nil {
		return errors.New("existing cluster found. Try again with --clean")
	}

	// Create cluster directory at given location
	if err := os.MkdirAll(conf.ClusterDir, 0o755); err != nil {
		return errors.Wrap(err, "mkdir")
	}

	// Map prater to goerli to ensure backwards compatibility with older cluster definitions and cluster locks.
	// TODO(xenowits): Remove the mapping later.
	if conf.Network == eth2util.Prater {
		conf.Network = eth2util.Goerli.Name
	}

	if err := validateClusterConfig(ctx, conf); err != nil {
		return err
	}

	safeThreshold := cluster.Threshold(conf.NumNodes)
	if conf.Threshold == 0 {
		conf.Threshold = safeThreshold
	} else if conf.Threshold != safeThreshold {
		log.Warn(ctx, "Non standard `--threshold` flag provided, this will affect cluster safety", nil, z.Int("threshold", conf.Threshold), z.Int("safe_threshold", safeThreshold))
	}

	// Get root bls secrets
	secrets, err := getKeys(conf)
	if err != nil {
		return err
	}

	// Generate threshold bls key shares
	dvs, shareSets, err2 := getTSSShares(secrets, conf)
	if err2 != nil {
		return err2
	}

	// Create p2p peers
	peers, err := createPeers(conf, shareSets)
	if err != nil {
		return err
	}

	if err = writeDepositData(conf, secrets); err != nil {
		return err
	}

	if err = writeLock(conf, dvs, peers, shareSets); err != nil {
		return err
	}

	if conf.SplitKeys {
		writeWarning(w)
	}

	writeOutput(w, conf)

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

// createPeers creates new peers from the provided config and saves validator keys to disk for each peer.
func createPeers(conf clusterConfig, shareSets [][]*bls_sig.SecretKeyShare) ([]p2p.Peer, error) {
	var peers []p2p.Peer
	for i := 0; i < conf.NumNodes; i++ {
		peer, err := newPeer(conf, i)
		if err != nil {
			return nil, err
		}

		peers = append(peers, peer)

		var secrets []*bls_sig.SecretKey
		for _, shares := range shareSets {
			secret, err := tblsconv.ShareToSecret(shares[i])
			if err != nil {
				return nil, err
			}
			secrets = append(secrets, secret)
		}

		keysDir := path.Join(nodeDir(conf.ClusterDir, i), "/validator_keys")

		if err := os.MkdirAll(keysDir, 0o755); err != nil {
			return nil, errors.Wrap(err, "mkdir validator_keys")
		}

		if conf.InsecureKeys {
			if err := keystore.StoreKeysInsecure(secrets, keysDir, keystore.ConfirmInsecureKeys); err != nil {
				return nil, err
			}
		} else {
			if err := keystore.StoreKeys(secrets, keysDir); err != nil {
				return nil, err
			}
		}
	}

	return peers, nil
}

func getTSSShares(secrets []*bls_sig.SecretKey, conf clusterConfig) ([]tbls.TSS, [][]*bls_sig.SecretKeyShare, error) {
	var (
		dvs    []tbls.TSS
		splits [][]*bls_sig.SecretKeyShare
	)
	for _, secret := range secrets {
		shares, verifier, err := tbls.SplitSecret(secret, conf.Threshold, conf.NumNodes, rand.Reader)
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
func getKeys(conf clusterConfig) ([]*bls_sig.SecretKey, error) {
	if conf.SplitKeys {
		if conf.SplitKeysDir == "" {
			return nil, errors.New("--split-keys-dir required when splitting keys")
		}

		return keystore.LoadKeys(conf.SplitKeysDir)
	}

	var secrets []*bls_sig.SecretKey
	for i := 0; i < conf.NumDVs; i++ {
		_, secret, err := tbls.KeygenWithSeed(rand.Reader)
		if err != nil {
			return nil, err
		}

		secrets = append(secrets, secret)
	}

	return secrets, nil
}

// writeDepositData writes deposit data to disk for the DVs in a cluster.
func writeDepositData(conf clusterConfig, secrets []*bls_sig.SecretKey) error {
	// Create deposit message signatures
	msgSigs, err := signDepositDatas(secrets, conf.WithdrawalAddr, conf.Network)
	if err != nil {
		return err
	}

	// Serialize the deposit data into bytes
	bytes, err := deposit.MarshalDepositData(msgSigs, conf.WithdrawalAddr, conf.Network)
	if err != nil {
		return err
	}

	for i := 0; i < conf.NumNodes; i++ {
		depositPath := path.Join(nodeDir(conf.ClusterDir, i), "deposit-data.json")
		err = os.WriteFile(depositPath, bytes, 0o400) // read-only
		if err != nil {
			return errors.Wrap(err, "write deposit data")
		}
	}

	return nil
}

// writeLock creates a cluster lock and writes it to disk.
func writeLock(conf clusterConfig, dvs []tbls.TSS, peers []p2p.Peer, shareSets [][]*bls_sig.SecretKeyShare) error {
	lock, err := newLock(conf, dvs, peers)
	if err != nil {
		return err
	}

	lock.SignatureAggregate, err = aggSign(shareSets, lock.LockHash)
	if err != nil {
		return err
	}

	b, err := json.MarshalIndent(lock, "", " ")
	if err != nil {
		return errors.Wrap(err, "marshal cluster lock")
	}

	for i := 0; i < conf.NumNodes; i++ {
		lockPath := path.Join(nodeDir(conf.ClusterDir, i), "cluster-lock.json")
		err = os.WriteFile(lockPath, b, 0o400) // read-only
		if err != nil {
			return errors.Wrap(err, "write cluster lock")
		}
	}

	return nil
}

// newLock returns a new unsigned cluster lock.
func newLock(conf clusterConfig, dvs []tbls.TSS, peers []p2p.Peer) (cluster.Lock, error) {
	var ops []cluster.Operator
	for _, p := range peers {
		enrStr, err := p2p.EncodeENR(p.ENR)
		if err != nil {
			return cluster.Lock{}, err
		}

		ops = append(ops, cluster.Operator{ENR: enrStr})
	}

	var vals []cluster.DistValidator
	for _, dv := range dvs {
		pk, err := dv.PublicKey().MarshalBinary()
		if err != nil {
			return cluster.Lock{}, errors.Wrap(err, "marshal pubkey")
		}

		var pubshares [][]byte
		for i := 0; i < dv.NumShares(); i++ {
			share := dv.PublicShare(i + 1) // Shares are 1-indexed.
			b, err := share.MarshalBinary()
			if err != nil {
				return cluster.Lock{}, errors.Wrap(err, "marshal pubshare")
			}
			pubshares = append(pubshares, b)
		}

		vals = append(vals, cluster.DistValidator{
			PubKey:    pk,
			PubShares: pubshares,
		})
	}

	forkVersion, err := eth2util.NetworkToForkVersion(conf.Network)
	if err != nil {
		return cluster.Lock{}, err
	}

	def, err := cluster.NewDefinition(conf.Name, len(dvs), conf.Threshold, conf.FeeRecipient, conf.WithdrawalAddr,
		forkVersion, cluster.Creator{}, ops, rand.Reader)
	if err != nil {
		return cluster.Lock{}, err
	}

	l := cluster.Lock{
		Definition: def,
		Validators: vals,
	}

	return l.SetLockHash()
}

// newPeer returns a new peer, generating a p2pkey and ENR and node directory and run script in the process.
func newPeer(conf clusterConfig, peerIdx int) (p2p.Peer, error) {
	dir := nodeDir(conf.ClusterDir, peerIdx)

	p2pKey, err := p2p.NewSavedPrivKey(dir)
	if err != nil {
		return p2p.Peer{}, errors.Wrap(err, "create charon-enr-private-key")
	}

	var r enr.Record
	if err = enode.SignV4(&r, p2pKey); err != nil {
		return p2p.Peer{}, errors.Wrap(err, "enode sign")
	}

	peer, err := p2p.NewPeer(r, peerIdx)
	if err != nil {
		return p2p.Peer{}, errors.Wrap(err, "new peer")
	}

	return peer, nil
}

// writeOutput writes the gen_cluster output.
func writeOutput(out io.Writer, conf clusterConfig) {
	var sb strings.Builder
	_, _ = sb.WriteString("Created charon cluster:\n")
	_, _ = sb.WriteString(fmt.Sprintf(" --split-existing-keys=%v\n", conf.SplitKeys))
	_, _ = sb.WriteString("\n")
	_, _ = sb.WriteString(strings.TrimSuffix(conf.ClusterDir, "/") + "/\n")
	_, _ = sb.WriteString(fmt.Sprintf("├─ node[0-%d]/\t\t\tDirectory for each node\n", conf.NumNodes-1))
	_, _ = sb.WriteString("│  ├─ charon-enr-private-key\tCharon networking private key for node authentication\n")
	_, _ = sb.WriteString("│  ├─ cluster-lock.json\t\tCluster lock defines the cluster lock file which is signed by all nodes\n")
	_, _ = sb.WriteString("│  ├─ deposit-data.json\t\tDeposit data file is used to activate a Distributed Validator on DV Launchpad\n")
	_, _ = sb.WriteString("│  ├─ validator_keys\t\tValidator keystores and password\n")
	_, _ = sb.WriteString("│  │  ├─ keystore-*.json\tValidator private share key for duty signing\n")
	_, _ = sb.WriteString("│  │  ├─ keystore-*.txt\t\tKeystore password files for keystore-*.json\n")

	_, _ = fmt.Fprint(out, sb.String())
}

// nodeDir returns a node directory.
func nodeDir(clusterDir string, i int) string {
	return fmt.Sprintf("%s/node%d", clusterDir, i)
}

// checksumAddr returns a valid EIP55-compliant checksummed ethereum address. Returns an error if a valid address cannot be constructed.
func checksumAddr(a string) (string, error) {
	if !common.IsHexAddress(a) {
		return "", errors.New("invalid address")
	}

	return common.HexToAddress(a).Hex(), nil
}

// validateClusterConfig returns an error if the cluster config is invalid.
func validateClusterConfig(ctx context.Context, conf clusterConfig) error {
	if conf.Name == "" {
		return errors.New("name not provided")
	}

	if conf.NumNodes < minNodes {
		return errors.New("insufficient number of nodes (min = 4)")
	}

	if !eth2util.ValidNetwork(conf.Network) {
		return errors.New("unsupported network", z.Str("network", conf.Network))
	}

	if conf.InsecureKeys && isMainNetwork(conf.Network) {
		return errors.New("insecure keys not supported on mainnet")
	} else if conf.InsecureKeys {
		log.Warn(ctx, "Insecure keystores configured. ONLY DO THIS DURING TESTING", nil)
	}

	return validateWithdrawalAddr(conf.WithdrawalAddr, conf.Network)
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
