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
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util/deposit"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

const (
	clusterName           = "local"
	defaultWithdrawalAddr = "0x0000000000000000000000000000000000000000"
	defaultNetwork        = "prater"
)

type clusterConfig struct {
	ClusterDir string
	Clean      bool

	NumNodes       int
	Threshold      int
	WithdrawalAddr string
	Network        string
	NumDVs         int

	SplitKeys    bool
	SplitKeysDir string
}

func newCreateClusterCmd(runFunc func(io.Writer, clusterConfig) error) *cobra.Command {
	var conf clusterConfig

	cmd := &cobra.Command{
		Use:   "cluster",
		Short: "Create private keys and configuration files needed to run a distributed validator cluster locally",
		Long: "Creates a local charon cluster configuration including validator keys, charon p2p keys, cluster-lock.json and a deposit-data.json. " +
			"See flags for supported features.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFunc(cmd.OutOrStdout(), conf)
		},
	}

	bindClusterFlags(cmd.Flags(), &conf)

	return cmd
}

func bindClusterFlags(flags *pflag.FlagSet, config *clusterConfig) {
	flags.StringVar(&config.ClusterDir, "cluster-dir", ".charon/cluster", "The target folder to create the cluster in.")
	flags.IntVarP(&config.NumNodes, "nodes", "n", 4, "The number of charon nodes in the cluster.")
	flags.IntVarP(&config.Threshold, "threshold", "t", 3, "The threshold required for signature reconstruction. Minimum is n-(ceil(n/3)-1).")
	flags.StringVar(&config.WithdrawalAddr, "withdrawal-address", defaultWithdrawalAddr, "Ethereum address to receive the returned stake and accrued rewards.")
	flags.StringVar(&config.Network, "network", defaultNetwork, "Ethereum network to create validators for. Options: mainnet, prater, kintsugi, kiln, gnosis.")
	flags.BoolVar(&config.Clean, "clean", false, "Delete the cluster directory before generating it.")
	flags.IntVar(&config.NumDVs, "num-validators", 1, "The number of distributed validators needed in the cluster.")
	flags.BoolVar(&config.SplitKeys, "split-existing-keys", false, "Split an existing validator's private key into a set of distributed validator private key shares. Does not re-create deposit data for this key.")
	flags.StringVar(&config.SplitKeysDir, "split-keys-dir", "", "Directory containing keys to split. Expects keys in keystore-*.json and passwords in keystore-*.txt. Requires --split-existing-keys.")
}

func runCreateCluster(w io.Writer, conf clusterConfig) error {
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

	if err := validateClusterConfig(conf); err != nil {
		return err
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

	if err = writeLock(conf, dvs, peers); err != nil {
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

		if err := os.MkdirAll(path.Join(nodeDir(conf.ClusterDir, i), "/validator_keys"), 0o755); err != nil {
			return nil, errors.Wrap(err, "mkdir validator_keys")
		}

		if err := keystore.StoreKeys(secrets, path.Join(nodeDir(conf.ClusterDir, i), "/validator_keys")); err != nil {
			return nil, err
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
		return nil
	}

	// Serialize the deposit data into bytes
	bytes, err := deposit.MarshalDepositData(msgSigs, conf.WithdrawalAddr, conf.Network)
	if err != nil {
		return err
	}

	// Write it to disk
	depositPath := path.Join(conf.ClusterDir, "deposit-data.json")
	err = os.WriteFile(depositPath, bytes, 0o400) // read-only
	if err != nil {
		return errors.Wrap(err, "write deposit data")
	}

	return nil
}

// writeLock creates a cluster lock and writes it to disk.
func writeLock(conf clusterConfig, dvs []tbls.TSS, peers []p2p.Peer) error {
	lock, err := newLock(conf, dvs, peers)
	if err != nil {
		return err
	}

	b, err := json.MarshalIndent(lock, "", " ")
	if err != nil {
		return errors.Wrap(err, "marshal cluster lock")
	}

	lockPath := path.Join(conf.ClusterDir, "cluster-lock.json")
	err = os.WriteFile(lockPath, b, 0o400) // read-only
	if err != nil {
		return errors.Wrap(err, "write cluster lock")
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
		pk, err := tblsconv.KeyToCore(dv.PublicKey())
		if err != nil {
			return cluster.Lock{}, err
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
			PubKey:    string(pk),
			PubShares: pubshares,
		})
	}

	def := cluster.NewDefinition(clusterName, len(dvs), conf.Threshold, "", "", "", ops, rand.Reader)

	return cluster.Lock{
		Definition: def,
		Validators: vals,
	}, nil
}

// newPeer returns a new peer, generating a p2pkey and ENR and node directory and run script in the process.
func newPeer(conf clusterConfig, peerIdx int) (p2p.Peer, error) {
	dir := nodeDir(conf.ClusterDir, peerIdx)

	p2pKey, err := p2p.NewSavedPrivKey(dir)
	if err != nil {
		return p2p.Peer{}, errors.Wrap(err, "create charon-enr-private-key")
	}

	var r enr.Record
	err = enode.SignV4(&r, p2pKey)
	if err != nil {
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
	_, _ = sb.WriteString("├─ cluster-lock.json\tCluster lock defines the cluster lock file which is signed by all nodes\n")
	_, _ = sb.WriteString("├─ deposit-data.json\tDeposit data file is used to activate a Distributed Validator on DV Launchpad\n")
	_, _ = sb.WriteString(fmt.Sprintf("├─ node[0-%d]/\t\tDirectory for each node\n", conf.NumNodes-1))
	_, _ = sb.WriteString("│  ├─ charon-enr-private-key\t\tCharon networking private key for node authentication\n")
	_, _ = sb.WriteString("│  ├─ validator_keys\t\tValidator keystores and password\n")
	_, _ = sb.WriteString("│  │  ├─ keystore-*.json\tValidator private share key for duty signing\n")
	_, _ = sb.WriteString("│  │  ├─ keystore-*.txt\tKeystore password files for keystore-*.json\n")

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

// validNetworks defines the set of valid networks.
var validNetworks = map[string]bool{
	"prater":   true,
	"kintsugi": true,
	"kiln":     true,
	"gnosis":   true,
	"mainnet":  true,
}

// validateClusterConfig returns an error if the cluster config is invalid.
func validateClusterConfig(conf clusterConfig) error {
	if !validNetworks[conf.Network] {
		return errors.New("unsupported network", z.Str("network", conf.Network))
	}

	// We cannot allow a zero withdrawal address on mainnet or gnosis.
	if (conf.Network == "mainnet" || conf.Network == "gnosis") &&
		conf.WithdrawalAddr == defaultWithdrawalAddr {
		return errors.New("zero address forbidden on this network", z.Str("network", conf.Network))
	}

	return nil
}
