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
	"net"
	"os"
	"path"
	"strings"
	"text/template"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/obolnetwork/charon/app"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/eth2util/deposit"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
)

const scriptTmpl = `#!/usr/bin/env bash

# This script run a charon node using the p2pkey in the
# local directory and the manifest in the parent directory

{{.CharonBin}} run \
{{range .Flags}}  {{.}} \
{{end}}`

const clusterTmpl = `#!/usr/bin/env bash

# This script runs all the charon nodes in
# the sub-directories; the whole cluster.

if (type -P tmux >/dev/null && type -P teamocil >/dev/null); then
  echo "Commands tmux and teamocil are installed"
  tmux new-session 'teamocil --layout teamocil.yml'
else
  echo "⚠️ Commands tmux and teamocil are not installed, output will be merged"

  trap "exit" INT TERM ERR
  trap "kill 0" EXIT

  {{range .}} {{.}} &
  {{end}}

  wait
fi
`

const teamocilTmpl = `
windows:
  - name: charon-simnet
    root: /tmp/charon-simnet
    layout: tiled
    panes: {{range .}}
      -  {{.}}
{{end}}
`

const (
	defaultWithdrawalAddr = "0x0000000000000000000000000000000000000000"
	defaultNetwork        = "prater"
)

type clusterConfig struct {
	ClusterDir string
	Clean      bool

	NumNodes       int
	NumDVs         int
	Threshold      int
	WithdrawalAddr string
	Network        string

	SplitKeys    bool
	SplitKeysDir string

	ConfigEnabled   bool
	ConfigSimnet    bool
	ConfigPortStart int
	ConfigBinary    string
}

func newCreateClusterCmd(runFunc func(io.Writer, clusterConfig) error) *cobra.Command {
	var conf clusterConfig

	cmd := &cobra.Command{
		Use:   "cluster",
		Short: "Create private keys and configuration files needed to run a distributed validator cluster locally",
		Long: "Creates a local charon cluster configuration including validator keys, charon p2p keys, and a cluster manifest. " +
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

	flags.BoolVar(&config.SplitKeys, "split-existing-keys", false, "Split an existing validator's private key into a set of distributed validator private key shares. Does not re-create deposit data for this key.")
	flags.StringVar(&config.SplitKeysDir, "split-keys-dir", "", "Directory containing keys to split. Expects keys in keystore-*.json and passwords in keystore-*.txt. Requires --split-existing-keys.")

	flags.BoolVar(&config.ConfigEnabled, "config", false, "Enables creation of local non-docker config files.")
	flags.BoolVar(&config.ConfigSimnet, "config-simnet", true, "Configures a simulated network cluster with mock beacon node and mock validator clients. It showcases a running charon in isolation. Requires --config.")
	flags.StringVar(&config.ConfigBinary, "config-binary", "", "Path of the charon binary to use in the config files. Defaults to this binary if empty. Requires --config.")
	flags.IntVar(&config.ConfigPortStart, "config-port-start", 16000, "Starting port number used in config files. Requires --config.")
}

func runCreateCluster(w io.Writer, conf clusterConfig) error { //nolint:gocognit
	if conf.Clean {
		// Remove previous directories
		if err := os.RemoveAll(conf.ClusterDir); err != nil {
			return errors.Wrap(err, "remove cluster dir")
		}
	} else if _, err := os.Stat(path.Join(conf.ClusterDir, "manifest.json")); err == nil {
		// TODO(xenowits): replace "manifest.json" with "cluster_lock.json"
		return errors.New("existing cluster found. Try again with --clean")
	}

	// Create cluster directory at given location
	if err := os.MkdirAll(conf.ClusterDir, 0o755); err != nil {
		return errors.Wrap(err, "mkdir")
	}

	if conf.ConfigBinary == "" {
		// Get charon binary to include in run scripts
		var err error
		conf.ConfigBinary, err = os.Executable()
		if err != nil {
			return errors.Wrap(err, "get charon binary")
		}
	}

	// Currently, we assume that we create a cluster of ONLY 1 Distributed Validator
	// TODO(xenowits): add flag to specify the number of distributed validators in a cluster
	numDVs := 1

	// Get root bls secrets
	secrets, err := getKeys(conf, numDVs)
	if err != nil {
		return err
	}

	// Get function to create sequential ports
	nextPort := nextPortFunc(conf.ConfigPortStart)

	// Generate threshold bls key shares
	dvs, shareSets, err2 := getTSSShares(secrets, conf)
	if err2 != nil {
		return err2
	}

	// Create p2p peers
	peers, err := createPeers(conf, nextPort, shareSets)
	if err != nil {
		return err
	}

	// Create public keys and message signatures to write as deposit data file
	pubkeys, msgSigs, err := createDepositData(secrets, conf.WithdrawalAddr, conf.Network, numDVs)
	if err != nil {
		return nil
	}

	if err := writeDepositData(conf, pubkeys, msgSigs, conf.WithdrawalAddr, conf.Network); err != nil {
		return err
	}

	// TODO(corver): Write deposit datas if not simnet

	if err := writeManifest(conf, dvs, peers); err != nil {
		return err
	}

	if conf.ConfigEnabled {
		err = writeClusterScript(conf.ClusterDir, conf.NumNodes)
		if err != nil {
			return errors.Wrap(err, "write cluster script")
		}

		err = writeTeamocilYML(conf.ClusterDir, conf.NumNodes)
		if err != nil {
			return errors.Wrap(err, "write teamocil.yml")
		}
	}

	if conf.SplitKeys {
		writeWarning(w)
	}

	writeOutput(w, conf)

	return nil
}

func createDepositData(secrets []*bls_sig.SecretKey, withdrawalAddr string, network string, numDVs int) ([]eth2p0.BLSPubKey, []eth2p0.BLSSignature, error) {
	// TODO(xenowits): add flag to specify the number of distributed validators in a cluster
	// Currently, we assume that we create a cluster of ONLY 1 Distributed Validator
	var pubkeys []eth2p0.BLSPubKey
	var msgSigs []eth2p0.BLSSignature

	for i := 0; i < numDVs; i++ {
		sk := secrets[i] // Secret key for this DV
		pk, err := sk.GetPublicKey()
		if err != nil {
			return nil, nil, errors.Wrap(err, "secret to pubkey")
		}

		pubkey, err := tblsconv.KeyToETH2(pk)
		if err != nil {
			return nil, nil, err
		}

		withdrawalAddr, err := checksumAddr(withdrawalAddr)
		if err != nil {
			return nil, nil, err
		}

		err = validNetwork(withdrawalAddr, network)
		if err != nil {
			return nil, nil, err
		}

		msgRoot, err := deposit.GetMessageSigningRoot(pubkey, withdrawalAddr, network)
		if err != nil {
			return nil, nil, err
		}

		sig, err := tbls.Sign(sk, msgRoot[:])
		if err != nil {
			return nil, nil, err
		}

		sigEth2 := tblsconv.SigToETH2(sig)

		pubkeys = append(pubkeys, pubkey)
		msgSigs = append(msgSigs, sigEth2)
	}

	return pubkeys, msgSigs, nil
}

func createPeers(conf clusterConfig, nextPort func() int, shareSets [][]*bls_sig.SecretKeyShare) ([]p2p.Peer, error) {
	var peers []p2p.Peer
	for i := 0; i < conf.NumNodes; i++ {
		peer, err := newPeer(conf, i, nextPort)
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

		if err := keystore.StoreKeys(secrets, nodeDir(conf.ClusterDir, i)); err != nil {
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
func getKeys(conf clusterConfig, numDVs int) ([]*bls_sig.SecretKey, error) {
	if conf.SplitKeys {
		if conf.SplitKeysDir == "" {
			return nil, errors.New("--split-keys-dir required when splitting keys")
		}

		return keystore.LoadKeys(conf.SplitKeysDir)
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

// writeDepositData writes deposit data to disk for the DVs in a cluster.
func writeDepositData(config clusterConfig, pubkeys []eth2p0.BLSPubKey, msgSigs []eth2p0.BLSSignature, withdrawalAddr, network string) error {
	depositPath := path.Join(config.ClusterDir, "deposit-data.json")

	// serialize the deposit data into bytes
	bytes, err := deposit.MarshalDepositData(pubkeys, msgSigs, withdrawalAddr, network)
	if err != nil {
		return err
	}

	err = os.WriteFile(depositPath, bytes, 0o400) // read-only
	if err != nil {
		return errors.Wrap(err, "write deposit data")
	}

	return nil
}

func writeManifest(config clusterConfig, tss []tbls.TSS, peers []p2p.Peer) error {
	manifest := app.Manifest{
		DVs:   tss,
		Peers: peers,
	}
	manifestJSON, err := json.MarshalIndent(manifest, "", " ")
	if err != nil {
		return errors.Wrap(err, "json marshal manifest")
	}

	manifestPath := path.Join(config.ClusterDir, "manifest.json")
	if err = os.WriteFile(manifestPath, manifestJSON, 0o600); err != nil {
		return errors.Wrap(err, "write manifest.json")
	}

	return nil
}

// newPeer returns a new peer, generating a p2pkey and ENR and node directory and run script in the process.
func newPeer(conf clusterConfig, peerIdx int, nextPort func() int) (p2p.Peer, error) {
	tcp := net.TCPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: nextPort(),
	}

	udp := net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: nextPort(),
	}

	dir := nodeDir(conf.ClusterDir, peerIdx)

	p2pKey, err := p2p.NewSavedPrivKey(dir)
	if err != nil {
		return p2p.Peer{}, errors.Wrap(err, "create p2p key")
	}

	var r enr.Record
	r.Set(enr.IPv4(tcp.IP))
	r.Set(enr.TCP(tcp.Port))
	r.Set(enr.UDP(udp.Port))
	r.SetSeq(0)

	err = enode.SignV4(&r, p2pKey)
	if err != nil {
		return p2p.Peer{}, errors.Wrap(err, "enode sign")
	}

	peer, err := p2p.NewPeer(r, peerIdx)
	if err != nil {
		return p2p.Peer{}, errors.Wrap(err, "new peer")
	}

	if conf.ConfigEnabled {
		if err := writeRunScript(conf, dir, nextPort(), tcp.String(), udp.String(), nextPort()); err != nil {
			return p2p.Peer{}, errors.Wrap(err, "write run script")
		}
	}

	return peer, nil
}

// writeOutput writes the gen_cluster output.
func writeOutput(out io.Writer, conf clusterConfig) {
	var sb strings.Builder
	_, _ = sb.WriteString("Created charon cluster:\n")
	_, _ = sb.WriteString(fmt.Sprintf(" --split-existing-keys=%v\n", conf.SplitKeys))
	_, _ = sb.WriteString(fmt.Sprintf(" --config=%v\n", conf.ConfigEnabled))
	if conf.ConfigEnabled {
		_, _ = sb.WriteString(fmt.Sprintf(" --config-simnet=%v\n", conf.ConfigSimnet))
		_, _ = sb.WriteString(fmt.Sprintf(" --config-binary=%v\n", conf.ConfigBinary))
	}
	_, _ = sb.WriteString("\n")
	_, _ = sb.WriteString(strings.TrimSuffix(conf.ClusterDir, "/") + "/\n")
	_, _ = sb.WriteString("├─ manifest.json\tCluster manifest defines the cluster; used by all nodes\n")
	_, _ = sb.WriteString("├─ deposit-data.json\tDeposit data file is used to activate a Distributed Validator on DV Launchpad\n")

	if conf.ConfigEnabled {
		_, _ = sb.WriteString("├─ run_cluster.sh\tConvenience script to run all nodes\n")
		_, _ = sb.WriteString("├─ teamocil.yml\t\tTeamocil config for splitting logs in tmux panes\n")
	}
	_, _ = sb.WriteString(fmt.Sprintf("├─ node[0-%d]/\t\tDirectory for each node\n", conf.NumNodes-1))
	_, _ = sb.WriteString("│  ├─ p2pkey\t\tP2P networking private key for node authentication\n")
	_, _ = sb.WriteString("│  ├─ keystore-*.json\tValidator private share key for duty signing\n")
	_, _ = sb.WriteString("│  ├─ keystore-*.txt\tKeystore password files for keystore-*.json\n")
	if conf.ConfigEnabled {
		_, _ = sb.WriteString("│  ├─ run.sh\t\tConfig script to run the node\n")
	}

	_, _ = fmt.Fprint(out, sb.String())
}

// writeRunScript creates run script for a node.
func writeRunScript(conf clusterConfig, nodeDir string, monitoringPort int,
	tcpAddr string, udpAddr string, validatorAPIPort int,
) error {
	f, err := os.Create(nodeDir + "/run.sh")
	if err != nil {
		return errors.Wrap(err, "create run.sh")
	}
	defer f.Close()

	// Flags for running a node
	var flags []string
	flags = append(flags, fmt.Sprintf("--data-dir=\"%s\"", nodeDir))
	flags = append(flags, fmt.Sprintf("--manifest-file=\"%s/manifest.json\"", conf.ClusterDir))
	flags = append(flags, fmt.Sprintf("--monitoring-address=\"127.0.0.1:%d\"", monitoringPort))
	flags = append(flags, fmt.Sprintf("--validator-api-address=\"127.0.0.1:%d\"", validatorAPIPort))
	flags = append(flags, fmt.Sprintf("--p2p-tcp-address=%s", tcpAddr))
	flags = append(flags, fmt.Sprintf("--p2p-udp-address=%s", udpAddr))
	if conf.ConfigSimnet {
		flags = append(flags, "--simnet-beacon-mock")
		flags = append(flags, "--simnet-validator-mock")
	}

	tmpl, err := template.New("").Parse(scriptTmpl)
	if err != nil {
		return errors.Wrap(err, "new template")
	}

	err = tmpl.Execute(f, struct {
		CharonBin string
		Flags     []string
	}{CharonBin: conf.ConfigBinary, Flags: flags})
	if err != nil {
		return errors.Wrap(err, "execute template")
	}

	err = os.Chmod(nodeDir+"/run.sh", 0o755)
	if err != nil {
		return errors.Wrap(err, "change permissions")
	}

	return nil
}

// writeClusterScript creates script to run all the nodes in the cluster.
func writeClusterScript(clusterDir string, n int) error {
	var cmds []string
	for i := 0; i < n; i++ {
		cmds = append(cmds, fmt.Sprintf("%s/node%d/run.sh", clusterDir, i))
	}

	f, err := os.Create(clusterDir + "/run_cluster.sh")
	if err != nil {
		return errors.Wrap(err, "create run cluster")
	}

	tmpl, err := template.New("").Parse(clusterTmpl)
	if err != nil {
		return errors.Wrap(err, "new template")
	}

	err = tmpl.Execute(f, cmds)
	if err != nil {
		return errors.Wrap(err, "execute template")
	}

	err = os.Chmod(clusterDir+"/run_cluster.sh", 0o755)
	if err != nil {
		return errors.Wrap(err, "change permissions")
	}

	return nil
}

// writeTeamocilYML creates teamocil configurations file to show the nodes output in different tmux panes.
func writeTeamocilYML(clusterDir string, n int) error {
	var cmds []string
	for i := 0; i < n; i++ {
		cmds = append(cmds, fmt.Sprintf("%s/node%d/run.sh", clusterDir, i))
	}

	f, err := os.Create(clusterDir + "/teamocil.yml")
	if err != nil {
		return errors.Wrap(err, "create teamocil.yml")
	}

	tmpl, err := template.New("").Parse(teamocilTmpl)
	if err != nil {
		return errors.Wrap(err, "new template")
	}

	err = tmpl.Execute(f, cmds)
	if err != nil {
		return errors.Wrap(err, "execute template")
	}

	err = os.Chmod(clusterDir+"/teamocil.yml", 0o644)
	if err != nil {
		return errors.Wrap(err, "change permissions")
	}

	return nil
}

// nodeDir returns a node directory.
func nodeDir(clusterDir string, i int) string {
	return fmt.Sprintf("%s/node%d", clusterDir, i)
}

// nextPortFunc returns a next port function starting at start port.
func nextPortFunc(startPort int) func() int {
	port := startPort
	return func() int {
		port++
		return port
	}
}

// checksumAddr returns a valid checksummed ethereum address. Returns an error if a valid address cannot be constructed.
func checksumAddr(a string) (string, error) {
	if !common.IsHexAddress(a) {
		return "", errors.New("invalid address")
	}

	hexAddr := common.HexToAddress(a)

	return hexAddr.Hex(), nil
}

// validNetwork returns an error if the input network is not supported or certain conditions are not met.
func validNetwork(addr, network string) error {
	validNetworks := []string{"prater", "kintsugi", "kiln", "gnosis", "mainnet"}

	// We cannot allow a zero withdrawal address on mainnet or gnosis.
	if addr == defaultWithdrawalAddr && (network == "mainnet" || network == "gnosis") {
		return errors.New("zero address forbidden on this network", z.Str("network", network))
	}

	for _, n := range validNetworks {
		if n == network {
			return nil
		}
	}

	return errors.New("unsupported network", z.Str("network", network))
}
