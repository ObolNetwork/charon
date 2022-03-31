// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"crypto/rand"
	"io"
	"os"

	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil/keystore"
)

type splitKeyConfig struct {
	simnetConfig
	KeyDir string
}

func newSplitKeyClusterCmd(runFunc func(io.Writer, splitKeyConfig) error) *cobra.Command {
	var config splitKeyConfig

	cmd := &cobra.Command{
		Use:   "split-key-cluster",
		Short: "Generates a new cluster by splitting standard validator key(s)",
		Long: "Generates a new charon distributed validator cluster by " +
			"splitting standard validator key(s) into t-of-n Threshold BLS keys. " +
			"P2P keys and a cluster manifest are also generated. " +
			"This command is similar to gen-simnet, except that new keys are not generated " +
			"but split from existing validator keys",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFunc(cmd.OutOrStdout(), config)
		},
	}

	bindSimnetFlags(cmd.Flags(), &config.simnetConfig)
	cmd.Flags().StringVar(&config.KeyDir, "key-dir", ".",
		"The directory containing the standard validator keys (keystore-*.json) to split. "+
			"Note keystore passwords are expected in buddy keystore-*.txt files")

	return cmd
}

func runSplitKeyCluster(w io.Writer, config splitKeyConfig) error {
	charonBin := config.TestBinary
	if charonBin == "" {
		var err error
		charonBin, err = os.Executable()
		if err != nil {
			return errors.Wrap(err, "get charon binary")
		}
	}

	nextPort := nextPortFunc(config.PortStart)

	secrets, err := keystore.LoadKeys(config.KeyDir)
	if err != nil {
		return err
	}

	var (
		dvs    []tbls.TSS
		splits [][]*bls_sig.SecretKeyShare
	)
	for _, secret := range secrets {
		shares, verifier, err := tbls.SplitSecret(secret, config.Threshold, config.NumNodes, rand.Reader)
		if err != nil {
			return err
		}

		splits = append(splits, shares)

		tss, err := tbls.NewTSS(verifier, len(shares))
		if err != nil {
			return err
		}

		dvs = append(dvs, tss)
	}

	var peers []p2p.Peer
	for i := 0; i < config.NumNodes; i++ {
		peer, err := newPeer(config.ClusterDir, nodeDir(config.ClusterDir, i), charonBin, i, nextPort)
		if err != nil {
			return err
		}

		peers = append(peers, peer)

		var secrets []*bls_sig.SecretKey
		for _, split := range splits {
			secret, err := tblsconv.ShareToSecret(split[i])
			if err != nil {
				return err
			}
			secrets = append(secrets, secret)
		}

		if err := keystore.StoreKeys(secrets, nodeDir(config.ClusterDir, i)); err != nil {
			return err
		}
	}

	if err := writeManifest(config.simnetConfig, dvs, peers); err != nil {
		return err
	}

	writeOutput(w, config.simnetConfig, charonBin, "split key cluster")

	return nil
}
