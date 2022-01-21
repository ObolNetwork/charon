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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/drand/kyber/share"
	"github.com/obolnetwork/charon/crypto"
	prompt "github.com/prysmaticlabs/prysm/shared/promptutil"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type bootstrapConfig struct {
	out          string
	shares       uint
	passwordFile string
	bootnodes    []string
}

// newBoostrapCmd returns new bootstrap command with bootstrapConfig
func newBootstrapCmd(runFunc func(io.Writer, bootstrapConfig)) *cobra.Command {
	var conf bootstrapConfig

	cmd := &cobra.Command{
		Use:   "bootstrap",
		Short: "Bootstraps a single validator centrally.",
		Long: `Generates a BLS12-381 validator private key in-memory, then splits it into a set of private key shares
using Shamir's Secret Sharing. Produces an EIP-2335 keystore file for each generated key share.
Also outputs a distributed validator profile.`,
		Args: cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			runFunc(cmd.OutOrStdout(), conf)
		},
	}

	bindBootstrapFlags(cmd.Flags(), &conf)
	return cmd
}

func bindBootstrapFlags(flags *pflag.FlagSet, config *bootstrapConfig) {
	flags.StringVarP(&config.out, "out", "o", "./keys", "Output directory")
	flags.UintVarP(&config.shares, "shares", "n", 4, "Number of key shares to generate")
	flags.StringVar(&config.passwordFile, "password-file", "", "Path to a plain-text password file")
	flags.StringSliceVar(&config.bootnodes, "bootnodes", nil, "List of bootnodes")
}

func runBootstrapCmd(_ io.Writer, config bootstrapConfig) {
	out := config.out
	passwordFile := config.passwordFile
	shares := config.shares
	if shares < 1 {
		shares = 1
	}
	k := newKeygen{
		outDir:       out,
		passwordFile: passwordFile,
		n:            shares,
	}
	k.run()
}

// TODO(dhruv): should be keygen once it is deployed in production
type newKeygen struct {
	// flags
	outDir       string
	passwordFile string
	n            uint
	bootnodes    []string
	// params
	t        uint
	password string
}

func (k *newKeygen) run() {
	fmt.Println("Running trusted BLS threshold key generation ceremony")
	// Figure out secret sharing params.
	k.t = k.n - ((k.n - 1) / 3)
	fmt.Printf("Params: n=%d t=%d\n", k.n, k.t)
	// Get password from file or prompt.
	k.getPassword()
	// Create "root" BLS key and polynomials.
	priPoly, pubPoly := crypto.NewTBLSPoly(k.t)
	pubkey := pubPoly.Commit()
	pubkeyHex := crypto.BLSPointToHex(pubkey)
	fmt.Println("Public key:", pubkeyHex)
	// Save public polynomials (required to recover root sig from sig shares).
	scheme := &crypto.TBLSScheme{PubPoly: pubPoly}
	k.mkOutdir()
	k.saveScheme(scheme, pubkeyHex)
	// Create private key shares.
	priShares := priPoly.Shares(int(k.n))
	k.saveKeys(scheme, priShares, pubkeyHex)
}

func (k *newKeygen) getPassword() {
	if k.passwordFile != "" {
		k.readPassword()
	} else {
		k.promptPassword()
	}
}

func (k *newKeygen) readPassword() {
	var err error
	k.password, err = crypto.ReadPlaintextPassword(k.passwordFile)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to read password")
	}
}

func (k *newKeygen) promptPassword() {
	password, err := prompt.PasswordPrompt("Input keystore password", prompt.NotEmpty)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to prompt password")
	}
	confirmPassword, err := prompt.PasswordPrompt("Confirm keystore password", prompt.NotEmpty)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to prompt password")
	}
	if password != confirmPassword {
		fmt.Println("Passwords do not match")
		os.Exit(1)
	}
	k.password = password
}

func (k *newKeygen) mkOutdir() {
	err := os.MkdirAll(k.outDir, 0777)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create out dir")
	}
}

func (k *newKeygen) saveScheme(scheme *crypto.TBLSScheme, pubkeyHex string) {
	enc, err := scheme.Encode()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to encode threshold BLS scheme info")
	}
	buf, err := json.MarshalIndent(enc, "", "\t")
	if err != nil {
		panic(err.Error())
	}
	polyName := filepath.Join(k.outDir, pubkeyHex+"-poly.json")
	fmt.Println("Writing polynomials to", polyName)
	err = os.WriteFile(polyName, buf, 0666)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to save public polynomials")
	}
}

func (k *newKeygen) keyPath(pubkeyHex string, i int) string {
	name := fmt.Sprintf("%s-share-%04d.json", pubkeyHex, i)
	return filepath.Join(k.outDir, name)
}

func (k *newKeygen) saveKeys(scheme *crypto.TBLSScheme, priShares []*share.PriShare, pubkeyHex string) {
	fmt.Println("Saving keys to", k.keyPath(pubkeyHex, 0))
	for _, priShare := range priShares {
		k.saveKey(scheme, priShare, k.keyPath(pubkeyHex, priShare.I))
	}
}

func (k *newKeygen) saveKey(scheme *crypto.TBLSScheme, priShare *share.PriShare, path string) {
	item, err := crypto.TBLSShareToKeystore(scheme, priShare, k.password)
	if err != nil {
		log.Fatal().Err(err).Int("key_share", priShare.I).Msg("Failed to create keystore for private key share")
	}
	if err := item.Save(path); err != nil {
		log.Fatal().Err(err).Msg("Failed to write keyshare")
	}
}
