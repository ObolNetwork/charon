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
	"errors"
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

type BootstrapConfig struct {
	Out          string
	Shares       int
	PasswordFile string
	Bootnodes    []string
}

// TODO(dhruv): rename back to keygen once it is deployed in production
type newKeygen struct {
	t        int
	password string
}

// newBoostrapCmd returns new bootstrap command with BootstrapConfig
func newBootstrapCmd(runFunc func(io.Writer, BootstrapConfig) error) *cobra.Command {
	var conf BootstrapConfig

	cmd := &cobra.Command{
		Use:   "bootstrap",
		Short: "Bootstraps a single validator centrally.",
		Long: `Generates a BLS12-381 validator private key in-memory, then splits it into a set of private key shares
using Shamir's Secret Sharing. Produces an EIP-2335 keystore file for each generated key share.
Also outputs a distributed validator profile.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFunc(cmd.OutOrStdout(), conf)
		},
	}

	bindBootstrapFlags(cmd.Flags(), &conf)
	return cmd
}

func bindBootstrapFlags(flags *pflag.FlagSet, config *BootstrapConfig) {
	flags.StringVarP(&config.Out, "out", "o", "./keys", "Output directory")
	flags.IntVarP(&config.Shares, "shares", "n", 4, "Number of key shares to generate")
	flags.StringVar(&config.PasswordFile, "password-file", "", "Path to a plain-text password file")
	flags.StringSliceVar(&config.Bootnodes, "bootnodes", nil, "List of bootnodes")
}

// runBootstrapCmd runs bootstrap command with the given BootstrapConfig. The BootstrapConfig
// helps to generate keyshares which are then saved into desired directories in json
func runBootstrapCmd(_ io.Writer, config BootstrapConfig) error {
	if config.Shares < 1 {
		return errors.New("Number of Shares should be >=1")
	}

	k := newKeygen{}

	// Figure out secret sharing params.
	k.t = config.Shares - ((config.Shares - 1) / 3)

	// Get password from file or prompt.
	err := getPassword(config, &k)
	if err != nil {
		return err
	}

	// Create "root" BLS key and polynomials.
	priPoly, pubPoly := crypto.NewTBLSPoly(uint(k.t))
	pubkey := pubPoly.Commit()
	pubkeyHex := crypto.BLSPointToHex(pubkey)

	// Save public polynomials (required to recover root sig from sig shares).
	scheme := &crypto.TBLSScheme{PubPoly: pubPoly}
	err = mkOutdir(config.Out)
	if err != nil {
		return err
	}

	// Saves generated TBLS scheme in config.Out directory
	err = saveScheme(scheme, pubkeyHex, config.Out)
	if err != nil {
		return err
	}

	// Create and save private key shares.
	priShares := priPoly.Shares(config.Shares)
	err = saveKeys(scheme, priShares, pubkeyHex, config.Out, k.password)
	if err != nil {
		return err
	}

	fmt.Println("Running trusted BLS threshold key generation ceremony")
	fmt.Printf("Params: n=%d t=%d\n", config.Shares, k.t)
	fmt.Println("Public key:", pubkeyHex)
	fmt.Println("Writing polynomials to", filepath.Join(config.Out, pubkeyHex+"-poly.json"))
	fmt.Println("Saving keys to", keyPath(pubkeyHex, 0, config.Out))

	return nil
}

func getPassword(config BootstrapConfig, k *newKeygen) error {
	if config.PasswordFile != "" {
		return readPassword(config.PasswordFile, k)
	} else {
		return promptPassword(k)
	}
}

func readPassword(passwordFile string, k *newKeygen) error {
	var err error
	k.password, err = crypto.ReadPlaintextPassword(passwordFile)
	if err != nil {
		return err
	}
	return nil
}

func promptPassword(k *newKeygen) error {
	password, err := prompt.PasswordPrompt("Input keystore password", prompt.NotEmpty)
	if err != nil {
		return err
	}

	confirmPassword, err := prompt.PasswordPrompt("Confirm keystore password", prompt.NotEmpty)
	if err != nil {
		return err
	}

	if password != confirmPassword {
		return errors.New("Passwords do not match")
	}

	k.password = password
	return nil
}

func mkOutdir(outDir string) error {
	err := os.MkdirAll(outDir, 0777)
	if err != nil {
		return err
	}

	return nil
}

func saveScheme(scheme *crypto.TBLSScheme, pubkeyHex string, outDir string) error {
	enc, err := scheme.Encode()
	if err != nil {
		return err
	}

	buf, err := json.MarshalIndent(enc, "", "\t")
	if err != nil {
		return err
	}

	err = os.WriteFile(filepath.Join(outDir, pubkeyHex+"-poly.json"), buf, 0666)
	if err != nil {
		return err
	}

	return nil
}

func keyPath(pubkeyHex string, i int, outDir string) string {
	name := fmt.Sprintf("%s-share-%04d.json", pubkeyHex, i)
	return filepath.Join(outDir, name)
}

func saveKeys(scheme *crypto.TBLSScheme, priShares []*share.PriShare, pubkeyHex string, outDir string, password string) error {
	for _, priShare := range priShares {
		err := saveKey(scheme, priShare, keyPath(pubkeyHex, priShare.I, outDir), password)

		if err != nil {
			return err
		}
	}
	return nil
}

func saveKey(scheme *crypto.TBLSScheme, priShare *share.PriShare, path string, password string) error {
	item, err := crypto.TBLSShareToKeystore(scheme, priShare, password)
	if err != nil {
		return err
	}

	if err := item.Save(path); err != nil {
		return err
	}
	return nil
}
