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
	prompt "github.com/prysmaticlabs/prysm/shared/promptutil"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/obolnetwork/charon/crypto"
)

type BootstrapConfig struct {
	Out          string
	Shares       int
	PasswordFile string
	Bootnodes    []string
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
func runBootstrapCmd(w io.Writer, config BootstrapConfig) error {
	if config.Shares < 1 {
		return errors.New("invalid non-positive shares")
	}

	if err := os.MkdirAll(config.Out, 0755); err != nil {
		return err
	}

	password, err := getPassword(config)
	if err != nil {
		return err
	}

	threshold := config.Shares - ((config.Shares - 1) / 3)

	// Create "root" BLS key and polynomials.
	priPoly, pubPoly := crypto.NewTBLSPoly(uint(threshold))

	pubkey := pubPoly.Commit()
	pubkeyHex := crypto.BLSPointToHex(pubkey)

	// Save public polynomials (required to recover root sig from sig shares).
	scheme := &crypto.TBLSScheme{PubPoly: pubPoly}

	// Saves generated TBLS scheme in config.Out directory
	polyFile := filepath.Join(config.Out, pubkeyHex+"-poly.json")
	err = saveScheme(scheme, polyFile)
	if err != nil {
		return err
	}

	// Create and save private key shares.
	priShares := priPoly.Shares(config.Shares)
	err = saveKeys(scheme, priShares, pubkeyHex, config.Out, password)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintln(w, "Ran trusted BLS threshold key generation ceremony")
	_, _ = fmt.Fprintf(w, "Params: shares=%d threshold=%d\n", config.Shares, threshold)
	_, _ = fmt.Fprintln(w, "Public key:", pubkeyHex)
	_, _ = fmt.Fprintln(w, "Saved polynomials to", polyFile)
	_, _ = fmt.Fprintln(w, "Saved keys to", keyPath(config.Out, pubkeyHex, 0))

	return nil
}

// getPassword returns the keystore password either from a file if provided or from user prompt.
func getPassword(config BootstrapConfig) (string, error) {
	if config.PasswordFile != "" {
		return crypto.ReadPlaintextPassword(config.PasswordFile)
	} else {
		return promptPassword()
	}
}

func promptPassword() (string, error) {
	password, err := prompt.PasswordPrompt("Enter keystore password", prompt.NotEmpty)
	if err != nil {
		return "", err
	}

	confirm, err := prompt.PasswordPrompt("Confirm keystore password", prompt.NotEmpty)
	if err != nil {
		return "", err
	}

	if password != confirm {
		return "", errors.New("passwords do not match")
	}

	return password, nil
}

func saveScheme(scheme *crypto.TBLSScheme, filename string) error {
	enc, err := scheme.Encode()
	if err != nil {
		return err
	}

	buf, err := json.MarshalIndent(enc, "", " ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, buf, 0644)
}

func keyPath(outDir string, pubkeyHex string, i int) string {
	name := fmt.Sprintf("%s-share-%04d.json", pubkeyHex, i)
	return filepath.Join(outDir, name)
}

func saveKeys(scheme *crypto.TBLSScheme, priShares []*share.PriShare, pubkeyHex string, outDir string, password string) error {
	for _, priShare := range priShares {
		item, err := crypto.TBLSShareToKeystore(scheme, priShare, password)
		if err != nil {
			return err
		}

		if err := item.Save(keyPath(outDir, pubkeyHex, priShare.I)); err != nil {
			return err
		}
	}
	return nil
}
