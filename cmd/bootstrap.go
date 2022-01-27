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
	"os"
	"path/filepath"

	"github.com/drand/kyber/share"
	prompt "github.com/prysmaticlabs/prysm/shared/promptutil"
	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/crypto"
)

var bootstrapCmd = cobra.Command{
	Use:   "bootstrap",
	Short: "Bootstraps a single validator centrally.",
	Long: `Generates a BLS12-381 validator private key in-memory, then splits it into a set of private key shares using Shamir's Secret Sharing.
Produces an EIP-2335 keystore file for each generated key share.
Also outputs a distributed validator profile.`,
	Args: cobra.NoArgs,
	Run:  runKeygen,
}

func init() {
	rootCmd.AddCommand(&bootstrapCmd)

	flags := bootstrapCmd.Flags()
	flags.StringP("out", "o", "./keys", "Output directory")
	flags.UintP("shares", "n", 4, "Number of key shares to generate")
	flags.String("password-file", "", "Path to a plain-text password file")
	flags.StringSlice("bootnodes", nil, "List of bootnodes")
}

func runKeygen(cmd *cobra.Command, _ []string) {
	flags := cmd.Flags()

	out, err := flags.GetString("out")
	if err != nil {
		panic(err.Error())
	}

	passwordFile, err := flags.GetString("password-file")
	if err != nil {
		panic(err.Error())
	}

	shares, err := flags.GetUint("shares")
	if err != nil {
		panic(err.Error())
	}

	if shares < 1 {
		shares = 1
	}

	k := keygen{
		outDir:       out,
		passwordFile: passwordFile,
		n:            shares,
	}
	k.run()
}

type keygen struct {
	// flags
	outDir       string
	passwordFile string
	n            uint
	// bootnodes    []string
	// params
	t        uint
	password string
}

func (k *keygen) run() {
	fmt.Println("Running trusted BLS threshold key generation ceremony")
	// Figure out secret sharing params.
	k.t = k.n - ((k.n - 1) / 3)
	fmt.Printf("Params: n=%d t=%d\n", k.n, k.t)

	// Get password from file or prompt.
	k.getPassword()
	k.mkOutdir()

	// Create "root" BLS key and polynomials.
	priPoly, pubPoly := crypto.NewTBLSPoly(k.t)
	pubkey := pubPoly.Commit()
	pubkeyHex := crypto.BLSPointToHex(pubkey)
	fmt.Println("Public key:", pubkeyHex)

	// Save public polynomials (required to recover root sig from sig shares).
	scheme := &crypto.TBLSScheme{PubPoly: pubPoly}
	k.saveScheme(scheme, pubkeyHex)

	// Create private key shares.
	priShares := priPoly.Shares(int(k.n))
	k.saveKeys(scheme, priShares, pubkeyHex)
}

func (k *keygen) getPassword() {
	if k.passwordFile != "" {
		k.readPassword()
	} else {
		k.promptPassword()
	}
}

func (k *keygen) readPassword() {
	var err error
	k.password, err = crypto.ReadPlaintextPassword(k.passwordFile)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to read password")
	}
}

func (k *keygen) promptPassword() {
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

func (k *keygen) mkOutdir() {
	err := os.MkdirAll(k.outDir, 0777)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create out dir")
	}
}

func (k *keygen) saveScheme(scheme *crypto.TBLSScheme, pubkeyHex string) {
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

	//nolint:gosec // No need to reduce permissions as it simply saves the public keys
	err = os.WriteFile(polyName, buf, 0666)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to save public polynomials")
	}
}

func (k *keygen) keyPath(pubkeyHex string, i int) string {
	name := fmt.Sprintf("%s-share-%04d.json", pubkeyHex, i)
	return filepath.Join(k.outDir, name)
}

func (k *keygen) saveKeys(scheme *crypto.TBLSScheme, priShares []*share.PriShare, pubkeyHex string) {
	fmt.Println("Saving keys to", k.keyPath(pubkeyHex, 0))

	for _, priShare := range priShares {
		k.saveKey(scheme, priShare, k.keyPath(pubkeyHex, priShare.I))
	}
}

func (k *keygen) saveKey(scheme *crypto.TBLSScheme, priShare *share.PriShare, path string) {
	item, err := crypto.TBLSShareToKeystore(scheme, priShare, k.password)
	if err != nil {
		log.Fatal().Err(err).Int("key_share", priShare.I).Msg("Failed to create keystore for private key share")
	}

	if err := item.Save(path); err != nil {
		log.Fatal().Err(err).Msg("Failed to write keyshare")
	}
}
