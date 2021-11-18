package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/drand/kyber/share"
	"github.com/obolnetwork/charon/crypto"
	prompt "github.com/prysmaticlabs/prysm/shared/promptutil"
	"github.com/spf13/cobra"
)

var keygenCmd = cobra.Command{
	Use:   "keygen",
	Short: "Centralized key generation tool for creating a validator signing key threshold signature scheme",
	Long: `Generates a BLS12-381 validator private key in-memory, then splits it into a set of private key shares using Shamir's Secret Sharing.
Produces an EIP-2335 keystore file for each generated key share.`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
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
	},
}

func init() {
	rootCmd.AddCommand(&keygenCmd)

	flags := keygenCmd.Flags()
	flags.StringP("out", "o", "./keys", "Output directory")
	flags.UintP("shares", "n", 4, "Number of key shares to generate")
	flags.String("password-file", "", "Path to a plain-text password file")
}

type keygen struct {
	// flags
	outDir       string
	passwordFile string
	n            uint
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
	// Create "root" BLS key and polynomials.
	priPoly, pubPoly := crypto.NewTBLSPoly(k.t)
	pubkey := pubPoly.Commit()
	pubkeyHex := crypto.BLSPointToHex(pubkey)
	fmt.Println("Public key:", pubkeyHex)
	// Save public polynomials (required to recover root sig from sig shares).
	scheme, err := crypto.NewTBLSScheme(pubPoly, int(k.n))
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create threshold BLS scheme info")
	}
	k.mkOutdir()
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
	f, err := os.Open(k.passwordFile)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to open password file")
	}
	defer f.Close()
	scn := bufio.NewScanner(f)
	if !scn.Scan() {
		log.Fatal().Msg("Password file is empty")
	}
	k.password = scn.Text()
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
	buf, err := json.MarshalIndent(item, "", "\t")
	if err != nil {
		panic(err.Error())
	}
	err = os.WriteFile(path, buf, 0600)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to write key share")
	}
}
