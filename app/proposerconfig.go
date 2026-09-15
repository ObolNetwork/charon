// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/eth2util/registration"
)

// proposerConfigDir and proposerConfigFilename locate the generated validator client
// proposer configuration file in a dedicated directory next to the cluster lock file,
// keeping validator client facing configuration separate from charon's own files.
const (
	proposerConfigDir      = "vc-config"
	proposerConfigFilename = "proposer-config.json"
)

// proposerConfigJSON is the proposer configuration file format understood by Prysm,
// Teku and Lodestar; Nimbus and Lighthouse require adapters rendering their own formats.
type proposerConfigJSON struct {
	// ProposerConfig maps this node's validator public shares (the identities the
	// validator client manages) to their proposer settings.
	ProposerConfig map[string]proposerSettingsJSON `json:"proposer_config"`
	// DefaultConfig applies to validators without an explicit entry.
	DefaultConfig proposerSettingsJSON `json:"default_config"`
}

type proposerSettingsJSON struct {
	FeeRecipient string              `json:"fee_recipient"`
	Builder      builderSettingsJSON `json:"builder"`
}

type builderSettingsJSON struct {
	Enabled  bool   `json:"enabled"`
	GasLimit string `json:"gas_limit"`
}

// writeProposerConfigFile generates the validator client proposer configuration file
// if it doesn't already exist, mirroring what charon registers with builders: the
// effective builder registrations including operator overrides, falling back to the
// cluster lock. An existing file is never modified.
func writeProposerConfigFile(conf Config, lock *cluster.Lock, nodeIdx cluster.NodeIdx,
	feeRecipientFunc func(core.PubKey) string, gasLimitFunc func(core.PubKey) uint64,
) (bool, error) {
	dir := filepath.Join(filepath.Dir(conf.LockFile), proposerConfigDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, errors.Wrap(err, "create proposer config directory", z.Str("dir", dir))
	}

	path := filepath.Join(dir, proposerConfigFilename)

	if info, err := os.Stat(path); err == nil {
		if info.IsDir() {
			return false, errors.New("proposer config file path is a directory", z.Str("path", path))
		}

		return false, nil // Never modify an existing file.
	} else if !os.IsNotExist(err) {
		return false, errors.Wrap(err, "stat proposer config file", z.Str("path", path))
	}

	feeRecipients := lock.FeeRecipientAddresses()

	config := proposerConfigJSON{ProposerConfig: make(map[string]proposerSettingsJSON)}

	for vi, val := range lock.Validators {
		pubshare, err := val.PublicShare(nodeIdx.PeerIdx)
		if err != nil {
			return false, errors.Wrap(err, "public share", z.Int("validator", vi))
		}

		pubshareHex := fmt.Sprintf("%#x", pubshare)

		corePubkey, err := core.PubKeyFromBytes(val.PubKey)
		if err != nil {
			return false, errors.Wrap(err, "core pubkey", z.Int("validator", vi))
		}

		feeRecipient := feeRecipientFunc(corePubkey)
		if feeRecipient == "" {
			feeRecipient = feeRecipients[vi]
		}

		gasLimit := gasLimitFunc(corePubkey)
		if gasLimit == 0 {
			gasLimit = registration.DefaultGasLimit
		}

		settings := proposerSettingsJSON{
			FeeRecipient: feeRecipient,
			Builder: builderSettingsJSON{
				Enabled:  conf.BuilderAPI,
				GasLimit: strconv.FormatUint(gasLimit, 10),
			},
		}

		config.ProposerConfig[pubshareHex] = settings

		if vi == 0 {
			// Default to the first validator's settings for non-cluster validators
			// of a shared validator client.
			config.DefaultConfig = settings
		}
	}

	b, err := json.Marshal(config)
	if err != nil {
		return false, errors.Wrap(err, "marshal proposer config")
	}

	//nolint:gosec // Configuration file without secrets, needs to be readable by validator clients.
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		return false, errors.Wrap(err, "write proposer config file", z.Str("path", path))
	}

	return true, nil
}

// wireProposerConfigFile generates the proposer config file, logging failures instead
// of returning them so generation never prevents duties.
func wireProposerConfigFile(ctx context.Context, conf Config, lock *cluster.Lock, nodeIdx cluster.NodeIdx,
	feeRecipientFunc func(core.PubKey) string, gasLimitFunc func(core.PubKey) uint64,
) {
	created, err := writeProposerConfigFile(conf, lock, nodeIdx, feeRecipientFunc, gasLimitFunc)
	if err != nil {
		log.Error(ctx, "Failed generating proposer config file, VC proposer settings must be configured manually", err)
		return
	}

	if created {
		log.Info(ctx, "Generated proposer config file for validator clients",
			z.Str("path", filepath.Join(filepath.Dir(conf.LockFile), proposerConfigDir, proposerConfigFilename)))
	}
}
