// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/obolapi"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/proposerconfig"
	"github.com/obolnetwork/charon/dkg"
	"github.com/obolnetwork/charon/p2p"
)

// proposerFetchConfig is the configuration of the proposer fetch command.
type proposerFetchConfig struct {
	LockFile           string
	PrivateKeyFile     string
	ProposerConfigFile string
	PublishAddress     string
	PublishTimeout     time.Duration
	// Revision is the revision to fetch, the latest if 0.
	Revision uint64
	NoVerify bool
}

func newProposerFetchCmd(runFunc func(context.Context, io.Writer, proposerFetchConfig) error) *cobra.Command {
	var (
		config  proposerFetchConfig
		logConf log.Config
	)

	cmd := &cobra.Command{
		Use:   "fetch",
		Short: "Fetch the cluster's signed proposer config from the Obol API into this node's file",
		Long: "Fetches the cluster's signed proposer config from the Obol API and writes it to this node's proposer config file. " +
			"Only the cluster's operators can fetch it: the request is signed with this node's charon ENR private key. " +
			"The fetched revision is verified against the cluster lock before anything is written, and it replaces the file only " +
			"if it is a later revision, archiving the file as an edit does. Restart the validator client afterwards to apply it.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := log.InitLogger(logConf); err != nil {
				return err
			}

			return runFunc(cmd.Context(), cmd.OutOrStdout(), config)
		},
	}

	f := cmd.Flags()
	f.Uint64Var(&config.Revision, "revision", 0, "The revision to fetch, the latest if not set.")
	f.StringVar(&config.PrivateKeyFile, "private-key-file", ".charon/charon-enr-private-key", "The path to the charon enr private key file.")
	f.StringVar(&config.LockFile, "lock-file", ".charon/cluster-lock.json", "The path to the cluster lock file defining the distributed validator cluster.")
	f.StringVar(&config.ProposerConfigFile, "proposer-config-file", ".charon/vc-config/proposer-config.json", "The path to the proposer config file.")
	bindProposerAPIFlags(f, &config.PublishAddress, &config.PublishTimeout)
	bindNoVerifyFlag(f, &config.NoVerify)
	bindLogFlags(f, &logConf)

	markHidden(f, "no-verify")

	return cmd
}

func runProposerFetch(ctx context.Context, w io.Writer, config proposerFetchConfig) error {
	lock, err := dkg.LoadAndVerifyClusterLock(ctx, config.LockFile, "", config.NoVerify)
	if err != nil {
		return errors.Wrap(err, "load cluster lock")
	}

	key, err := dkg.LoadPrivKey(config.PrivateKeyFile)
	if err != nil {
		return err
	}

	self, err := p2p.PeerIDFromKey(key.PubKey())
	if err != nil {
		return err
	}

	nodeIdx, err := lock.NodeIdx(self)
	if err != nil {
		return errors.Wrap(err, "private key not matching any operator in the cluster lock")
	}

	cl, err := obolapi.New(config.PublishAddress, obolapi.WithTimeout(config.PublishTimeout))
	if err != nil {
		return err
	}

	doc, err := cl.GetProposerConfig(ctx, lock.LockHash, uint64(nodeIdx.ShareIdx), config.Revision, key)
	if err != nil {
		return err
	}

	// The Obol API is not trusted: only a signed revision of this cluster lands on disk.
	if doc.Revision == 0 {
		return errors.New("unsigned revision 0 returned by Obol API")
	} else if config.Revision != 0 && doc.Revision != config.Revision {
		return errors.New("another revision than asked for returned by Obol API", z.U64("revision", doc.Revision), z.U64("asked", config.Revision))
	}

	err = proposerconfig.Verify(doc, *lock)
	if err != nil {
		return errors.Wrap(err, "verify fetched proposer config")
	}

	written, err := writeFetchedProposerConfig(config.ProposerConfigFile, doc, *lock, nodeIdx)
	if err != nil {
		return err
	}

	if !written {
		_, _ = fmt.Fprintf(w, "The proposer config file already holds revision %d, nothing written.\n", doc.Revision)
		return nil
	}

	_, _ = fmt.Fprintf(w, "Proposer config revision %d, signed by %d of %d operators (%s), written to %s.\n",
		doc.Revision, len(doc.Signatures), len(lock.Operators), signerList(doc), config.ProposerConfigFile)
	_, _ = fmt.Fprintln(w, "Restart your validator client now to apply it, e.g.: docker compose restart <vc service>")

	return nil
}

// writeFetchedProposerConfig writes the fetched revision to path unless the file holds it or a later one, archiving
// the file it replaces. It returns false if the file already holds the revision.
func writeFetchedProposerConfig(path string, doc proposerconfig.Document, lock cluster.Lock, nodeIdx cluster.NodeIdx) (bool, error) {
	cur, err := proposerconfig.Load(path, lock, nodeIdx)
	if errors.Is(err, proposerconfig.ErrNotFound) {
		return true, proposerconfig.Write(path, doc, lock, nodeIdx)
	} else if err != nil {
		return false, errors.Wrap(err, "load the proposer config file, move it away to replace it")
	}

	switch {
	case cur.Revision > doc.Revision:
		return false, errors.New("the proposer config file holds a later revision than the fetched one, nothing written",
			z.U64("file_revision", cur.Revision), z.U64("fetched_revision", doc.Revision))
	case cur.Revision == doc.Revision:
		curHash, err := cur.Hash()
		if err != nil {
			return false, err
		}

		docHash, err := doc.Hash()
		if err != nil {
			return false, err
		}

		if curHash != docHash {
			return false, errors.New("the proposer config file holds another document of the fetched revision, move it away to replace it",
				z.U64("revision", doc.Revision))
		}

		return false, nil
	}

	err = proposerconfig.Archive(path, cur.Revision)
	if err != nil {
		return false, err
	}

	return true, proposerconfig.Write(path, doc, lock, nodeIdx)
}
