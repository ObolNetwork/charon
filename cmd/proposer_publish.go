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
	"github.com/obolnetwork/charon/cluster/proposerconfig"
	"github.com/obolnetwork/charon/dkg"
)

// proposerPublishConfig is the configuration of the proposer publish command.
type proposerPublishConfig struct {
	LockFile           string
	ProposerConfigFile string
	PublishAddress     string
	PublishTimeout     time.Duration
	NoVerify           bool
}

func newProposerPublishCmd(runFunc func(context.Context, io.Writer, proposerPublishConfig) error) *cobra.Command {
	var (
		config  proposerPublishConfig
		logConf log.Config
	)

	cmd := &cobra.Command{
		Use:   "publish",
		Short: "Publish the cluster's signed proposer config to the Obol API as a backup",
		Long: "Publishes the signed proposer config revision of the file to the Obol API, as a backup charon alpha proposer fetch restores. " +
			"Its operator signatures authenticate it, so it needs no node key and any operator can publish it. " +
			"Use it for a revision not published when it was signed: edit, dkg and create cluster publish it with --publish. " +
			"Revision 0 is unsigned and is not published.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := log.InitLogger(logConf); err != nil {
				return err
			}

			return runFunc(cmd.Context(), cmd.OutOrStdout(), config)
		},
	}

	f := cmd.Flags()
	f.StringVar(&config.LockFile, "lock-file", ".charon/cluster-lock.json", "The path to the cluster lock file defining the distributed validator cluster.")
	f.StringVar(&config.ProposerConfigFile, "proposer-config-file", ".charon/vc-config/proposer-config.json", "The path to the proposer config file of any of the cluster's nodes.")
	bindProposerAPIFlags(f, &config.PublishAddress, &config.PublishTimeout)
	bindNoVerifyFlag(f, &config.NoVerify)
	bindLogFlags(f, &logConf)

	markHidden(f, "no-verify")

	return cmd
}

func runProposerPublish(ctx context.Context, w io.Writer, config proposerPublishConfig) error {
	lock, err := dkg.LoadAndVerifyClusterLock(ctx, config.LockFile, "", config.NoVerify)
	if err != nil {
		return errors.Wrap(err, "load cluster lock")
	}

	doc, err := proposerconfig.LoadAnyNode(config.ProposerConfigFile, *lock)
	if err != nil {
		return err
	}

	if doc.Revision == 0 {
		return errors.New("the proposer config file holds the unsigned revision 0, which is not published: publish a revision signed by charon alpha proposer edit")
	}

	err = proposerconfig.Verify(doc, *lock)
	if err != nil {
		return errors.Wrap(err, "verify proposer config file")
	}

	cl, err := obolapi.New(config.PublishAddress, obolapi.WithTimeout(config.PublishTimeout))
	if err != nil {
		return err
	}

	err = cl.PublishProposerConfig(ctx, doc)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(w, "Proposer config revision %d published to %s: charon alpha proposer fetch restores it.\n", doc.Revision, config.PublishAddress)

	return nil
}
