// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package vcbundle

import (
	"context"
	"strings"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster/proposerconfig"
)

// vcFlags returns the command-line flags a distributed validator needs on the client: the ones it always needs,
// then the builder ones derived from the proposer config. Paths, the network, the beacon node and metrics are left
// to the operator.
func vcFlags(client Client, cfg proposerconfig.Config, builderEnabled bool) []string {
	flags := distributedFlags(client)
	// Nimbus takes whether builder proposals are enabled as a flag, the others in their proposer settings.
	if client == Nimbus && builderEnabled {
		flags = append(flags, "--payload-builder=true")
	}

	return append(flags, builderFlags(client, cfg.DefaultConfig.Builder)...)
}

// distributedFlags returns the flags the client always needs in a distributed validator.
func distributedFlags(client Client) []string {
	switch client {
	case Teku:
		return []string{"--Xobol-dvt-integration-enabled=true"}
	case Prysm:
		// Charon only serves the beacon REST API.
		return []string{"--distributed", "--enable-beacon-rest-api"}
	case Lodestar:
		// Charon expects the stateful gloas block form, the payload kept on the beacon node. Lodestar applies the
		// boost factor of the proposer settings file only with the maxprofit builder selection.
		return []string{"--distributed", "--payloadLocal=true", "--builder.selection=maxprofit"}
	case Nimbus:
		// The other operators' signatures of the same validators would trip doppelganger detection.
		return []string{"--distributed", "--doppelganger-detection=false"}
	case Lighthouse:
		return []string{"--distributed"}
	default:
		return nil
	}
}

// builderFlags returns the client's builder flags derived from the proposer config, none without builders.
// Only Nimbus takes its builder as flags, the others from a file.
func builderFlags(client Client, builder *proposerconfig.Builder) []string {
	if builder == nil || len(builder.Builders) == 0 {
		return nil
	}

	switch client {
	case Nimbus:
		// Nimbus takes the flag once per builder.
		var flags []string
		for _, b := range builder.Builders {
			flags = append(flags, "--payload-builder-url="+b.URL)
		}

		return append(flags,
			"--builder-min-bid="+builder.MinBid,
			"--builder-boost-factor="+builder.BuilderBoostFactor,
			"--builder-max-execution-payment="+builder.MaxExecutionPayment,
		)
	case Lodestar:
		// Lodestar refuses any max execution payment above 0 (trusted payments) without an explicit opt-in.
		if builder.MaxExecutionPayment != "0" {
			return []string{"--allowDangerousTrustedPayments"}
		}

		return nil
	default:
		return nil
	}
}

// logBuilders logs where the client takes its builders from: the flags for Nimbus, the proposer settings for the
// others.
func logBuilders(ctx context.Context, client Client, builder *proposerconfig.Builder) {
	if builder == nil || len(builder.Builders) == 0 {
		log.Info(ctx, "No builders in the proposer config, no builder settings written")
		return
	}

	var urls []string
	for _, b := range builder.Builders {
		urls = append(urls, b.URL)
	}

	redacted := log.RedactURLs(urls, true)

	switch client {
	case Teku:
		log.Info(ctx, "Builders taken from the proposer config file", z.Str("file", tekuSettingsPath), z.Any("builders", redacted))
	case Prysm:
		log.Info(ctx, "Builders taken from the proposer settings file", z.Str("file", prysmSettingsPath), z.Any("builders", redacted))
	case Lodestar:
		log.Info(ctx, "Builders taken from the proposer settings file", z.Str("file", lodestarSettingsPath), z.Any("builders", redacted))
	case Lighthouse:
		log.Info(ctx, "Builders taken from the builder definitions", z.Str("file", lighthouseBuildersPath), z.Any("builders", redacted))
	case Nimbus:
		log.Info(ctx, "Builders passed as flags", z.Str("file", FlagsFile), z.Any("builders", redacted))
	default:
	}
}

// renderFlags returns the flags one per line.
func renderFlags(flags []string) []byte {
	var b strings.Builder
	for _, f := range flags {
		b.WriteString(f + "\n")
	}

	return []byte(b.String())
}
