// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package vcbundle

import (
	"context"
	"slices"
	"strings"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster/proposerconfig"
)

// vcFlags returns the command-line flags a distributed validator needs on the client: the ones it always needs,
// then the builder ones derived from the proposer config. Paths, the network, the beacon node and metrics are left
// to the operator.
func vcFlags(ctx context.Context, client Client, cfg proposerconfig.Config) []string {
	return append(distributedFlags(client), builderFlags(ctx, client, cfg)...)
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

// builderFlags returns the client's builder flags derived from the proposer config, none without a builder block.
// Only Nimbus takes its builder as flags, the others from a file.
func builderFlags(ctx context.Context, client Client, cfg proposerconfig.Config) []string {
	builder := cfg.DefaultConfig.Builder
	if builder == nil || len(builder.Builders) == 0 {
		log.Info(ctx, "No builders in the proposer config, no builder settings written")
		return nil
	}

	var urls []string
	for _, b := range builder.Builders {
		urls = append(urls, b.URL)
	}

	redacted := log.RedactURLs(urls, true)

	switch client {
	case Teku:
		log.Info(ctx, "Builders taken from the proposer config file", z.Str("file", tekuSettingsPath), z.Any("builders", redacted))

		return nil
	case Nimbus:
		// Nimbus takes a single builder: the first, with its own values over the block's.
		first := builder.Builders[0]

		log.Info(ctx, "First builder passed as flags", z.Str("file", FlagsFile), z.Str("builder", redacted[0]))

		if len(redacted) > 1 {
			log.Warn(ctx, "Nimbus takes a single builder, the others are not used", nil, z.Any("unused_builders", redacted[1:]))
		}

		return []string{
			"--payload-builder=true",
			"--payload-builder-url=" + first.URL,
			"--builder-min-bid=" + orDefault(first.MinBid, builder.MinBid),
			"--builder-boost-factor=" + orDefault(first.BuilderBoostFactor, builder.BuilderBoostFactor),
			"--builder-max-execution-payment=" + orDefault(first.MaxExecutionPayment, builder.MaxExecutionPayment),
		}
	case Lodestar:
		log.Info(ctx, "Builders taken from the proposer settings file", z.Str("file", lodestarSettingsPath), z.Any("builders", redacted))

		// Lodestar refuses any max execution payment above 0 (trusted payments) without an explicit opt-in.
		trusted := builder.MaxExecutionPayment != "0" || slices.ContainsFunc(builder.Builders, func(b proposerconfig.BuilderEntry) bool {
			return b.MaxExecutionPayment != "" && b.MaxExecutionPayment != "0"
		})
		if trusted {
			return []string{"--allowDangerousTrustedPayments"}
		}

		return nil
	case Prysm:
		log.Info(ctx, "Builders taken from the proposer settings file", z.Str("file", prysmSettingsPath), z.Any("builders", redacted))

		return nil
	case Lighthouse:
		log.Info(ctx, "Builders taken from the builder definitions", z.Str("file", lighthouseBuildersPath), z.Any("builders", redacted))

		return nil
	default:
		return nil
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

// orDefault returns value, or def if value is empty.
func orDefault(value, def string) string {
	if value == "" {
		return def
	}

	return value
}
