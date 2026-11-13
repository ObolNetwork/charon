// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package vcbundle

import (
	"context"
	"strings"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster/proposerconfig"
)

// vcFlags returns the command-line flags a distributed validator needs on the client: the ones it always needs,
// then the builder ones derived from the proposer config. Paths, the network, the beacon node and metrics are left
// to the operator.
func vcFlags(ctx context.Context, client Client, cfg proposerconfig.Config) ([]string, error) {
	builder, err := builderFlags(ctx, client, cfg)
	if err != nil {
		return nil, err
	}

	return append(distributedFlags(client), builder...), nil
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
		// Charon expects the stateful gloas block form, the payload kept on the beacon node.
		return []string{"--distributed", "--payloadLocal=true"}
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
// Only Teku and Nimbus take their builders as flags, the others from a file.
func builderFlags(ctx context.Context, client Client, cfg proposerconfig.Config) ([]string, error) {
	builder := cfg.DefaultConfig.Builder
	if builder == nil || len(builder.Builders) == 0 {
		log.Info(ctx, "No builders in the proposer config, no builder settings written")
		return nil, nil
	}

	var urls []string
	for _, b := range builder.Builders {
		urls = append(urls, b.URL)
	}

	redacted := log.RedactURLs(urls, true)

	switch client {
	case Teku:
		// Teku's builder settings are global, so per-builder overrides don't apply.
		for _, b := range builder.Builders {
			if strings.Contains(b.URL, ",") {
				return nil, errors.New("builder url contains a comma, which teku's --Xbuilder-urls splits on",
					z.Str("url", log.RedactURL(b.URL, true)))
			}
		}

		log.Info(ctx, "Builders passed as flags", z.Str("file", FlagsFile), z.Any("builders", redacted))

		return []string{
			"--Xbuilder-urls=" + strings.Join(urls, ","),
			"--Xbuilder-min-bid=" + builder.MinBid,
			"--Xbuilder-boost-factor=" + builder.BuilderBoostFactor,
			"--Xbuilder-max-execution-payment=" + builder.MaxExecutionPayment,
		}, nil
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
		}, nil
	case Lodestar:
		log.Info(ctx, "Builders taken from the proposer settings file", z.Str("file", lodestarSettingsPath), z.Any("builders", redacted))

		flags := []string{"--builder=true"}

		// Lodestar refuses a max execution payment above 0 (trusted payments) without an explicit opt-in.
		if builder.MaxExecutionPayment != "0" {
			flags = append(flags, "--allowDangerousTrustedPayments")
		}

		return flags, nil
	case Prysm:
		log.Info(ctx, "Builders taken from the proposer settings file", z.Str("file", prysmSettingsPath), z.Any("builders", redacted))

		return nil, nil
	case Lighthouse:
		log.Info(ctx, "Builders taken from the builder definitions", z.Str("file", lighthouseBuildersPath), z.Any("builders", redacted))

		return nil, nil
	default:
		return nil, nil
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
