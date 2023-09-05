// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Command promrated grabs rated stats for all monitored charon clusters

package promrated

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/promauto"
	"github.com/obolnetwork/charon/app/z"
)

type Config struct {
	RatedEndpoint  string
	RatedAuth      string
	PromEndpoint   string
	PromAuth       string
	MonitoringAddr string
	Networks       []string
}

// Run blocks running the promrated program until the context is canceled or a fatal error occurs.
func Run(ctx context.Context, config Config) error {
	log.Info(ctx, "Promrated started",
		z.Str("rated_endpoint", config.RatedEndpoint), // TODO(corver): This may contain a password
		z.Str("prom_auth", config.PromAuth),           // TODO(corver): This may contain a password
		z.Str("monitoring_addr", config.MonitoringAddr),
	)

	promRegistry, err := promauto.NewRegistry(nil)
	if err != nil {
		return err
	}

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- serveMonitoring(config.MonitoringAddr, promRegistry)
	}()

	ticker := time.NewTicker(12 * time.Hour)
	defer ticker.Stop()

	onStartup := make(chan struct{}, 1)
	onStartup <- struct{}{}

	for {
		select {
		case err := <-serverErr:
			return err
		case <-onStartup:
			reportMetrics(ctx, config)
		case <-ticker.C:
			reportMetrics(ctx, config)
		case <-ctx.Done():
			log.Info(ctx, "Shutting down")
			return nil
		}
	}
}

// report the validator effectiveness metrics for prometheus.
func reportMetrics(ctx context.Context, config Config) {
	validators, err := getValidators(ctx, config.PromEndpoint, config.PromAuth)
	if err != nil {
		log.Error(ctx, "Failed fetching validators from prometheus", err)
		return
	}

	for _, validator := range validators {
		log.Info(ctx, "Fetched validator from prometheus",
			z.Str("pubkey", validator.PubKey),
			z.Str("cluster_name", validator.ClusterName),
			z.Str("cluster_network", validator.ClusterNetwork),
		)

		if contains(config.Networks, validator.ClusterNetwork) {
			stats, err := getValidatorStatistics(ctx, config.RatedEndpoint, config.RatedAuth, validator)
			if err != nil {
				log.Error(ctx, "Getting validator statistics", err, z.Str("validator", validator.PubKey))
				continue
			}

			clusterLabels := prometheus.Labels{
				"pubkey_full":     validator.PubKey,
				"cluster_name":    validator.ClusterName,
				"cluster_hash":    validator.ClusterHash,
				"cluster_network": validator.ClusterNetwork,
			}

			uptime.With(clusterLabels).Set(stats.Uptime)
			correctness.With(clusterLabels).Set(stats.AvgCorrectness)
			inclusionDelay.With(clusterLabels).Set(stats.AvgInclusionDelay)
			attester.With(clusterLabels).Set(stats.AttesterEffectiveness)
			proposer.With(clusterLabels).Set(stats.ProposerEffectiveness)
			effectiveness.With(clusterLabels).Set(stats.ValidatorEffectiveness)
		}
	}

	for _, network := range config.Networks {
		networkLabels := prometheus.Labels{
			"cluster_network": network,
		}

		stats, err := getNetworkStatistics(ctx, config.RatedEndpoint, config.RatedAuth, network)
		if err != nil {
			log.Error(ctx, "Getting network statistics", err, z.Str("network", network))
			continue
		}

		networkUptime.With(networkLabels).Set(stats.AvgUptime)
		networkCorrectness.With(networkLabels).Set(stats.AvgCorrectness)
		networkInclusionDelay.With(networkLabels).Set(stats.AvgInclusionDelay)
		networkEffectiveness.With(networkLabels).Set(stats.ValidatorEffectiveness)
	}
}

func contains(arr []string, s string) bool {
	result := false
	for _, x := range arr {
		if x == s {
			result = true
			break
		}
	}

	return result
}
