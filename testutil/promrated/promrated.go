// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Command promrated grabs rated stats for all monitored charon clusters

package promrated

import (
	"context"
	"net/url"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/promauto"
	"github.com/obolnetwork/charon/app/z"
)

type Config struct {
	RatedEndpoint  string
	RatedAuth      string
	PromAuth       string
	MonitoringAddr string
	Networks       []string
	NodeOperators  []string
}

// Run blocks running the promrated program until the context is canceled or a fatal error occurs.
func Run(ctx context.Context, config Config) error {
	log.Info(ctx, "Promrated started",
		z.Str("rated_endpoint", redactURL(config.RatedEndpoint)),
		z.Str("prom_auth", config.PromAuth),
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

	// Metrics are produced daily so can preserve Rated CUs
	ticker := time.NewTicker(24 * time.Hour)
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
	for _, network := range config.Networks {
		networkLabels := prometheus.Labels{
			clusterNetworkLabel: network,
			nodeOperatorLabel:   "all",
		}

		stats, err := getNetworkStatistics(ctx, config.RatedEndpoint, config.RatedAuth, network)
		if err != nil {
			log.Error(ctx, "Getting network statistics", err, z.Str("network", network))
			continue
		}

		setMetrics(networkLabels, stats)

		for _, nodeOperator := range config.NodeOperators {
			nodeOperatorLabels := prometheus.Labels{
				clusterNetworkLabel: network,
				nodeOperatorLabel:   nodeOperator,
			}

			stats, err = getNodeOperatorStatistics(ctx, config.RatedEndpoint, config.RatedAuth, nodeOperator, network)
			if err != nil {
				log.Error(ctx, "Getting node operator statistics", err, z.Str("network", network), z.Str("node_operator", nodeOperator))
				continue
			}

			setMetrics(nodeOperatorLabels, stats)
		}
	}
}

func setMetrics(labels prometheus.Labels, stats networkEffectivenessData) {
	networkUptime.With(labels).Set(stats.AvgUptime)
	networkCorrectness.With(labels).Set(stats.AvgCorrectness)
	networkInclusionDelay.With(labels).Set(stats.AvgInclusionDelay)
	networkEffectiveness.With(labels).Set(stats.AvgValidatorEffectiveness)
	networkProposerEffectiveness.With(labels).Set(stats.AvgProposerEffectiveness)
	networkAttesterEffectiveness.With(labels).Set(stats.AvgAttesterEffectiveness)
}

// redactURL returns a redacted version of the given URL.
func redactURL(val string) string {
	u, err := url.Parse(val)
	if err != nil {
		return val
	}

	return u.Redacted()
}
