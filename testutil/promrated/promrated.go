// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

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
	PromEndpoint   string
	PromAuth       string
	MonitoringAddr string
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

	ticker := time.NewTicker(10 * time.Minute)
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

		stats, err := getValidationStatistics(ctx, config.RatedEndpoint, validator)
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
