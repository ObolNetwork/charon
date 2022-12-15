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

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

type Config struct {
	RatedAPIEndpoint string
	PromEndpoint     string
	PromAuth         string
	MonitoringAddr   string
}

// Run blocks running the promrated program until the context is canceled or a fatal error occurs.
func Run(ctx context.Context, config Config) error {
	log.Info(ctx, "Promrated started",
		z.Str("rated_api_endpoint", config.RatedAPIEndpoint), // TODO(corver): This may contain a password
		z.Str("prom_auth", config.PromAuth),                  // TODO(corver): This may contain a password
		z.Str("monitoring_addr", config.MonitoringAddr),
	)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- serveMonitoring(config.MonitoringAddr)
	}()

	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	reportMetrics(ctx, config)

	for {
		select {
		case err := <-serverErr:
			return err
		case <-ticker.C:
			reportMetrics(ctx, config)
		case <-ctx.Done():
			log.Info(ctx, "Shutting down")
			return nil
		}
	}
}

func reportMetrics(ctx context.Context, config Config) {
	validators, err := getValidators(ctx, config.PromEndpoint, config.PromAuth)
	if err != nil {
		log.Error(context.Background(), "getting pubkey info", err)
	}

	for _, validator := range validators {
		log.Info(ctx, "Fetched validator from prometheus", z.Str("pubkey", validator.PubKey), z.Str("cluster_name", validator.ClusterName))
	}
}
