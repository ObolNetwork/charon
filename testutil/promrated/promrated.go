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
	PromAuth         string
	MonitoringAddr   string
}

func Run(ctx context.Context, config Config) error {
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- listenAndServe(config.MonitoringAddr)
	}()

	go func() {
		log.Info(ctx, "Promrated looping.", z.Str("endpoint", config.RatedAPIEndpoint))

		sleepFor := time.Minute * time.Duration(10)
		time.Sleep(sleepFor)
	}()

	for {
		select {
		case err := <-serverErr:
			return err
		case <-ctx.Done():
			log.Info(ctx, "Shutting down")
			continue
		}
	}
}
