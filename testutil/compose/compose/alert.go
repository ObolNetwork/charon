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

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"time"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

const alertsPolled = "alerts_polled"

// startAlertCollector starts a goroutine that polls prometheus alerts until the context is closed and returns
// a channel on which the received alert descriptions will be sent.
func startAlertCollector(ctx context.Context, dir string) (chan string, error) {
	resp := make(chan string, 100)

	go func() {
		var (
			success bool
			dedup   = make(map[string]bool)
		)
		defer close(resp)
		for ctx.Err() == nil {
			time.Sleep(time.Second * 5)

			cmd := exec.CommandContext(ctx, "docker-compose", "exec", "-T", "curl", "curl", "-s", "http://prometheus:9090/api/v1/rules?type=alert")
			cmd.Dir = dir
			out, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				return
			} else if err != nil {
				log.Error(ctx, "Exec curl alerts", err, z.Str("out", string(out)))
				continue
			}

			var alerts promAlerts
			if err := json.Unmarshal(bytes.TrimSpace(out), &alerts); err != nil {
				resp <- errors.Wrap(err, "unmarshal alerts", z.Str("out", string(out))).Error()
				continue
			}

			if alerts.Status != "success" {
				resp <- "non success status from prometheus alerts: " + alerts.Status
				continue
			}

			if !success {
				resp <- alertsPolled // Push initial "fake alert" so logic can fail is not alerts polled.
				success = true
			}

			for _, active := range getActiveAlerts(alerts) {
				if dedup[active] {
					continue
				}
				dedup[active] = true
				log.Info(ctx, "Detected new alert", z.Str("alert", active))

				resp <- active
			}
		}
	}()

	return resp, nil
}

func getActiveAlerts(alerts promAlerts) []string {
	var resp []string
	for _, group := range alerts.Data.Groups {
		for _, rule := range group.Rules {
			for _, alert := range rule.Alerts {
				if alert.State != "active" {
					continue
				}

				resp = append(resp, alert.Annotations.Description)
			}
		}
	}

	return resp
}

// promAlerts is the json response returned by querying prometheus alerts.
// nolint: revive // Nested structs are ok in this case.
type promAlerts struct {
	Status string `json:"status"`
	Data   struct {
		Groups []struct {
			Name  string `json:"name"`
			Rules []struct {
				Name   string `json:"name"`
				Alerts []struct {
					State       string `json:"state"`
					Annotations struct {
						Description string `json:"description"`
					} `json:"annotations"`
				} `json:"alerts"`
			} `json:"rules"`
		} `json:"groups"`
	} `json:"data"`
}
