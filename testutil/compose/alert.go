// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package compose

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
func startAlertCollector(ctx context.Context, dir string) chan string {
	resp := make(chan string, 100)

	go func() {
		var (
			success bool
			dedup   = make(map[string]bool)
		)

		defer close(resp)

		const iterSleep = time.Second * 2

		// Time required to wait for prometheus container to start.
		time.Sleep(time.Second * 10)

		for ; ctx.Err() == nil; time.Sleep(iterSleep) { // Sleep for iterSleep before next iteration.
			//nolint:revive // tls not required for testing.
			cmd := exec.CommandContext(ctx, "docker", "compose", "exec", "-T", "curl", "curl", "-s", "http://prometheus:9090/api/v1/rules?type=alert")
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

	return resp
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
