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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"

	"golang.org/x/sync/errgroup"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

// startAlertCollector starts a server that accepts alert webhooks until the context is closed and returns
// a channel on which the received alert titles will be sent.
func startAlertCollector(ctx context.Context, port int) (chan string, error) {
	l, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return nil, errors.Wrap(err, "new listener")
	}

	resp := make(chan string, 100)
	server := http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer r.Body.Close()

			b, err := io.ReadAll(r.Body)
			if err != nil {
				log.Error(ctx, "Read request body", err)
				return
			}

			wrapper := struct {
				Body string `json:"body"`
			}{}
			if err := json.Unmarshal(b, &wrapper); err != nil {
				log.Error(ctx, "Unmarshal body wrapper", err, z.Str("body", string(b)))
				return
			}

			alert := struct {
				Title string `json:"title"`
			}{}
			if err := json.Unmarshal(b, &alert); err != nil {
				log.Error(ctx, "Unmarshal alert", err, z.Str("body", string(b)))
				return
			} else if alert.Title == "" {
				log.Error(ctx, "Alert title empty", err, z.Str("body", string(b)))
				return
			}

			log.Info(ctx, "Received webhook", z.Str("body", string(b)), z.Str("title", alert.Title))

			resp <- alert.Title
		}),
	}

	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		return server.Serve(l) //nolint:wrapcheck
	})
	eg.Go(func() error {
		<-ctx.Done()
		return server.Close() //nolint:wrapcheck
	})
	go func() {
		if err := eg.Wait(); !errors.Is(err, context.Canceled) && !errors.Is(err, http.ErrServerClosed) {
			log.Error(ctx, "Alert collector", err)
		}
		close(resp)
	}()

	return resp, nil
}
