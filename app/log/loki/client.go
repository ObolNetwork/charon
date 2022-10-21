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

package loki

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/expbackoff"
	"github.com/obolnetwork/charon/app/log"
	pbv1 "github.com/obolnetwork/charon/app/log/loki/lokipb/v1"
	"github.com/obolnetwork/charon/app/z"
)

const (
	contentType  = "application/x-protobuf"
	maxErrMsgLen = 1024
	httpTimeout  = 2 * time.Second
	batchWait    = 1 * time.Second
	batchMaxSize = 5 * 1 << 20 // 5MB
)

// Client for pushing logs in snappy-compressed protos over HTTP.
type Client struct {
	input    chan string
	quit     chan struct{}
	done     chan struct{}
	service  string
	endpoint string
}

// New makes a new Client.
func New(endpoint string, service string) *Client {
	return &Client{
		endpoint: endpoint,
		service:  service,
		done:     make(chan struct{}),
		quit:     make(chan struct{}),
		input:    make(chan string),
	}
}

func (c *Client) Run() {
	var (
		client        = new(http.Client)
		ctx           = log.WithTopic(context.Background(), "loki")
		backoffConfig = expbackoff.DefaultConfig
		retries       int
		batch         = newBatch(c.service) // New empty batch
		ticker        = time.NewTicker(batchWait / 10)
		logFilter     = log.Filter()
	)
	defer close(c.done)
	defer ticker.Stop()

	for {
		select {
		case line := <-c.input:
			batch.Add(&pbv1.Entry{
				Timestamp: timestamppb.Now(),
				Line:      line,
			})
			if batch.Size() > batchMaxSize {
				batch = newBatch(c.service) // Just silently drop, there should have been multiple error logs below.
			}
		case <-c.quit:
			_ = send(ctx, client, c.endpoint, batch) // On shutdown just try to send once as best effort.
			return
		case <-ticker.C:
			// Do not send if the batch is too young
			if batch.Age() < batchWait {
				break
			}
			// Do not send if we are backing off
			if retries > 0 && expbackoff.Backoff(backoffConfig, retries) > 0 {
				break
			}

			err := send(ctx, client, c.endpoint, batch)
			if err != nil {
				log.Warn(ctx, "Loki batch send failed", err, logFilter)
				retries++

				break
			}

			batch = newBatch(c.service)
			retries = 0
		}
	}
}

func (c *Client) Add(line string) {
	select {
	case c.input <- line:
	case <-c.quit:
	}
}

func (c *Client) Stop(ctx context.Context) {
	close(c.quit)

	select {
	case <-ctx.Done():
	case <-c.done:
	}
}

func send(ctx context.Context, client *http.Client, endpoint string, batch *batch) error {
	buf, err := batch.Encode()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(buf))
	if err != nil {
		return errors.Wrap(err, "new loki request")
	}
	req.Header.Set("Content-Type", contentType)

	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "http do")
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		scanner := bufio.NewScanner(io.LimitReader(resp.Body, maxErrMsgLen))
		line := ""
		if scanner.Scan() {
			line = scanner.Text()
		}

		return errors.New("http nok response",
			z.Int("status_code", resp.StatusCode),
			z.Str("line", line),
		)
	}

	return nil
}
