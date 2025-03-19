// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package loki provides a simple best-effort loki log ingestion client supporting batch sends.
// It is heavily based on https://github.com/grafana/loki/tree/main/clients/pkg/promtail/client.
//
// It is best-effort, meaning it doesn't provide delivery guarantees, it will drop logs if
// loki isn't accessible. It is meant to be used in local dev environments or where log
// delivery isn't critical.
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
	pbv1 "github.com/obolnetwork/charon/app/log/loki/lokipb/v1"
	"github.com/obolnetwork/charon/app/z"
)

const (
	contentType   = "application/x-protobuf"
	maxErrMsgLen  = 1024
	httpTimeout   = 10 * time.Second
	batchWait     = 1 * time.Second
	batchMax      = 5 * 1 << 20 // 5MB
	maxLogLineLen = 4 << 10     // 4096B
)

// lazyLabelsFunc abstracts lazy loading of labels, logs will only be sent when it returns true.
type lazyLabelsFunc func() (map[string]string, bool)

// logFunc abstracts logging, since this is a logger itself.
type logFunc func(string, error)

// NewForT returns a new Client for testing.
func NewForT(endpoint string, serviceLabel string, batchWait time.Duration, batchMax, maxLogLineLen int,
	moreLabelsFunc lazyLabelsFunc, logFunc logFunc,
) *Client {
	return newInternal(endpoint, serviceLabel, batchWait, batchMax, maxLogLineLen, logFunc, moreLabelsFunc)
}

// New returns a new Client.
func New(endpoint string, serviceLabel string, logFunc logFunc, moreLabelsFunc lazyLabelsFunc) *Client {
	return newInternal(endpoint, serviceLabel, batchWait, batchMax, maxLogLineLen, logFunc, moreLabelsFunc)
}

func newInternal(endpoint string, serviceLabel string, batchWait time.Duration, batchMax, maxLogLineLen int,
	logFunc logFunc, moreLabelsFunc lazyLabelsFunc,
) *Client {
	return &Client{
		endpoint:       endpoint,
		done:           make(chan struct{}),
		quit:           make(chan struct{}),
		input:          make(chan string),
		batchMax:       batchMax,
		batchWait:      batchWait,
		maxLogLineLen:  maxLogLineLen,
		logFunc:        logFunc,
		serviceLabel:   serviceLabel,
		moreLabelsFunc: moreLabelsFunc,
	}
}

// Client for pushing logs in snappy-compressed protos over HTTP.
type Client struct {
	input          chan string
	quit           chan struct{}
	done           chan struct{}
	endpoint       string
	batchWait      time.Duration
	batchMax       int
	maxLogLineLen  int
	serviceLabel   string
	moreLabelsFunc lazyLabelsFunc
	logFunc        logFunc
}

// Run blocks until Stop is called.
//   - It batches and sends logs to loki.
//   - It sends logs every batchWait time.
//   - Failed sends are retried.
//   - Enqueue logs are dropped if BatchMax is reached.
//   - It tries to send the last batch when Stop is called. It doesn't retry this batch.
func (c *Client) Run() {
	var (
		client        = new(http.Client)
		ctx           = context.Background()
		backoffConfig = expbackoff.DefaultConfig
		retries       int
		triedAt       time.Time
		batch         = newBatch() // New empty batch
		ticker        = time.NewTicker(c.batchWait)
	)
	defer close(c.done)
	defer ticker.Stop()

	for {
		select {
		case line := <-c.input:
			if len(line) > c.maxLogLineLen && c.maxLogLineLen != 0 {
				continue // Silently drop log line longer than maxLogLineLen if set
			}

			batch.Add(&pbv1.Entry{
				Timestamp: timestamppb.Now(),
				Line:      line,
			})

			if batch.Size() > c.batchMax {
				batch = newBatch() // Just silently drop, there should have been multiple error logs below.
			}
		case <-c.quit:
			_ = send(ctx, client, c.endpoint, batch, c.labels()) // On shutdown just try to send once as best effort.
			return
		case <-ticker.C:
			// Do not send if the batch is empty or too young or labels not ready yet.
			if batch.Size() == 0 || batch.Age() < c.batchWait || !c.labelsReady() {
				continue
			}

			// Do not send if we are backing off
			if retries > 0 {
				nextTry := triedAt.Add(expbackoff.Backoff(backoffConfig, retries))
				if time.Until(nextTry) > 0 {
					break
				}
			}

			err := send(ctx, client, c.endpoint, batch, c.labels())
			if err != nil {
				// Log async to avoid deadlock by recursive calls to Add.
				go c.logFunc("Loki batch send failed (will retry)", err)

				retries++
				triedAt = time.Now()

				continue
			}

			batch = newBatch()
			retries = 0
		}
	}
}

// Add enqueues a line for sending to loki.
func (c *Client) Add(line string) {
	select {
	case c.input <- line:
	case <-c.quit:
	}
}

// Stop triggers graceful shutdown, it blocks until all
// enqueue logs have been sent or when the context is closed.
func (c *Client) Stop(ctx context.Context) {
	close(c.quit)

	select {
	case <-ctx.Done():
	case <-c.done:
	}
}

// labelsReady returns true if the lazy labels are ready.
func (c *Client) labelsReady() bool {
	_, ok := c.moreLabelsFunc()
	return ok
}

// labels returns all labels by merging the service label with those returned by lazyLabelsFunc.
func (c *Client) labels() map[string]string {
	labels := map[string]string{
		"service": c.serviceLabel,
	}

	kvs, _ := c.moreLabelsFunc()
	for k, v := range kvs {
		labels[k] = v
	}

	return labels
}

func send(ctx context.Context, client *http.Client, endpoint string, batch *batch, labels map[string]string) error {
	buf, err := batch.Encode(labels)
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
