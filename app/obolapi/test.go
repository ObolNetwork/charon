// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapi

import (
	"context"
	"net/url"

	"github.com/obolnetwork/charon/app/errors"
)

const (
	postTestPath = "/test"
)

func (c Client) PostTestResult(ctx context.Context, jsonTestResult []byte) error {
	u, err := url.ParseRequestURI(c.baseURL)
	if err != nil {
		return errors.Wrap(err, "bad Obol API url")
	}

	u.Path += postTestPath

	ctx, cancel := context.WithTimeout(ctx, c.reqTimeout)
	defer cancel()

	err = httpPost(ctx, u, jsonTestResult, nil)
	if err != nil {
		return errors.Wrap(err, "http Obol API POST request")
	}

	return nil
}
