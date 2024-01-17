// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package keymanager

import (
	"net/url"
	"strings"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

func VerifyKeymanagerAddr(addr string) error {
	parsedURL, err := url.Parse(addr)
	if err != nil {
		return errors.Wrap(err, "failed to parse keymanager address", z.Str("addr", addr))
	}
	if parsedURL.Scheme != "https" {
		if parsedURL.Host != "127.0.0.1" && !strings.HasPrefix(parsedURL.Host, "127.0.0.1:") {
			return errors.New("keymanager address must use https scheme", z.Str("addr", addr))
		}
	}

	return nil
}
