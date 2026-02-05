// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cluster

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth1wrap"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

// LoadClusterLockAndVerify loads and verifies the cluster lock. Suitable for cmd tools.
func LoadClusterLockAndVerify(ctx context.Context, lockFilePath string) (*Lock, error) {
	eth1Cl := eth1wrap.NewDefaultEthClientRunner("")
	go eth1Cl.Run(ctx)

	return LoadClusterLock(ctx, lockFilePath, false, eth1Cl)
}

// LoadClusterLock loads and verifies the cluster lock.
// The lockFilePathOrURL can be either a local file path or an HTTP/HTTPS URL.
func LoadClusterLock(ctx context.Context, lockFilePathOrURL string, noVerify bool, eth1Cl eth1wrap.EthClientRunner) (*Lock, error) {
	b, err := loadClusterLockBytes(ctx, lockFilePathOrURL)
	if err != nil {
		return nil, err
	}

	var lock Lock
	if err := json.Unmarshal(b, &lock); err != nil {
		return nil, errors.Wrap(err, "unmarshal cluster-lock.json", z.Str("path", lockFilePathOrURL))
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if err := lock.VerifyHashes(); err != nil && !noVerify {
		return nil, errors.Wrap(err, "verify cluster lock hashes (run with --no-verify to bypass verification at own risk)")
	} else if err != nil && noVerify {
		log.Warn(ctx, "Ignoring failed cluster lock hashes verification due to --no-verify flag", err)
	}

	if err := lock.VerifySignatures(eth1Cl); err != nil && !noVerify {
		return nil, errors.Wrap(err, "verify cluster lock signatures (run with --no-verify to bypass verification at own risk)")
	} else if err != nil && noVerify {
		log.Warn(ctx, "Ignoring failed cluster lock signature verification due to --no-verify flag", err)
	}

	return &lock, nil
}

// loadClusterLockBytes loads the cluster lock bytes from either a local file path or an HTTP/HTTPS URL.
func loadClusterLockBytes(ctx context.Context, pathOrURL string) ([]byte, error) {
	if IsURL(pathOrURL) {
		parsedURL, err := url.ParseRequestURI(pathOrURL)
		if err != nil {
			return nil, errors.Wrap(err, "parse cluster lock URL", z.Str("url", pathOrURL))
		}

		if parsedURL.Scheme != "https" {
			log.Warn(ctx, "Fetching cluster lock file over insecure HTTP connection", nil, z.Str("url", pathOrURL))
		}

		return fetchClusterLockBytes(ctx, pathOrURL)
	}

	b, err := os.ReadFile(pathOrURL)
	if err != nil {
		return nil, errors.Wrap(err, "read cluster-lock.json from disk", z.Str("path", pathOrURL))
	}

	return b, nil
}

// fetchClusterLockBytes fetches cluster lock file bytes from a remote URL.
func fetchClusterLockBytes(ctx context.Context, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "create http request")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "fetch cluster-lock.json from URL")
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return nil, errors.New("http error fetching cluster-lock.json", z.Int("status_code", resp.StatusCode))
	}

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "read response body")
	}

	return buf, nil
}

// IsURL returns true if the given string is a valid HTTP or HTTPS URL.
func IsURL(s string) bool {
	parsedURL, err := url.ParseRequestURI(s)
	if err != nil {
		return false
	}

	return parsedURL.Host != "" && (parsedURL.Scheme == "http" || parsedURL.Scheme == "https")
}
