// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

//nolint:revive,nolintlint // somehow the nolintlint linter catches revive as unnecessary, while it is
package log

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/obolnetwork/charon/app/errors"
)

const redacted = "xxxxx"

var (
	// apiKeySegment matches path segments that look like API keys, e.g. "/v2/<key>" of hosted node providers:
	// at least 20 characters, mixing letters and digits. Beacon API names like "prepare_beacon_proposer" have
	// no digits, and hex values with a 0x prefix (roots, pubkeys, lock hashes) are skipped by the caller.
	apiKeySegment = regexp.MustCompile(`^[A-Za-z0-9_-]{20,}$`)
	digit         = regexp.MustCompile(`[0-9]`)
	letter        = regexp.MustCompile(`[A-Za-z]`)
	// publicQueryValue matches query values kept for debugging: integers like slots and indices, and 0x hex values.
	publicQueryValue = regexp.MustCompile(`^([0-9]{1,20}|0x[0-9a-fA-F]*)$`)
)

// RedactURL returns raw with the URL's password and query values replaced with "xxxxx".
// Query values that are integers or 0x hex values, like slots and roots, are kept.
// If maskPath is true, a non-empty path is replaced too, since hosted beacon and execution
// providers put API keys in it. Otherwise only path segments that look like API keys are.
// Values that aren't absolute URLs are returned unchanged.
//
// Beacon node, execution and other endpoint URLs may contain credentials, so redact them
// wherever they are logged or used as metric labels.
func RedactURL(raw string, maskPath bool) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return raw
	}

	changed := false

	if _, ok := u.User.Password(); ok {
		u.User = url.UserPassword(u.User.Username(), redacted)
		changed = true
	}

	if u.RawQuery != "" {
		q := u.Query()
		queryChanged := false

		for _, vals := range q {
			for i, v := range vals {
				if !publicQueryValue.MatchString(v) {
					vals[i] = redacted
					queryChanged = true
				}
			}
		}

		if queryChanged {
			u.RawQuery = q.Encode()
			changed = true
		}
	}

	if maskPath && strings.Trim(u.Path, "/") != "" {
		u.Path, u.RawPath = "/"+redacted, ""
		changed = true
	} else if !maskPath {
		segments := strings.Split(u.Path, "/")
		for i, s := range segments {
			if looksLikeAPIKey(s) {
				segments[i] = redacted
				changed = true
			}
		}

		u.Path, u.RawPath = strings.Join(segments, "/"), ""
	}

	if !changed {
		return raw
	}

	return u.String()
}

// RedactURLs returns the URLs redacted with RedactURL.
func RedactURLs(raws []string, maskPath bool) []string {
	resp := make([]string, 0, len(raws))
	for _, raw := range raws {
		resp = append(resp, RedactURL(raw, maskPath))
	}

	return resp
}

// RedactURLError redacts the URL of the first *url.Error in err's chain in place, keeping its path
// for debugging, and returns err. Go's HTTP client strips passwords from it, but not API keys
// in the path or query. Call it before wrapping err, since wrapping captures the message.
func RedactURLError(err error) error {
	if uerr := new(url.Error); errors.As(err, &uerr) {
		uerr.URL = RedactURL(uerr.URL, false)
	}

	return err
}

func looksLikeAPIKey(segment string) bool {
	return !strings.HasPrefix(segment, "0x") && apiKeySegment.MatchString(segment) &&
		digit.MatchString(segment) && letter.MatchString(segment)
}
