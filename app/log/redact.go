// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package log

import (
	"net/url"
	"regexp"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const redacted = "xxxxx"

var (
	// urlPattern matches URLs embedded in free text, stopping at whitespace, quotes, brackets and commas.
	urlPattern = regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]*://[^\s"'<>\[\](),]+`)
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
		for k, vals := range q {
			for i, v := range vals {
				if !publicQueryValue.MatchString(v) {
					vals[i] = redacted
					changed = true
				}
			}

			q[k] = vals
		}

		if changed {
			u.RawQuery = q.Encode()
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

func looksLikeAPIKey(segment string) bool {
	return !strings.HasPrefix(segment, "0x") && apiKeySegment.MatchString(segment) &&
		digit.MatchString(segment) && letter.MatchString(segment)
}

// redactURLs redacts the credentials, query values and API-key-like path segments of any URLs in s.
// Beacon node, execution, builder and other URLs may contain credentials, and logs may be shared.
func redactURLs(s string) string {
	if !strings.Contains(s, "://") {
		return s
	}

	return urlPattern.ReplaceAllStringFunc(s, func(m string) string {
		return RedactURL(m, false)
	})
}

// redactField returns the field with any URLs in its string or error value redacted.
func redactField(f zap.Field) zap.Field {
	switch f.Type {
	case zapcore.StringType:
		f.String = redactURLs(f.String)
	case zapcore.ErrorType:
		err, ok := f.Interface.(error)
		if !ok {
			return f
		}

		if msg := redactURLs(err.Error()); msg != err.Error() {
			return zap.String(f.Key, msg)
		}
	default:
	}

	return f
}
