// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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
// A URL that doesn't parse as an absolute URL, as with an unescaped password or without a scheme, has its
// credentials and path replaced as a whole. Other values, like host:port, are returned unchanged.
// Without credentials, an "@" in the path, query or fragment is read as their end and what precedes it is
// replaced, the host included.
//
// Beacon node, execution and other endpoint URLs may contain credentials, so redact them
// wherever they are logged or used as metric labels.
func RedactURL(raw string, maskPath bool) string {
	u, err := url.Parse(raw)

	// A password with an unescaped "/", "?" or "#" ends the host early, leaving the "@" in the path, query or
	// fragment: the credentials then end at the last "@" instead.
	misread := err == nil && u.Scheme != "" && u.Host != "" && u.User == nil &&
		(strings.Contains(u.Path, "@") || strings.Contains(u.RawQuery, "@") || strings.Contains(u.Fragment, "@"))
	if misread {
		u, err = url.Parse(u.Scheme + "://" + redacted + "@" + raw[strings.LastIndex(raw, "@")+1:])
	}

	if err != nil || u.Scheme == "" || u.Host == "" {
		return redactUnparsed(raw, maskPath)
	}

	changed := misread

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

// redactUnparsed redacts a URL that url.Parse rejects, by position: everything up to the last "@"
// is taken as credentials and everything after the host as the path, both replaced. It applies to values with a
// scheme or with user:password credentials, and to any path if maskPath is true; other values are returned
// unchanged, like host:port and email addresses.
func redactUnparsed(raw string, maskPath bool) string {
	scheme, rest, hasScheme := strings.Cut(raw, "://")
	if hasScheme {
		scheme += "://"
	} else {
		scheme, rest = "", raw
	}

	at := strings.LastIndex(rest, "@")
	hasCredentials := at >= 0 && (hasScheme || strings.Contains(rest[:at], ":"))

	if !hasScheme && !hasCredentials && !maskPath {
		return raw
	}

	if hasCredentials {
		scheme += redacted + "@"
		rest = rest[at+1:]
	}

	host, path := rest, ""
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		host, path = rest[:i], rest[i:]
	}

	if strings.TrimSpace(strings.Trim(path, "/")) != "" {
		path = "/" + redacted
	}

	return scheme + host + path
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
