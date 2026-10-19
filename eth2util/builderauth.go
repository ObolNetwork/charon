// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth2util

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

// BuilderAuthData returns the default builder request auth data of the builder URL: its lowercase
// ASCII hostname, with an IPv6 literal compressed inside brackets, as defined by the gloas
// builder-specs. Like the spec's urlsplit, the hostname keeps its spelling otherwise, so it matches
// the bytes validator clients sign.
// See https://github.com/ethereum/builder-specs/blob/61aeca42d9ba8eb467ae230d191ebc1c3f38107d/specs/gloas/validator.md#default-auth-data
func BuilderAuthData(builderURL string) ([]byte, error) {
	// urlsplit removes ASCII tab and newline characters anywhere in the URL.
	url := strings.NewReplacer("\t", "", "\r", "", "\n", "").Replace(builderURL)

	_, rest, ok := strings.Cut(url, "://")
	if !ok {
		return nil, errors.New("builder URL has no scheme", z.Str("url", builderURL))
	}

	authority, _, _ := strings.Cut(rest, "/")
	authority, _, _ = strings.Cut(authority, "?")
	authority, _, _ = strings.Cut(authority, "#")

	if i := strings.LastIndex(authority, "@"); i >= 0 {
		authority = authority[i+1:]
	}

	var host string

	if literal, ok := strings.CutPrefix(authority, "["); ok {
		literal, _, ok = strings.Cut(literal, "]")
		if !ok {
			return nil, errors.New("builder URL has an unterminated IPv6 literal", z.Str("url", builderURL))
		}

		addr, err := netip.ParseAddr(literal)
		if err != nil || !addr.Is6() || addr.Zone() != "" {
			return nil, errors.New("builder URL has an invalid IPv6 literal", z.Str("url", builderURL))
		}

		host = "[" + compressIPv6(addr) + "]"
	} else {
		host, _, _ = strings.Cut(authority, ":")
	}

	if host == "" || !isASCII(host) {
		return nil, errors.New("builder URL has no ASCII hostname", z.Str("url", builderURL))
	}

	return []byte(strings.ToLower(host)), nil
}

// compressIPv6 returns the RFC 5952 compressed form of the IPv6 address using hexadecimal groups
// only: netip writes IPv4-mapped addresses in the mixed IPv4 notation, which builder-specs excludes.
func compressIPv6(addr netip.Addr) string {
	if !addr.Is4In6() {
		return addr.String()
	}

	b := addr.As16()

	return fmt.Sprintf("::ffff:%x:%x", uint16(b[12])<<8|uint16(b[13]), uint16(b[14])<<8|uint16(b[15]))
}

func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= 0x80 {
			return false
		}
	}

	return true
}
