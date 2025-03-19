// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package p2p

import (
	"testing"

	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
)

func TestFilterAdvertisedAddrs(t *testing.T) {
	priv1 := "/ip4/192.168.1.1/tcp/80"
	priv2 := "/ip4/127.0.0.1/udp/123"
	pub1 := "/ip4/1.1.1.1/tcp/80"

	tests := []struct {
		name           string
		internal       []string
		external       []string
		excludePrivate bool
		result         []string
	}{
		{
			name: "empty",
		},
		{
			name:           "drop one private",
			internal:       []string{pub1, priv1},
			excludePrivate: true,
			result:         []string{pub1},
		},
		{
			name:           "keep one private",
			internal:       []string{pub1, priv1},
			excludePrivate: false,
			result:         []string{pub1, priv1},
		},
		{
			name:           "duplicate public",
			internal:       []string{pub1, priv1},
			external:       []string{priv1, pub1},
			excludePrivate: true,
			result:         []string{priv1, pub1},
		},
		{
			name:           "duplicate private",
			internal:       []string{priv1, priv2},
			external:       []string{priv2, priv1},
			excludePrivate: false,
			result:         []string{priv2, priv1},
		},
		{
			name:           "drop all private",
			internal:       []string{priv1, priv2},
			excludePrivate: true,
			result:         nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cast := func(addrs []string) []ma.Multiaddr {
				var resp []ma.Multiaddr
				for _, addr := range addrs {
					maddr, err := ma.NewMultiaddr(addr)
					require.NoError(t, err)

					resp = append(resp, maddr)
				}

				return resp
			}

			res := filterAdvertisedAddrs(cast(test.external), cast(test.internal), test.excludePrivate)
			var resStr []string
			for _, mAddr := range res {
				resStr = append(resStr, mAddr.String())
			}
			require.EqualValues(t, test.result, resStr)
		})
	}
}
