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

package cmd

import (
	"crypto/ecdsa"
	"io"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/p2p"
)

func TestRunCreateEnr(t *testing.T) {
	temp, err := os.MkdirTemp("", "")
	require.NoError(t, err)

	err = runCreateEnrCmd(io.Discard, p2p.Config{}, temp)
	require.NoError(t, err)
}

func TestCreateENR(t *testing.T) {
	config := p2p.Config{
		TCPAddrs: []string{"127.0.0.1:3610"},
		UDPAddr:  "127.0.0.1:3630",
	}

	key, err := ecdsa.GenerateKey(crypto.S256(), rand.New(rand.NewSource(time.Now().Unix())))
	require.NoError(t, err)

	enr1, err := createENR(key, config)
	require.NoError(t, err)

	enr2, err := createENR(key, config)
	require.NoError(t, err)
	require.Equal(t, enr1, enr2)
}
