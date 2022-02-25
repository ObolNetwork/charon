// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package scheduler_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"strings"
	"testing"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2http "github.com/attestantio/go-eth2-client/http"
	"github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/scheduler"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/types"
)

const infoLevel = 1 // 1 is InfoLevel, this avoids importing zerolog directly.

var integration = flag.Bool("integration", false, "enable integration test, requires BEACON_URL vars.")

// TestIntegration runs an integration test for the Scheduler.
// It expects the above flag to enabled and a BEACON_URL env var.
// It then generates a fake manifest with actual mainnet validators
// and logs 10 duties triggered from them.
func TestIntegration(t *testing.T) {
	if !*integration {
		return
	}

	beaconURL, ok := os.LookupEnv("BEACON_URL")
	if !ok {
		t.Fatal("BEACON_URL env var not set")
	}

	ctx := context.Background()

	eth2Cl, err := eth2http.New(ctx, eth2http.WithAddress(beaconURL), eth2http.WithLogLevel(infoLevel))
	require.NoError(t, err)

	// Use random actual mainnet validators
	manifest := types.Manifest{
		DVs: []tbls.TSS{
			pkFromHex(t, "0x914cff835a769156ba43ad50b931083c2dadd94e8359ce394bc7a3e06424d0214922ddf15f81640530b9c25c0bc0d490"),
			pkFromHex(t, "0x8dae41352b69f2b3a1c0b05330c1bf65f03730c520273028864b11fcb94d8ce8f26d64f979a0ee3025467f45fd2241ea"),
			pkFromHex(t, "0x8ee91545183c8c2db86633626f5074fd8ef93c4c9b7a2879ad1768f600c5b5906c3af20d47de42c3b032956fa8db1a76"),
			pkFromHex(t, "0xa8785ecbb5c030e5da6cbbacc3e6cad39dffbc7bcf7f223a12844db8c1182603df99f673157f0d27912a53546e0f64fe"),
			pkFromHex(t, "0xb790b322e1cce41c48e3c344cf8d752bdc3cfd51e8eeef44a4bdaac081bc92b53b73e823a9878b5d7a532eb9d9dce1e3"),
		},
	}

	s, err := scheduler.New(manifest, eth2Cl)
	require.NoError(t, err)

	count := 10

	s.Subscribe(func(ctx context.Context, duty types.Duty, set types.DutyArgSet) error {
		for idx, data := range set {
			duty := new(eth2v1.AttesterDuty)
			err := json.Unmarshal(data, &duty)
			require.NoError(t, err)

			t.Logf("Duty triggered: vidx=%v slot=%v committee=%v\n", idx, duty.Slot, duty.CommitteeIndex)
		}
		count--
		if count == 0 {
			s.Stop()
		}

		return nil
	})

	require.NoError(t, s.Run())
}

func pkFromHex(t *testing.T, pk string) tbls.TSS {
	t.Helper()

	pk = strings.TrimPrefix(pk, "0x")

	b, err := hex.DecodeString(pk)
	require.NoError(t, err)

	pubkey := new(bls_sig.PublicKey)
	err = pubkey.UnmarshalBinary(b)
	require.NoError(t, err)

	return tbls.TSS{
		PublicKey: pubkey,
	}
}
