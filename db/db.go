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

package db

import (
	"testing"

	"github.com/dgraph-io/badger/v3"
)

type Config struct {
	// TODO(corver): Add config.
}

func Open(conf Config) (*badger.DB, error) {
	return badger.Open(badger.DefaultOptions(""))
}

func OpenForT(t *testing.T) *badger.DB {
	t.Helper()
	bdb, err := badger.Open(badger.DefaultOptions("").WithInMemory(true))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = bdb.Close()
	})
	return bdb
}
