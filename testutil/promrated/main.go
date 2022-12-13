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

// Command promrated grabs rated stats for all monitored charon clusters

package main

import (
	"context"
	"os"
	"time"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

var cfg Config

func init() {
	if len(os.Args) == 2 {
		err := initConfig(os.Args[1], &cfg)
		if err != nil {
			panic(err)
		}
	} else {
		panic("No config file provided.")
	}
}

func main() {
	ctx := context.Background()

	for {
		log.Info(ctx, "Promrated looping.", z.Str("network", cfg.Network))

		sleepFor := time.Minute * time.Duration(10)
		time.Sleep(sleepFor)
	}
}
