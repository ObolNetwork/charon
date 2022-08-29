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

package main

import (
	"github.com/obolnetwork/charon/app/errors"
	"log"
	"os"

	"github.com/obolnetwork/charon/testutil/pr"
)

func main() {
	if err := run(); err != nil {
		log.Printf("❌ Fatal error: %#v\n", err)
		os.Exit(1)
	}

	log.Println("✅ Success")
}

func run() error {
	ghToken, ok := os.LookupEnv("GH_TOKEN")
	if !ok {
		return errors.New("GH_TOKEN not set")
	}

	p, err := pr.FromEnv()
	if err != nil {
		return err
	}

	err = pr.Track(ghToken, p)
	if err != nil {
		return err
	}

	return nil
}
