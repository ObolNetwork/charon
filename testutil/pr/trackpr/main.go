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
	"log"
	"os"

	"github.com/obolnetwork/charon/testutil/pr"
)

func main() {
	ghToken, ok := os.LookupEnv("GH_TOKEN")
	if !ok {
		log.Fatalf("❌ Github token not found")
	}

	prID, ok := os.LookupEnv("PR_ID")
	if !ok {
		log.Fatalf("cannot find PR_ID in env")
	}

	err := pr.Track(ghToken, prID)
	if err != nil {
		log.Fatalf("❌ Tracking failed: " + err.Error())
	}
	log.Println("✅ Tracking Success")
}
