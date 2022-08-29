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

// Command verifypr provides a tool to verify charon PRs against the template defined in docs/contibuting.md.
package main

import (
	"log"
	"os"
)

func main() {
	err := verify()
	if err != nil {
		log.Printf("❌ Verification failed: %+v\n", err)
		os.Exit(1)
	}

	log.Println("✅ Verification Success")
}
