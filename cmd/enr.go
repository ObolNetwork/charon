/*
Copyright © 2021 Oisín Kyne <oisin@obol.tech>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// enrCmd represents the enr command
var enrCmd = &cobra.Command{
	Use:   "enr",
	Short: "Return information about this node's ENR",
	Long:  `Return information on this node's Ethereum Node Record (ENR)`,
	Run: func(cmd *cobra.Command, args []string) {
		enrInfo()
	},
}

func init() {
	infoCmd.AddCommand(enrCmd)
}

// Function for printing status of ENR for this instance
func enrInfo() {
	fmt.Println("Checking for the presence of an Ethereum Node Record for this client")
	fmt.Println("None found")
	fmt.Println("enr:-")
}
