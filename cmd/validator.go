/*
Copyright © 2021 Obol Technologies Inc.

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

// validatorCmd represents the validator command
var validatorCmd = &cobra.Command{
	Use:   "validator",
	Short: "Test the connection to a downstream validator client",
	Long: `This command is as of yet un-implemented, as with current middleware architecture designs, the dependent validator does not
	implement an HTTP server. Instead, it opens a HTTP2 event stream to the charon client, and subsequently makes POST requests to the client when it sees particular HTTP events.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("validator called")
	},
}

func init() {
	testCmd.AddCommand(validatorCmd)
}
