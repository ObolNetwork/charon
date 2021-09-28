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

// beaconCmd represents the beacon command
var beaconCmd = &cobra.Command{
	Use:   "beacon",
	Short: "Test the connection to upstream beacon clients",
	Long: `Test that one or more configured beacon chain consensus clients are accessible and that they implement the required minimum validator API endpoints.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("beacon called")
	},
}

func init() {
	testCmd.AddCommand(beaconCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// beaconCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// beaconCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
