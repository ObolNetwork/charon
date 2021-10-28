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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// beaconCmd represents the beacon command
var beaconCmd = &cobra.Command{
	Use:   "beacon",
	Short: "Test the connection to upstream beacon clients",
	Long:  `Test that one or more configured beacon chain consensus clients are accessible and that they implement the required minimum validator API endpoints.`,
	Run: func(cmd *cobra.Command, args []string) {
		testBeaconClient()
	},
}

func init() {
	testCmd.AddCommand(beaconCmd)
}

// Main function that organises API requests to the configured Beacon node and posts summary data to console
func testBeaconClient() {
	var beaconURI string = viper.GetString("beacon-node")
	fmt.Printf("Testing readiness of beacon client at: %s\n\n", beaconURI)

	chainSpec := getChainSpec(beaconURI)
	spec := specJSON{}

	if err := json.Unmarshal(chainSpec, &spec); err != nil {
		fmt.Printf("Could not unmarshal chain spec response. %#v", err)
	}

	nodeVersionResponse := getNodeVersion(beaconURI)
	version := specJSON{}

	if err := json.Unmarshal(nodeVersionResponse, &version); err != nil {
		fmt.Printf("Could not unmarshal node version response. %#v", err)
	}

	// Debug Chain Spec Response Object
	// fmt.Printf("%#v\r\n", spec)
	// Debug Node Version Response Object
	// fmt.Printf("%#v\r\n", version)

	nodeVersion := version.Data["version"]
	genesisForkVersion := spec.Data["GENESIS_FORK_VERSION"]
	eth1ChainID := spec.Data["DEPOSIT_NETWORK_ID"]
	fmt.Printf("Results:\n")
	fmt.Printf("Node version: %s\r\n", nodeVersion)
	fmt.Printf("Genesis fork version (which eth2 chain): %s\r\n", genesisForkVersion)
	fmt.Printf("Eth1 Chain ID (which eth1 chain is upstream): %s\r\n", eth1ChainID)
}

// Retrieves info from the Beacon Chain Spec endpoint
func getChainSpec(baseAPI string) []byte {
	request, err := http.NewRequest(
		http.MethodGet,                //method
		baseAPI+"/eth/v1/config/spec", //url
		nil,                           //body
	)

	if err != nil {
		fmt.Printf("Could not request data from the chain spec endpoint. %v", err)
	}

	request.Header.Add("Accept", "application/json")
	request.Header.Add("User-Agent", "Charon SSV Client (https://github.com/ObolNetwork/charon)")

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		fmt.Printf("Could not make a request. %v", err)
	}

	responseBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Printf("Could not read response body. %v", err)
	}

	return responseBytes
}

// Retrieves info from the Beacon Chain node version endpoint
func getNodeVersion(baseAPI string) []byte {
	request, err := http.NewRequest(
		http.MethodGet,                 //method
		baseAPI+"/eth/v1/node/version", //url
		nil,                            //body
	)

	if err != nil {
		fmt.Printf("Could not request node version from the API endpoint. %v", err)
	}

	request.Header.Add("Accept", "application/json")
	request.Header.Add("User-Agent", "Charon SSV Client (https://github.com/ObolNetwork/charon)")

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		fmt.Printf("Could not make a request. %v", err)
	}

	responseBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Printf("Could not read response body. %v", err)
	}

	return responseBytes
}

// Struct for storing the API response objects that are single key JSON objects with key 'data'
type specJSON struct {
	Data map[string]string `json:"data"`
}
