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

package cmd

const (
	KeyDataDir     = "data-dir"
	KeyClustersDir = "clusters-dir"
	KeyConfigFile  = "config-file"
	KeyBeaconNode  = "beacon-node"
	KeyLogLevel    = "log-level"
	KeyAPI         = "api"
	KeyVerbose     = "verbose"
	KeyValidators  = "validators"
)

type P2PConfig struct {
	Address   string
	TcpPort   int
	UdpPort   int
	AllowList []string
	DenyList  []string
}

type MonitoringConfig struct {
	Address string
	Port    int
}

type ValidatorApiConfig struct {
	Address string
	Port    int
}

type BeaconNodeConfig struct {
	Endpoint []string
}

type RunnerConfig struct {
	BeaconNodeUrl   string
	ControlPlaneApi MonitoringConfig
	DataDir         string
	LogLevel        string
	VerboseFlag     bool
	ClusterConfig
}

type ClusterConfig struct {
	ClusterFilepath     string
	CertificateFilepath string
	PrivateKeyFilepath  string
	PrivateKeyPassword  string
}
