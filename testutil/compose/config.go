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

package compose

const (
	version           = "obol/charon/compose/1.0.0"
	configFile        = "config.json"
	defaultImageTag   = "latest"
	defaultBeaconNode = "mock"
	defaultKeyGen     = KeyGenCreate
	defaultNumVals    = 1
	defaultNumNodes   = 4
	defaultThreshold  = 3
	defaultFeatureSet = "alpha"

	charonImage      = "obolnetwork/charon"
	containerBinary  = "/usr/local/bin/charon"
	cmdRun           = "run"
	cmdDKG           = "dkg"
	cmdCreateCluster = "[create,cluster]"
	cmdCreateDKG     = "[create,dkg]"
)

var charonPorts = []port{
	{External: 3600, Internal: 3600}, // # Validator API
	{External: 3610, Internal: 3610}, // # Libp2p
	{External: 3620, Internal: 3620}, // # Monitoring
	{External: 3630, Internal: 3630}, // # Discv5
}

// VCType defines a validator client type.
type VCType string

const (
	VCMock       VCType = "mock"
	VCTeku       VCType = "teku"
	VCLighthouse VCType = "lighthouse"
)

// KeyGen defines a key generation process.
type KeyGen string

const (
	KeyGenDKG    KeyGen = "dkg"
	KeyGenCreate KeyGen = "create"
)

// step defines the current completed compose step.
type step string

const (
	stepNew     step = "new"
	stepDefined step = "defined"
	stepLocked  step = "locked"
)

// Config defines a local compose cluster; including both keygen and running a cluster.
type Config struct {
	// Version defines the compose config version.
	Version string `json:"version"`

	// Step defines the current completed compose step.
	Step step `json:"step"`

	// NumNodes is the number of charon nodes in the cluster.
	NumNodes int `json:"num_nodes"`

	// Threshold required for signature reconstruction. Defaults to safe value for number of nodes/peers.
	Threshold int `json:"threshold"`

	// NumValidators is the number of DVs (n*32ETH) to be created in the cluster lock file.
	NumValidators int `json:"num_validators"`

	// ImageTag defines the charon docker image tag: obolnetwork/charon:{ImageTag}.
	ImageTag string `json:"image_tag"`

	// BuildLocal enables building a local docker container from source overriding ImageTag with 'local'.
	BuildLocal bool `json:"build_local"`

	// KeyGen defines the key generation process.
	KeyGen KeyGen `json:"key_gen"`

	// SplitKeysDir directory containing keys to split for keygen==create.
	SplitKeysDir string `json:"split_keys_dir"`

	// BeaconNode url endpoint or "mock" for simnet.
	BeaconNode string `json:"beacon_node"`

	// ExternalRelay HTTP url endpoint or empty to disable.
	ExternalRelay string `json:"external_relay"`

	// VCs define the types of validator clients to use.
	VCs []VCType `json:"validator_clients"`

	// FeatureSet defines the minimum feature set to enable.
	FeatureSet string `json:"feature_set"`

	// DisableMonitoringPorts defines whether to disable prometheus and jaeger monitoring port binding.
	DisableMonitoringPorts bool `json:"disable_monitoring_ports"`

	// InsecureKeys generates insecure keys. Useful when testing large validator sets
	// as it speeds up keystore encryption and decryption.
	InsecureKeys bool `json:"insecure_keys"`
}

// VCStrings returns the VCs field as a slice of strings.
func (c Config) VCStrings() []string {
	var resp []string
	for _, vc := range c.VCs {
		resp = append(resp, string(vc))
	}

	return resp
}

// NewDefaultConfig returns a new default config.
func NewDefaultConfig() Config {
	return Config{
		Version:       version,
		NumNodes:      defaultNumNodes,
		Threshold:     defaultThreshold,
		NumValidators: defaultNumVals,
		ImageTag:      defaultImageTag,
		VCs:           []VCType{VCTeku, VCLighthouse, VCMock},
		KeyGen:        defaultKeyGen,
		BeaconNode:    defaultBeaconNode,
		Step:          stepNew,
		FeatureSet:    defaultFeatureSet,
	}
}
