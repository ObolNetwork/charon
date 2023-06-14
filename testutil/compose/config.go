// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package compose

import "time"

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
	VCVouch      VCType = "vouch"
	VCLodestar   VCType = "lodestar"
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

	// BeaconNodes url endpoint or "mock" for simnet.
	BeaconNodes string `json:"beacon_nodes"`

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

	// SlotDuration configures slot duration on simnet beacon mock for all the nodes in the cluster.
	SlotDuration time.Duration `json:"slot_duration"`

	// Fuzz configures simnet beaconmock to return fuzzed responses.
	Fuzz bool `json:"fuzz"`

	// SyntheticBlockProposals configures use of synthetic block proposals in simnet cluster.
	SyntheticBlockProposals bool `json:"synthetic_block_proposals"`

	// Monitoring enables monitoring stack for the compose cluster. It includes grafana, loki and jaeger services.
	Monitoring bool `json:"monitoring"`
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
		Version:                 version,
		NumNodes:                defaultNumNodes,
		Threshold:               defaultThreshold,
		NumValidators:           defaultNumVals,
		ImageTag:                defaultImageTag,
		VCs:                     []VCType{VCTeku, VCLighthouse, VCMock},
		KeyGen:                  defaultKeyGen,
		BeaconNodes:             defaultBeaconNode,
		Step:                    stepNew,
		FeatureSet:              defaultFeatureSet,
		SlotDuration:            time.Second,
		SyntheticBlockProposals: true,
		Monitoring:              true,
	}
}
