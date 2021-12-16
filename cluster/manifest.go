package cluster

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/drand/kyber"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/obolnetwork/charon/crypto"
	"github.com/obolnetwork/charon/internal/config"
	zerologger "github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

// Manifest captures the public cryptographic and networking info required to connect to a DV cluster.
type Manifest struct {
	TSS     crypto.TBLSScheme     `json:"tss"`     // Threshold signature scheme params
	Members []crypto.BLSPubkeyHex `json:"members"` // DV consensus BLS pubkeys
	ENRs    []string              `json:"enrs"`    // Charon peer ENRs
}

// Pubkey returns the BLS public key of the distributed validator.
func (m *Manifest) Pubkey() kyber.Point {
	return m.TSS.Pubkey()
}

// ParsedENRs returns the decoded list of ENRs in a manifest.
func (m *Manifest) ParsedENRs() ([]enr.Record, error) {
	records := make([]enr.Record, len(m.ENRs))
	for i, enrStr := range m.ENRs {
		record, err := DecodeENR(enrStr)
		if err != nil {
			return nil, fmt.Errorf("invalid ENR: %w for \"%s\"", err, enrStr)
		}
		records[i] = *record
	}
	return records, nil
}

func DecodeENR(enrStr string) (*enr.Record, error) {
	enrStr = strings.TrimPrefix(enrStr, "enr:")
	enrBytes, err := base64.StdEncoding.DecodeString(enrStr)
	if err != nil {
		return nil, err
	}
	// TODO support hex encoding too?
	var record enr.Record
	rd := bytes.NewReader(enrBytes)
	if err := rlp.Decode(rd, &record); err != nil {
		return nil, err
	}
	if rd.Len() > 0 {
		return nil, fmt.Errorf("leftover garbage bytes in ENR")
	}
	return &record, nil
}

// KnownClusters is a registry of known clusters.
type KnownClusters struct {
	clusters map[string]*Manifest
}

// clusterSuffix is the file extension that each cluster file should have.
var clusterSuffix = ".dv.json"

// LoadKnownClusters loads cluster specs.
func LoadKnownClusters() (KnownClusters, error) {
	return LoadKnownClustersFromDir(viper.GetString(config.KeyClustersDir))
}

// LoadKnownClustersFromDir discovers clusters from the given directory.
func LoadKnownClustersFromDir(dir string) (KnownClusters, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return KnownClusters{}, err
	}
	known := KnownClusters{clusters: make(map[string]*Manifest)}
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !strings.HasSuffix(entry.Name(), clusterSuffix) {
			continue
		}
		cluster, err := LoadCluster(filepath.Join(dir, entry.Name()))
		if err != nil {
			zerologger.Warn().Err(err).Msg("Ignoring invalid cluster file")
			continue
		}
		pubkeyHex := crypto.BLSPointToHex(cluster.Pubkey())
		known.clusters[pubkeyHex] = cluster
	}
	return known, nil
}

// GetCluster returns the cluster for the given BLS public key.
//
// Returns nil if no matching cluster was found.
func (k KnownClusters) GetCluster(pubkey kyber.Point) *Manifest {
	return k.clusters[crypto.BLSPointToHex(pubkey)]
}

// Clusters returns a list of known clusters.
func (k KnownClusters) Clusters() map[string]*Manifest {
	return k.clusters
}

// LoadCluster reads the cluster file from the given file path.
func LoadCluster(filePath string) (*Manifest, error) {
	buf, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	c := new(Manifest)
	err = json.Unmarshal(buf, c)
	return c, err
}
