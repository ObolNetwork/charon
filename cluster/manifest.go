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
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/rlp"
	libp2pcrypto "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	zerologger "github.com/rs/zerolog/log"
	"github.com/spf13/viper"

	"github.com/obolnetwork/charon/crypto"
	"github.com/obolnetwork/charon/internal/config"
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

// PeerIDs maps ENRs to libp2p peer IDs.
//
// TODO This can be computed at deserialization-time.
func (m *Manifest) PeerIDs() ([]peer.ID, error) {
	records, err := m.ParsedENRs()
	if err != nil {
		return nil, err
	}
	ids := make([]peer.ID, len(records))

	for i := range records {
		var err error
		ids[i], err = PeerIDFromENR(&records[i])
		if err != nil {
			return nil, err
		}
	}

	return ids, nil
}

// PeerIDFromENR derives the libp2p peer ID from the secp256k1 public key encoded in the ENR.
func PeerIDFromENR(record *enr.Record) (peer.ID, error) {
	var pubkey enode.Secp256k1
	if err := record.Load(&pubkey); err != nil {
		recordStr, _ := EncodeENR(record)
		zerologger.Warn().Err(err).
			Str("enr", recordStr).
			Msg("ENR missing secp256k1 field")

		return "", err
	}
	p2pPubkey := libp2pcrypto.Secp256k1PublicKey(pubkey)
	p2pID, err := peer.IDFromPublicKey(&p2pPubkey)
	if err != nil {
		recordStr, _ := EncodeENR(record)
		zerologger.Warn().Err(err).
			Str("enr", recordStr).
			Msg("Failed to derive libp2p ID")

		return "", err
	}

	return p2pID, nil
}

func EncodeENR(record *enr.Record) (string, error) {
	var buf bytes.Buffer
	if err := record.EncodeRLP(&buf); err != nil {
		return "", err
	}

	return "enr:" + base64.URLEncoding.EncodeToString(buf.Bytes()), nil
}

func DecodeENR(enrStr string) (*enr.Record, error) {
	enrStr = strings.TrimPrefix(enrStr, "enr:")
	enrBytes, err := base64.URLEncoding.DecodeString(enrStr)
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
		cluster, err := LoadManifest(filepath.Join(dir, entry.Name()))
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

// LoadManifest reads the manifest file from the given file path.
func LoadManifest(filePath string) (*Manifest, error) {
	buf, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	c := new(Manifest)
	err = json.Unmarshal(buf, c)

	return c, err
}
