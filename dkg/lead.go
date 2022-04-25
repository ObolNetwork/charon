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

package dkg

import (
	"context"
	"crypto/rand"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/p2p"
)

type ClusterConfig struct {
	Validators int
	Threshold  int
}

type LeadConfig struct {
	ManifestFile  string
	DataDir       string
	P2PConfig     p2p.Config
	LogConfig     log.Config
	ClusterConfig ClusterConfig
}

// Lead starts a libp2p tcp node and generates distributed validator keys and manifest lock file.
func Lead(ctx context.Context, conf LeadConfig) error {
	ctx = log.WithTopic(ctx, "dkg")

	if err := log.InitLogger(conf.LogConfig); err != nil {
		return err
	}

	manifest, err := loadManifest(conf.ManifestFile)
	if err != nil {
		return err
	}

	tcpNode, shutdown, err := setupP2P(conf.DataDir, conf.P2PConfig, manifest.Peers)
	if err != nil {
		return err
	}
	defer shutdown()

	var outs []output
	for i := 0; i < conf.ClusterConfig.Validators; i++ {
		t := conf.ClusterConfig.Threshold
		out, err := leadKeyCast(ctx, tcpNode, manifest.Peers, t, rand.Reader)
		if err != nil {
			return err
		}
		outs = append(outs, out)
	}

	err = writeOutput(manifest, conf.DataDir, outs)
	if err != nil {
		return err
	}

	return nil
}
