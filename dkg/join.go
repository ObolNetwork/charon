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
	"path"

	"github.com/libp2p/go-libp2p-core/host"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/p2p"
)

// JoinConfig defines the configuration required to join a DKG ceremony.
type JoinConfig struct {
	DataDir       string
	P2PConfig     p2p.Config
	LogConfig     log.Config
	ClusterConfig ClusterConfig
}

// Join starts a libp2p tcp node and generates distributed validator keys and manifest lock file.
func Join(ctx context.Context, conf JoinConfig) error {
	ctx = log.WithTopic(ctx, "dkg")

	if err := log.InitLogger(conf.LogConfig); err != nil {
		return err
	}

	manifest, err := loadManifest(path.Join(conf.DataDir, "manifest.yml"))
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
		out, err := joinKeyCast(ctx, tcpNode)
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

// setupP2P returns a started libp2p tcp node and a shutdown function.
func setupP2P(datadir string, p2pConf p2p.Config, peers []p2p.Peer) (host.Host, func(), error) {
	key, err := p2p.LoadPrivKey(datadir)
	if err != nil {
		return nil, nil, err
	}

	localEnode, db, err := p2p.NewLocalEnode(p2pConf, key)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to open enode")
	}

	udpNode, err := p2p.NewUDPNode(p2pConf, localEnode, key, nil)
	if err != nil {
		return nil, nil, errors.Wrap(err, "")
	}

	tcpNode, err := p2p.NewTCPNode(p2pConf, key, p2p.NewOpenGater(), udpNode, peers, nil)
	if err != nil {
		return nil, nil, errors.Wrap(err, "")
	}

	return tcpNode, func() {
		db.Close()
		udpNode.Close()
		_ = tcpNode.Close()
	}, nil
}
