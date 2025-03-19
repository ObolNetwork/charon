// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"context"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth1wrap"
	erc1271 "github.com/obolnetwork/charon/app/eth1wrap/generated"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/manifest"
	manifestpb "github.com/obolnetwork/charon/cluster/manifestpb/v1"
)

// loadClusterManifest returns the cluster manifest from the given file path.
func loadClusterManifest(ctx context.Context, conf Config) (*manifestpb.Cluster, error) {
	if conf.TestConfig.Lock != nil {
		return manifest.NewClusterFromLockForT(nil, *conf.TestConfig.Lock)
	}

	verifyLock := func(lock cluster.Lock) error {
		if err := lock.VerifyHashes(); err != nil && !conf.NoVerify {
			return errors.Wrap(err, "cluster lock hash verification failed. Run with --no-verify to bypass verification at own risk")
		} else if err != nil && conf.NoVerify {
			log.Warn(ctx, "Ignoring failed cluster lock hash verification due to --no-verify flag", err)
		}

		eth1Cl := eth1wrap.NewEthClientRunner(conf.ExecutionEngineAddr,
			func(ctx context.Context, url string) (eth1wrap.EthClient, error) {
				cl, err := ethclient.DialContext(ctx, url)
				if err != nil {
					return nil, errors.Wrap(err, "failed to connect to eth1 client")
				}

				return cl, nil
			},
			func(contractAddress string, cl eth1wrap.EthClient) (eth1wrap.Erc1271, error) {
				addr := common.HexToAddress(contractAddress)
				erc1271, err := erc1271.NewErc1271(addr, cl)
				if err != nil {
					return nil, errors.Wrap(err, "failed to create binding to ERC1271 contract")
				}

				return erc1271, nil
			},
		)

		if err := lock.VerifySignatures(eth1Cl); err != nil && !conf.NoVerify {
			return errors.Wrap(err, "cluster lock signature verification failed. Run with --no-verify to bypass verification at own risk")
		} else if err != nil && conf.NoVerify {
			log.Warn(ctx, "Ignoring failed cluster lock signature verification due to --no-verify flag", err)
		}

		return nil
	}

	cluster, err := manifest.LoadCluster(conf.ManifestFile, conf.LockFile, verifyLock)
	if err != nil {
		return nil, errors.Wrap(err, "load cluster manifest")
	}

	return cluster, nil
}
