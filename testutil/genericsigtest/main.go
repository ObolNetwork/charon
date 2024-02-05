// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/manifest"
	manifestpb "github.com/obolnetwork/charon/cluster/manifestpb/v1"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/tbls"
)

type genericSignatureJSON struct {
	Hash            string `json:"hash"`
	Signature       string `json:"signature"`
	ValidatorPubkey string `json:"validator_pubkey"`
}

type fullSignatureJSON struct {
	Signature string `json:"signature"`
	Error     string `json:"error"`
}

func main() {
	var (
		hash   = "0x2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"
		pubkey = "0xb74d1ecdb3a585589c00d45ce569ccae523524476d30c06b893dd4a57821580c63003137eb87356acdf5ac19f9fb0a53"
		port   = "3650"
	)

	ctx := context.Background()

	// stolen from combine

	_, possibleKeyPaths, err := loadManifest(ctx, os.Args[1], false)
	if err != nil {
		panic(err)
	}

	privkeys := make(map[int][]tbls.PrivateKey)

	for _, pkp := range possibleKeyPaths {
		log.Info(ctx, "Loading keystore", z.Str("path", pkp))

		keyFiles, err := keystore.LoadFilesUnordered(pkp)
		if err != nil {
			panic(err)
		}

		secrets, err := keyFiles.SequencedKeys()
		if err != nil {
			panic(err)
		}

		for idx, secret := range secrets {
			privkeys[idx] = append(privkeys[idx], secret)
		}
	}

	thresholdSigs := make(map[int]tbls.Signature)
	for i := 0; i < 4; i++ {
		var addr string

		if i == 0 {
			addr = fmt.Sprintf("http://localhost:%s/genericsig/push", port)
		} else {
			addr = fmt.Sprintf("http://localhost:%d%s/genericsig/push", i, port)
		}

		fmt.Println("pushing signature to", addr)

		h, err := hex.DecodeString(hash[2:])
		if err != nil {
			panic(err)
		}

		// we know we only have 1 validator for this test
		s, err := tbls.Sign(privkeys[0][i], h)
		if err != nil {
			panic(err)
		}

		thresholdSigs[i+1] = s

		sigPush := genericSignatureJSON{
			Hash:            hash,
			Signature:       "0x" + hex.EncodeToString(s[:]),
			ValidatorPubkey: pubkey,
		}

		spBytes, err := json.Marshal(sigPush)
		if err != nil {
			panic(err)
		}

		resp, err := http.Post(addr, "application/json", bytes.NewReader(spBytes))
		if err != nil {
			panic(err)
		}

		if resp.StatusCode != http.StatusOK {
			panic(fmt.Sprintf("status code %s", resp.Status))
		}
	}

	aggSig, err := tbls.ThresholdAggregate(thresholdSigs)
	if err != nil {
		panic(err)
	}

	aggSigHex := "0x" + hex.EncodeToString(aggSig[:])

	for i := 0; i < 4; i++ {
		var addr string

		if i == 0 {
			addr = fmt.Sprintf("http://localhost:%s/genericsig/%s/%s", port, pubkey, hash)
		} else {
			addr = fmt.Sprintf("http://localhost:%d%s/genericsig/%s/%s", i, port, pubkey, hash)
		}

		for tries := 0; tries < 10; tries++ {
			var resp fullSignatureJSON

			httpResp, err := http.Get(addr)
			if err != nil {
				panic(err)
			}

			if httpResp.StatusCode != http.StatusOK {
				fmt.Printf("status code %d, retrying in 1s\n", httpResp.StatusCode)
				time.Sleep(1 * time.Second)
				continue
			}

			if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
				panic(err)
			}

			defer httpResp.Body.Close()

			if resp.Error != "" {
				fmt.Printf("remote error: %s\n", resp.Error)
				time.Sleep(1 * time.Second)
				continue
			}

			fmt.Println(i, resp.Signature == aggSigHex)
			break
		}
	}
}

func loadManifest(ctx context.Context, dir string, noverify bool) (*manifestpb.Cluster, []string, error) {
	root, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, errors.Wrap(err, "can't read directory")
	}

	var (
		possibleValKeysDir []string
		lastCluster        *manifestpb.Cluster
	)

	for _, sd := range root {
		if !sd.IsDir() {
			continue
		}

		// try opening the lock file
		lockFile := filepath.Join(dir, sd.Name(), "cluster-lock.json")
		manifestFile := filepath.Join(dir, sd.Name(), "cluster-manifest.pb")

		cl, err := manifest.LoadCluster(manifestFile, lockFile, func(lock cluster.Lock) error {
			return verifyLock(ctx, lock, noverify)
		})
		if err != nil {
			return nil, nil, errors.Wrap(err, "manifest load error", z.Str("name", sd.Name()))
		}

		if !noverify {
			if lastCluster != nil && !bytes.Equal(lastCluster.LatestMutationHash, cl.LatestMutationHash) {
				return nil, nil, errors.New("mismatching last mutation hash")
			}
		}

		// does this directory contains a "validator_keys" directory? if yes continue and add it as a candidate
		vcdPath := filepath.Join(dir, sd.Name(), "validator_keys")
		_, err = os.ReadDir(vcdPath)
		if err != nil {
			continue
		}

		possibleValKeysDir = append(possibleValKeysDir, vcdPath)

		lastCluster = cl
	}

	if lastCluster == nil {
		return nil, nil, errors.New("no manifest file found")
	}

	return lastCluster, possibleValKeysDir, nil
}

func verifyLock(ctx context.Context, lock cluster.Lock, noverify bool) error {
	if err := lock.VerifyHashes(); err != nil && !noverify {
		return errors.Wrap(err, "cluster lock hash verification failed. Run with --no-verify to bypass verification at own risk")
	} else if err != nil && noverify {
		log.Warn(ctx, "Ignoring failed cluster lock hash verification due to --no-verify flag", err)
	}

	if err := lock.VerifySignatures(); err != nil && !noverify {
		return errors.Wrap(err, "cluster lock signature verification failed. Run with --no-verify to bypass verification at own risk")
	} else if err != nil && noverify {
		log.Warn(ctx, "Ignoring failed cluster lock signature verification due to --no-verify flag", err)
	}

	return nil
}
