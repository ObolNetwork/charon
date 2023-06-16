// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util"
	"github.com/obolnetwork/charon/eth2util/keystore"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/obolnetwork/charon/testutil"
)

//go:generate go test . -run=TestCreateCluster -update -clean

func TestCreateCluster(t *testing.T) {
	defPath := "../cluster/examples/cluster-definition-004.json"
	def, err := loadDefinition(context.Background(), defPath)
	require.NoError(t, err)

	// Serve definition over network
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defBytes, err := os.ReadFile(defPath)
		require.NoError(t, err)

		_, err = w.Write(defBytes)
		require.NoError(t, err)
	}))
	defer srv.Close()

	tests := []struct {
		Name   string
		Config clusterConfig
		Prep   func(*testing.T, clusterConfig) clusterConfig
	}{
		{
			Name: "simnet",
			Config: clusterConfig{
				NumNodes:  4,
				Threshold: 3,
				NumDVs:    1,
			},
		},
		{
			Name: "splitkeys",
			Config: clusterConfig{
				NumNodes:  4,
				Threshold: 3,
				NumDVs:    1, // Default
				SplitKeys: true,
			},
			Prep: func(t *testing.T, config clusterConfig) clusterConfig {
				t.Helper()

				keyDir := t.TempDir()

				secret1, err := tbls.GenerateSecretKey()
				require.NoError(t, err)
				secret2, err := tbls.GenerateSecretKey()
				require.NoError(t, err)

				err = keystore.StoreKeysInsecure([]tbls.PrivateKey{secret1, secret2}, keyDir, keystore.ConfirmInsecureKeys)
				require.NoError(t, err)

				config.SplitKeysDir = keyDir

				return config
			},
		},
		{
			Name: "goerli",
			Config: clusterConfig{
				NumNodes:  minNodes,
				Threshold: 3,
				NumDVs:    2,
				Network:   "goerli",
			},
		},
		{
			Name: "solo flow definition from disk",
			Config: clusterConfig{
				DefFile: defPath,
			},
		},
		{
			Name: "solo flow definition from network",
			Config: clusterConfig{
				DefFile: srv.URL,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			if test.Prep != nil {
				test.Config = test.Prep(t, test.Config)
			}

			test.Config.InsecureKeys = true
			test.Config.WithdrawalAddrs = []string{zeroAddress}
			test.Config.FeeRecipientAddrs = []string{zeroAddress}

			if test.Config.Network == "" {
				test.Config.Network = eth2util.Goerli.Name
			}

			testCreateCluster(t, test.Config, def)
		})
	}
}

func testCreateCluster(t *testing.T, conf clusterConfig, def cluster.Definition) {
	t.Helper()

	dir := t.TempDir()
	conf.ClusterDir = dir
	conf.Name = t.Name()

	var buf bytes.Buffer
	err := runCreateCluster(context.Background(), &buf, conf)
	if err != nil {
		log.Error(context.Background(), "", err)
	}
	require.NoError(t, err)

	t.Run("output", func(t *testing.T) {
		out := bytes.ReplaceAll(buf.Bytes(), []byte(dir), []byte("charon"))
		testutil.RequireGoldenBytes(t, out)
	})

	t.Run("files", func(t *testing.T) {
		l1files, err := filepath.Glob(path.Join(dir, "*"))
		require.NoError(t, err)
		l2files, err := filepath.Glob(path.Join(dir, "*/*"))
		require.NoError(t, err)

		var files []string
		for _, file := range append(l1files, l2files...) {
			files = append(files, strings.TrimPrefix(file, dir+"/"))
		}

		testutil.RequireGoldenJSON(t, files)
	})

	t.Run("valid lock", func(t *testing.T) {
		// Since `cluster-lock.json` is copied into each node directory, use any one of them.
		b, err := os.ReadFile(path.Join(nodeDir(conf.ClusterDir, 0), "cluster-lock.json"))
		require.NoError(t, err)

		var lock cluster.Lock
		require.NoError(t, json.Unmarshal(b, &lock))
		require.NoError(t, lock.VerifyHashes())
		require.NoError(t, lock.VerifySignatures())

		// check that there are lock.Definition.NumValidators different public keys in the validator slice
		vals := make(map[string]struct{})
		for _, val := range lock.Validators {
			vals[val.PublicKeyHex()] = struct{}{}
		}

		require.Equal(t, lock.Definition.NumValidators, len(vals))

		if conf.DefFile != "" {
			// Config hash and creator should remain the same
			require.Equal(t, def.ConfigHash, lock.ConfigHash)
			require.Equal(t, def.Creator, lock.Creator)

			for i := 0; i < len(def.Operators); i++ {
				// ENRs should be populated
				require.NotEqual(t, lock.Operators[i].ENR, "")
			}
		}

		previousVersions := []string{"v1.0.0", "v1.1.0", "v1.2.0", "v1.3.0", "v1.4.0", "v1.5.0"}
		for _, val := range lock.Validators {
			if isAnyVersion(lock.Version, previousVersions...) {
				break
			}

			if isAnyVersion(lock.Version, "v1.6.0", "v1.7.0") {
				require.NotEmpty(t, val.DepositData)
			}

			if isAnyVersion(lock.Version, "v1.7.0") {
				require.NotEmpty(t, val.BuilderRegistration)
			}
		}

		if isAnyVersion(lock.Version, "v1.7.0") {
			require.NotEmpty(t, lock.NodeSignatures)
			for _, ns := range lock.NodeSignatures {
				require.NotEmpty(t, ns)
			}
		}
	})
}

func TestValidateDef(t *testing.T) {
	ctx := context.Background()
	conf := clusterConfig{
		Name:      "test",
		NumNodes:  4,
		NumDVs:    4,
		Threshold: 3,
		Network:   "goerli",
	}

	for i := 0; i < conf.NumDVs; i++ {
		conf.FeeRecipientAddrs = append(conf.FeeRecipientAddrs, testutil.RandomETHAddress())
		conf.WithdrawalAddrs = append(conf.WithdrawalAddrs, zeroAddress)
	}

	definition, err := newDefFromConfig(ctx, conf)
	require.NoError(t, err)

	defPath := "../cluster/examples/cluster-definition-002.json"
	remoteDef, err := loadDefinition(context.Background(), defPath)
	require.NoError(t, err)

	t.Run("zero address", func(t *testing.T) {
		def := definition
		gnosis, err := hex.DecodeString(strings.TrimPrefix(eth2util.Gnosis.ForkVersionHex, "0x"))
		require.NoError(t, err)
		def.ForkVersion = gnosis

		err = validateDef(ctx, false, conf.KeymanagerAddrs, def)
		require.Error(t, err, "zero address")
	})

	t.Run("fork versions", func(t *testing.T) {
		def := definition
		err = validateDef(ctx, false, conf.KeymanagerAddrs, def)
		require.NoError(t, err)

		mainnet, err := hex.DecodeString(strings.TrimPrefix(eth2util.Mainnet.ForkVersionHex, "0x"))
		require.NoError(t, err)
		def.ForkVersion = mainnet

		err = validateDef(ctx, conf.InsecureKeys, conf.KeymanagerAddrs, def)
		require.Error(t, err, "zero address")
	})

	t.Run("insufficient keymanager addresses", func(t *testing.T) {
		conf := conf
		conf.KeymanagerAddrs = []string{"127.0.0.1:1234"}

		err = validateDef(ctx, true, conf.KeymanagerAddrs, definition)
		require.Error(t, err)
	})

	t.Run("insecure keys", func(t *testing.T) {
		conf := conf
		err = validateDef(ctx, true, conf.KeymanagerAddrs, definition) // Validate with insecure keys set to true
		require.NoError(t, err)
	})

	t.Run("insufficient number of nodes", func(t *testing.T) {
		def := definition
		def.Operators = nil
		err = validateDef(ctx, conf.InsecureKeys, conf.KeymanagerAddrs, def)
		require.ErrorContains(t, err, "insufficient number of nodes")
	})

	t.Run("name not provided", func(t *testing.T) {
		def := definition
		def.Name = ""
		err = validateDef(ctx, conf.InsecureKeys, conf.KeymanagerAddrs, def)
		require.ErrorContains(t, err, "name not provided")
	})

	t.Run("zero validators provided", func(t *testing.T) {
		def := definition
		def.NumValidators = 0
		err = validateDef(ctx, conf.InsecureKeys, conf.KeymanagerAddrs, def)
		require.ErrorContains(t, err, "cannot create cluster with zero validators, specify at least one")
	})

	t.Run("invalid hash", func(t *testing.T) {
		def := remoteDef
		def.NumValidators = 3
		err = validateDef(ctx, conf.InsecureKeys, conf.KeymanagerAddrs, def)
		require.ErrorContains(t, err, "invalid config hash")
	})

	t.Run("invalid config signatures", func(t *testing.T) {
		def := remoteDef
		def.NumValidators = 3
		def, err = def.SetDefinitionHashes()
		require.NoError(t, err)
		err = validateDef(ctx, conf.InsecureKeys, conf.KeymanagerAddrs, def)
		require.ErrorContains(t, err, "invalid creator config signature")
	})
}

func TestSplitKeys(t *testing.T) {
	tests := []struct {
		name           string
		numSplitKeys   int
		conf           clusterConfig
		expectedErrMsg string
	}{
		{
			name:         "split keys from local definition with mismatch NumValidators",
			numSplitKeys: 2,
			conf: clusterConfig{
				DefFile: "../cluster/examples/cluster-definition-002.json",
			},
			expectedErrMsg: "number of keystores provided in split-keys-dir does not matches with NumValidators in the given definition file",
		},
		{
			name:         "split keys from local definition with same NumValidators",
			numSplitKeys: 1,
			conf: clusterConfig{
				DefFile:    "../cluster/examples/cluster-definition-002.json",
				ClusterDir: t.TempDir(),
			},
		},
		{
			name:         "split keys from config with one num-validators",
			numSplitKeys: 3,
			conf: clusterConfig{
				Name:              "test split keys",
				NumDVs:            1,
				NumNodes:          minNodes,
				Threshold:         3,
				FeeRecipientAddrs: []string{zeroAddress},
				WithdrawalAddrs:   []string{zeroAddress},
				ClusterDir:        t.TempDir(),
			},
		},
		{
			name:         "split keys from config with mismatch num-validators",
			numSplitKeys: 3,
			conf: clusterConfig{
				NumDVs:            2,
				FeeRecipientAddrs: []string{zeroAddress},
				WithdrawalAddrs:   []string{zeroAddress},
			},
			expectedErrMsg: "num-validators provided is not equal to keystores provided in split-keys-dir",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var keys []tbls.PrivateKey
			for i := 0; i < test.numSplitKeys; i++ {
				secret, err := tbls.GenerateSecretKey()
				require.NoError(t, err)

				keys = append(keys, secret)
			}

			keysDir := t.TempDir()

			err := keystore.StoreKeysInsecure(keys, keysDir, keystore.ConfirmInsecureKeys)
			require.NoError(t, err)

			test.conf.SplitKeysDir = keysDir
			test.conf.SplitKeys = true
			test.conf.InsecureKeys = true
			test.conf.Network = eth2util.Goerli.Name

			var buf bytes.Buffer
			err = runCreateCluster(context.Background(), &buf, test.conf)
			if test.expectedErrMsg != "" {
				require.ErrorContains(t, err, test.expectedErrMsg)
			} else {
				testutil.RequireNoError(t, err)

				// Since `cluster-lock.json` is copied into each node directory, use any one of them.
				b, err := os.ReadFile(path.Join(nodeDir(test.conf.ClusterDir, 0), "cluster-lock.json"))
				require.NoError(t, err)

				var lock cluster.Lock
				require.NoError(t, json.Unmarshal(b, &lock))
				require.NoError(t, lock.VerifyHashes())
				require.NoError(t, lock.VerifySignatures())

				require.Equal(t, test.numSplitKeys, lock.NumValidators)
			}
		})
	}
}

func TestMultipleAddresses(t *testing.T) {
	t.Run("insufficient addresses in config", func(t *testing.T) {
		err := runCreateCluster(context.Background(), io.Discard, clusterConfig{
			NumDVs:            4,
			FeeRecipientAddrs: []string{},
			WithdrawalAddrs:   []string{},
		})
		require.ErrorContains(t, err, "insufficient fee recipient addresses")
	})

	t.Run("insufficient addresses from remote URL", func(t *testing.T) {
		lock, _, _ := cluster.NewForT(t, 2, 3, 4, 1, func(d *cluster.Definition) {
			d.ValidatorAddresses = []cluster.ValidatorAddresses{}
		})

		def := lock.Definition

		// Serve definition over network
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defBytes, err := def.MarshalJSON()
			require.NoError(t, err)

			_, err = w.Write(defBytes)
			require.NoError(t, err)
		}))
		defer srv.Close()

		err := runCreateCluster(context.Background(), io.Discard, clusterConfig{DefFile: srv.URL, NumNodes: minNodes})
		require.ErrorContains(t, err, "num_validators not matching validators length")
	})
}

// TestKeymanager tests keymanager support by letting create cluster command split a single secret and then receiving those keyshares using test
// keymanager servers. These shares are then combined to create the combined share which is then compared to the original secret that was split.
func TestKeymanager(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const testAuthToken = "api-token-test"

	// Create secret
	secret1, err := tbls.GenerateSecretKey()
	require.NoError(t, err)

	// Store secret
	keyDir := t.TempDir()
	err = keystore.StoreKeysInsecure([]tbls.PrivateKey{secret1}, keyDir, keystore.ConfirmInsecureKeys)
	require.NoError(t, err)

	// Create minNodes test servers
	results := make(chan result, minNodes) // Buffered channel
	defer close(results)

	var addrs, authTokens []string
	var servers []*httptest.Server
	for i := 0; i < minNodes; i++ {
		srv := httptest.NewServer(newKeymanagerHandler(ctx, t, i, results))
		servers = append(servers, srv)
		addrs = append(addrs, srv.URL)
		authTokens = append(authTokens, testAuthToken)
	}

	defer func() {
		for _, srv := range servers {
			srv.Close()
		}
	}()

	// Create cluster config
	conf := clusterConfig{
		Name:                 t.Name(),
		SplitKeysDir:         keyDir,
		SplitKeys:            true,
		NumNodes:             minNodes,
		NumDVs:               1,
		KeymanagerAddrs:      addrs,
		KeymanagerAuthTokens: authTokens,
		Network:              eth2util.Goerli.Name,
		WithdrawalAddrs:      []string{zeroAddress},
		FeeRecipientAddrs:    []string{zeroAddress},
		Clean:                true,
		InsecureKeys:         true,
	}
	conf.ClusterDir = t.TempDir()

	t.Run("all successful", func(t *testing.T) {
		// Run create cluster command
		var buf bytes.Buffer
		err = runCreateCluster(context.Background(), &buf, conf)
		if err != nil {
			log.Error(context.Background(), "", err)
		}
		require.NoError(t, err)

		// Receive secret shares from all keymanager servers
		shares := make(map[int]tbls.PrivateKey)
		for len(shares) < minNodes {
			res := <-results
			shares[res.id+1] = res.secret
		}

		// Combine the shares and test equality with original share
		csb, err := tbls.RecoverSecret(shares, minNodes, 3)
		require.NoError(t, err)

		require.EqualValues(t, secret1, csb)
	})

	t.Run("some unsuccessful", func(t *testing.T) {
		// Close one server so that request to it fails
		servers[0].Close()

		// Run create cluster command
		var buf bytes.Buffer
		err = runCreateCluster(context.Background(), &buf, conf)
		if err != nil {
			log.Error(context.Background(), "", err)
		}
		require.ErrorContains(t, err, "cannot ping address")
	})

	t.Run("lengths don't match", func(t *testing.T) {
		// Construct an incorrect config where len(KeymanagerAuthTokens) = len(KeymanagerAddresses)-1
		incorrectConf := conf
		incorrectConf.KeymanagerAuthTokens = incorrectConf.KeymanagerAuthTokens[1:]

		err = runCreateCluster(context.Background(), nil, incorrectConf)
		require.ErrorContains(t, err, "number of --keymanager-addresses do not match --keymanager-auth-tokens. Please fix configuration flags")
	})
}

// TestPublish tests support for uploading the cluster lockfile to obol-api.
func TestPublish(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	result := make(chan struct{}, 1) // Buffered channel
	defer close(result)

	srv := httptest.NewServer(newObolAPIHandler(ctx, t, result))
	addr := srv.URL

	defer func() {
		srv.Close()
	}()

	// Create cluster config
	conf := clusterConfig{
		Name:              t.Name(),
		NumNodes:          minNodes,
		NumDVs:            1,
		Network:           eth2util.Goerli.Name,
		WithdrawalAddrs:   []string{zeroAddress},
		FeeRecipientAddrs: []string{zeroAddress},
		PublishAddr:       addr,
		Publish:           true,
		InsecureKeys:      true,
	}
	conf.ClusterDir = t.TempDir()

	t.Run("upload successful", func(t *testing.T) {
		// Run create cluster command
		var buf bytes.Buffer
		err := runCreateCluster(context.Background(), &buf, conf)
		if err != nil {
			log.Error(context.Background(), "", err)
		}

		require.NoError(t, err)
		require.Equal(t, <-result, struct{}{})
	})
}

// mockKeymanagerReq is a mock keymanager request for use in tests.
type mockKeymanagerReq struct {
	Keystores []string `json:"keystores"`
	Passwords []string `json:"passwords"`
}

// decrypt returns the secret from the encrypted keystore.
func decrypt(t *testing.T, store keystore.Keystore, password string) (tbls.PrivateKey, error) {
	t.Helper()

	decryptor := keystorev4.New()
	secretBytes, err := decryptor.Decrypt(store.Crypto, password)
	require.NoError(t, err)

	return tblsconv.PrivkeyFromBytes(secretBytes)
}

// result is a struct for receiving secrets along with their id.
// This is needed as tbls.CombineShares needs shares in the correct (original) order.
type result struct {
	id     int
	secret tbls.PrivateKey
}

// newKeymanagerHandler returns http handler for a test keymanager API server.
func newKeymanagerHandler(ctx context.Context, t *testing.T, id int, results chan<- result) http.Handler {
	t.Helper()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		defer func() {
			require.NoError(t, r.Body.Close())
		}()

		var req mockKeymanagerReq
		require.NoError(t, json.Unmarshal(data, &req))

		require.Equal(t, len(req.Keystores), len(req.Passwords))
		require.Equal(t, len(req.Keystores), 1) // Since we split only 1 key

		var ks keystore.Keystore
		require.NoError(t, json.Unmarshal([]byte(req.Keystores[0]), &ks))
		secret, err := decrypt(t, ks, req.Passwords[0])
		require.NoError(t, err)

		res := result{
			id:     id,
			secret: secret,
		}

		w.WriteHeader(http.StatusOK)

		select {
		case <-ctx.Done():
			return
		case results <- res:
		}
	})
}

// newObolAPIHandler returns http handler for a test obol-api server.
func newObolAPIHandler(ctx context.Context, t *testing.T, result chan<- struct{}) http.Handler {
	t.Helper()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		defer r.Body.Close()

		var req cluster.Lock
		require.NoError(t, json.Unmarshal(data, &req))

		w.WriteHeader(http.StatusOK)

		select {
		case <-ctx.Done():
			return
		case result <- struct{}{}:
		}
	})
}

func isAnyVersion(version string, versions ...string) bool {
	for _, v := range versions {
		if version == v {
			return true
		}
	}

	return false
}
