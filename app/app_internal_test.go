// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path"
	"testing"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/eth2wrap/mocks"
	"github.com/obolnetwork/charon/app/lifecycle"
	vapimocks "github.com/obolnetwork/charon/core/validatorapi/mocks"
	"github.com/obolnetwork/charon/testutil"
)

func TestWireVAPIRouterForTLS(t *testing.T) {
	const testVersion = "v1.0.0"

	life := new(lifecycle.Manager)
	client := mocks.NewClient(t)
	handler := vapimocks.NewHandler(t)
	handler.On("NodeVersion", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		t.Log("NodeVersion called")
	}).Return(&eth2api.Response[string]{
		Data: testVersion,
	}, nil)

	vapiCalls := func() {}
	certPath, keyPath := generateTestTLSCertAndKey(t)
	conf := &Config{
		VCTLSCertFile: certPath,
		VCTLSKeyFile:  keyPath,
	}

	port := testutil.GetFreePort(t)
	endpoint := fmt.Sprintf("localhost:%v", port)
	err := wireVAPIRouter(t.Context(), life, endpoint, client, handler, vapiCalls, conf)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	doneCh := make(chan error)

	go func() {
		doneCh <- life.Run(ctx)
	}()

	vapiClient := createTLSClient(t, certPath, keyPath)
	require.Eventually(t, func() bool {
		resp, err := vapiClient.Get(fmt.Sprintf("https://%s/eth/v1/node/version", endpoint))
		if err != nil {
			return false
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return false
		}

		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return false
		}

		return bytes.Contains(b, []byte(testVersion))
	}, 5*time.Second, 100*time.Millisecond)

	cancel()

	err = <-doneCh
	require.NoError(t, err)
}

func createTLSClient(t *testing.T, certPath, keyPath string) *http.Client {
	t.Helper()

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	require.NoError(t, err)

	tlsClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates:       []tls.Certificate{cert},
				InsecureSkipVerify: true,
			},
		},
	}

	return tlsClient
}

func generateTestTLSCertAndKey(t *testing.T) (certPath, keyPath string) {
	t.Helper()

	tempDir := t.TempDir()
	certPath = path.Join(tempDir, "test_cert.pem")
	keyPath = path.Join(tempDir, "test_key.pem")

	t.Cleanup(func() {
		os.Remove(certPath)
		os.Remove(keyPath)
	})

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"ACME"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Generate a self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	certFile, err := os.Create(certPath)
	require.NoError(t, err)

	defer certFile.Close()

	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	require.NoError(t, err)

	keyFile, err := os.Create(keyPath)
	require.NoError(t, err)

	defer keyFile.Close()

	privBytes, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)

	err = pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
	require.NoError(t, err)

	return certPath, keyPath
}
