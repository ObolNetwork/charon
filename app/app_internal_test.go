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
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/eth2wrap/mocks"
	"github.com/obolnetwork/charon/app/lifecycle"
	"github.com/obolnetwork/charon/core"
	vapimocks "github.com/obolnetwork/charon/core/validatorapi/mocks"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
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

func TestCalculateTrackerDelay(t *testing.T) {
	tests := []struct {
		name         string
		slotDuration time.Duration
		slotDelay    int64
	}{
		{
			name:         "slow slots",
			slotDuration: time.Second,
			slotDelay:    11,
		},
		{
			name:         "fast slots",
			slotDuration: time.Second * 12,
			slotDelay:    2,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const currentSlot = 100

			ctx := context.Background()
			now := time.Now()
			genesis := now.Add(-test.slotDuration * currentSlot)

			bmock, err := beaconmock.New(
				t.Context(),
				beaconmock.WithSlotDuration(test.slotDuration),
				beaconmock.WithGenesisTime(genesis),
			)
			require.NoError(t, err)

			fromSlot, err := calculateTrackerDelay(ctx, bmock, now)
			require.NoError(t, err)
			require.EqualValues(t, currentSlot+test.slotDelay, fromSlot)
		})
	}
}

func TestSetFeeRecipient(t *testing.T) {
	set := beaconmock.ValidatorSetA
	for i := range len(set) {
		clone, err := set.Clone()
		require.NoError(t, err)

		// Make i+1 validators inactive
		inactive := i + 1

		for index, validator := range clone {
			validator.Status = eth2v1.ValidatorStatePendingQueued
			clone[index] = validator

			inactive--
			if inactive == 0 {
				break
			}
		}

		bmock, err := beaconmock.New(t.Context(), beaconmock.WithValidatorSet(clone))
		require.NoError(t, err)

		// Only expect preparations for active validators.
		var active int

		bmock.SubmitProposalPreparationsFunc = func(ctx context.Context, preparations []*eth2v1.ProposalPreparation) error {
			if len(preparations) == 0 {
				return errors.New("empty slice")
			}

			active = len(preparations)

			return nil
		}

		fn := setFeeRecipient(bmock, func(core.PubKey) string {
			return "0xdead"
		})
		err = fn(context.Background(), core.Slot{SlotsPerEpoch: 1})
		require.NoError(t, err)

		require.Equal(t, active, len(clone)-(i+1))
	}
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
