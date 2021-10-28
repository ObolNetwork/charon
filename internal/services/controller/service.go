/*
Copyright © 2021 Obol Technologies Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package controller

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"

	eth2client "github.com/attestantio/go-eth2-client"

	"github.com/obolnetwork/charon/internal/services/monitoring"
	nullmetrics "github.com/obolnetwork/charon/internal/services/monitoring/null"
	prometheusmetrics "github.com/obolnetwork/charon/internal/services/monitoring/prometheus"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

// Service is the core runtime for Charon, and may later make use of a formally verified SSV state machine.
// It instantiates all services and handles the lifecycle of the Charon client
type Service struct {
	lock                        sync.RWMutex
	stop                        chan struct{} // Channel to wait for termination notifications.
	bftType                     string
	proposerDutiesProvider      eth2client.ProposerDutiesProvider
	attesterDutiesProvider      eth2client.AttesterDutiesProvider
	syncCommitteeDutiesProvider eth2client.SyncCommitteeDutiesProvider
}

// New creates a new controller service. (Does nothing yet, just getting the hang of context passing)
func New(ctx context.Context) (*Service, error) {
	log.Debug().Msg("Controller Service instantiated")
	s := &Service{
		stop:    make(chan struct{}),
		bftType: "qbft",
	}

	return s, nil
}

// Starts the Controller Service and instantiates all downstream services.
// Waits for either the controller to come to a stop, or a system interrupt is fired, which triggers a Close() function on the controller service to clean up all resources.
func (s *Service) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	s.lock.Lock()

	log.Info().Msg("Starting Charon Controller")

	log.Debug().Msg("Starting Monitoring Service")

	monitor, err := startMonitor(ctx)
	if err != nil {
		log.Warn().Msg("Failed to start monitoring service")
		log.Debug().Msgf("%s", err)
	}

	log.Debug().Msgf("%o", monitor)

	stop := s.stop
	s.lock.Unlock()

	go func() {
		sigc := make(chan os.Signal, 1)
		signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(sigc)
		<-sigc
		log.Info().Msg("Got interrupt, shutting down...")
		cancel()
		go s.Close()
		for i := 10; i > 0; i-- {
			<-sigc
			if i > 1 {
				log.Info().Msgf("Already shutting down, interrupt %d more times to panic", i)
			}
		}
		panic("Panic closing the Charon client")
	}()

	// Wait for stop channel to be closed.
	<-stop
	log.Debug().Msg("Stop signal received, controller.Start() function exit")
}

// Close handles graceful shutdown of the system.
func (s *Service) Close() {
	s.lock.Lock()
	defer s.lock.Unlock()
	log.Info().Msg("Stopping Charon Controller")
	close(s.stop)
	// Metrics
	// s.collector.unregister()
}

// Triggers the instantiation of either a prometheus monitoring service or a null monitoring service
// suitable for injection into other processes for metric reporting
func startMonitor(ctx context.Context) (monitoring.Service, error) {
	log.Trace().Msg("Starting monitoring service")
	var monitor monitoring.Service
	address := viper.GetString("monitoring-address")
	enable := viper.GetBool("monitoring")
	if enable {
		var err error
		monitor, err = prometheusmetrics.New(ctx,
			prometheusmetrics.WithLogLevel(log.GetLevel()),
			prometheusmetrics.WithAddress(address),
		)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to start prometheus monitoring service")
		}
		log.Info().Str("listen_address", address).Msg("Started prometheus monitoring service")
	} else {
		log.Debug().Msg("No monitoring service supplied; monitor not starting")
		monitor = nullmetrics.New(ctx)
	}
	return monitor, nil
}
