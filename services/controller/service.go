/*
Copyright © 2021 Oisín Kyne <oisin@obol.tech>

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
	"github.com/obolnetwork/charon/runtime"
)

// Service is the core runtime for Charon, and may later make use of a formally verified SSV state machine.
// It instantiates all services and handles the lifecycle of the Charon client
type Service struct {
	ctx                         context.Context
	cancel                      context.CancelFunc
	services                    *runtime.ServiceRegistry
	lock                        sync.RWMutex
	stop                        chan struct{} // Channel to wait for termination notifications.
	bftType                     string
	proposerDutiesProvider      eth2client.ProposerDutiesProvider
	attesterDutiesProvider      eth2client.AttesterDutiesProvider
	syncCommitteeDutiesProvider eth2client.SyncCommitteeDutiesProvider
}

// New creates a new controller service. (Does nothing yet, just getting the hang of context passing)
func New(cliCtx context.Context) (*Service, error) {
	ctx, cancel := context.WithCancel(cliCtx)
	// Instantiate service registry for the controller
	registry := runtime.NewServiceRegistry()

	s := &Service{
		ctx:      ctx,
		cancel:   cancel,
		stop:     make(chan struct{}),
		services: registry,
		bftType:  "qbft",
	}

	return s, nil
}

// Start the Controller and kick off every registered service.
func (s *Service) Start() {
	s.lock.Lock()

	log.Info().Msg("Starting Charon Controller")

	s.services.StartAll()

	stop := s.stop
	s.lock.Unlock()

	go func() {
		sigc := make(chan os.Signal, 1)
		signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(sigc)
		<-sigc
		log.Info().Msg("Got interrupt, shutting down...")
		go s.Close()
		for i := 10; i > 0; i-- {
			<-sigc
			if i > 1 {
				log.Info().Msgf("Already shutting down, interrupt %f more times to panic", i)
			}
		}
		panic("Panic closing the Charon client")
	}()

	// Wait for stop channel to be closed.
	<-stop
}

// Close handles graceful shutdown of the system.
func (s *Service) Close() {
	s.lock.Lock()
	defer s.lock.Unlock()

	log.Info().Msg("Stopping Charon Controller")
	s.services.StopAll()

	// Metrics
	// s.collector.unregister()
	s.cancel()
	close(s.stop)
}
