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
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
)

// Service is the core runtime for Charon, and may later make use of a formally verified SSV state machine.
// It contains pointers to beacon client, p2p client and BLS services, and contains a map of Validator services for each SSV validator Charon is operating in
type Service struct {
	bftType                     string
	proposerDutiesProvider      eth2client.ProposerDutiesProvider
	attesterDutiesProvider      eth2client.AttesterDutiesProvider
	syncCommitteeDutiesProvider eth2client.SyncCommitteeDutiesProvider
}

// New creates a new controller.
func New(ctx context.Context) (*Service, error) {

	s := &Service{
		bftType: "qbft",
	}
	log.Info().Msg("Server Struct Instantiation complete")
	go func(ctx context.Context, err interface{}) {
		log.Info().Msg("First server subroutine instantiated")
		time.Sleep(6 * time.Second)
		if ctx.Err() != nil {
			log.Err(ctx.Err()).Msg("Context Deadline Exceeded")
		}

		time.Sleep(10 * time.Second)
		if ctx.Err() != nil {
			log.Err(ctx.Err()).Msg("Context Deadline Exceeded")
		}
		log.Info().Msg("First server subroutine ended normally")
	}(context.WithTimeout(ctx, 5*time.Second))
	log.Info().Msg("Server Subroutine Instantiated")
	return s, nil
}
