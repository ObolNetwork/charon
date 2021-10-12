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
package services

import (
	"context"
	"time"

	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service is the core runtime for Charon, and may later make use of a formally verified SSV state machine.
type Service struct {
	bftType string
}

// module-wide log.
var log zerolog.Logger

// New creates a new controller.
func New(ctx context.Context) (*Service, error) {

	// Set logging.
	log = zerologger.With().Str("service", "controller").Str("impl", "standard").Logger()

	s := &Service{
		bftType: "qbft",
	}
	log.Info().Msg("Server Struct Instantiation complete")
	go func() {
		log = zerologger.With().Str("service", "subroutine").Str("impl", "standard").Logger()
		log.Info().Msg("First server subroutine instantiated")
		time.Sleep(10 * time.Second)
		log.Info().Msg("First server subroutine ended normally")
	}()
	log.Info().Msg("Server Subroutine Instantiated")
	return s, nil
}
