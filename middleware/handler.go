// Copyright © 2021 Obol Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package middleware

import (
	"context"

	eth2client "github.com/attestantio/go-eth2-client"
	gwruntime "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	eth2v1 "github.com/prysmaticlabs/ethereumapis/eth/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Handler handles intercepted validator client requests.
type Handler struct {
	ValidatorAPI ValidatorProvider

	eth2v1.UnimplementedBeaconValidatorServer
}

// ValidatorProvider is the set of Eth2 validator APIs of interest to the middleware.
type ValidatorProvider interface {
	eth2client.AttesterDutiesProvider
	eth2client.ProposerDutiesProvider
}

// APIPaths returns the REST API paths overridden by the middleware handler.
func (*Handler) APIPaths() []string {
	return []string{
		"/eth/v1/validator/duties/", // validator duties (proposing, attesting, sync committee)
		"/eth/v1/validator/blocks/", // block production
		// TODO more endpoints
	}
}

// GetAttesterDuties returns the attestations to be made by a validator client.
//
// The attestations are to signed by the DV key share.
func (h *Handler) GetAttesterDuties(_ context.Context, _ *eth2v1.AttesterDutiesRequest) (*eth2v1.AttesterDutiesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetAttesterDuties not implemented")
}

// NewRESTHandler returns a REST handler for the gRPC DVC middleware handler.
func NewRESTHandler(ctx context.Context, handler *Handler) (gmux *gwruntime.ServeMux, err error) {
	gmux = gwruntime.NewServeMux()
	err = eth2v1.RegisterBeaconValidatorHandlerServer(ctx, gmux, handler)
	return
}
