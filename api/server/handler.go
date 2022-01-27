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

package server

import (
	"context"

	"github.com/ethereum/go-ethereum/p2p/enode"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/obolnetwork/charon/api"
	"github.com/obolnetwork/charon/internal"
	"github.com/obolnetwork/charon/internal/config"
	"github.com/obolnetwork/charon/p2p"
)

// Handler implements gRPC APIs.
type Handler struct {
	LocalEnode *enode.LocalNode
	Node       *p2p.Node

	api.UnimplementedControlPlaneServer
}

func (h Handler) GetSelf(_ context.Context, _ *api.GetSelfRequest) (*api.GetSelfResponse, error) {
	r := &api.GetSelfResponse{
		Peer: &api.Peer{
			PeerId:  h.LocalEnode.ID().String(),
			Version: internal.ReleaseVersion,
			Enr:     h.LocalEnode.Node().String(),
		},
		StartTime: timestamppb.New(config.StartTime),
		PeerCount: uint32(len(h.Node.Network().Peers())),
	}

	return r, nil
}
