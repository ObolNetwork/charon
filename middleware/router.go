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
	"net/http"
)

// Router splits an incoming request stream between two backends.
type Router struct {
	Base     http.Handler
	Override http.Handler
	Mux      *http.ServeMux
}

// NewRouter creates a new request router given a base handler and an override handler,
// which responds to the given list of paths.
func NewRouter(base http.Handler, override http.Handler, overridePaths []string) *Router {
	mux := http.NewServeMux()
	mux.Handle("/", base)
	for _, p := range overridePaths {
		mux.Handle(p, override)
	}
	return &Router{
		Base:     base,
		Override: override,
		Mux:      mux,
	}
}
