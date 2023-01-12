// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"context"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
)

// WithTracking wraps component input functions to support tracking of core components.
func WithTracking(tracker Tracker) WireOption {
	return func(w *wireFuncs) {
		clone := *w

		w.FetcherFetch = func(ctx context.Context, duty Duty, set DutyDefinitionSet) error {
			fetchErr := clone.FetcherFetch(ctx, duty, set)
			defer func() {
				for pubkey := range set {
					err := tracker.SendEvent(ctx, duty, "fetcher", pubkey, fetchErr, ParSignedData{})
					if err != nil {
						log.Error(ctx, "Send event to tracker", err, z.Str("duty", duty.String()))
					}
				}
			}()

			return fetchErr
		}
	}
}
