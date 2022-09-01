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

package dkg

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/obolnetwork/charon/cluster"
)

func TestFetchDefinition(t *testing.T) {
	lock, _, _ := cluster.NewForT(t, 1, 2, 3, 0)
	validDef := lock.Definition
	invalidDef := cluster.Definition{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch strings.TrimSpace(r.URL.Path) {
		case "/validDef":
			b, _ := validDef.MarshalJSON()
			_, _ = w.Write(b)
		case "/invalidDef":
			b, _ := invalidDef.MarshalJSON()
			_, _ = w.Write(b)
		}
	}))
	defer server.Close()

	type args struct {
		url string
	}
	tests := []struct {
		name    string
		args    args
		want    cluster.Definition
		wantErr bool
	}{
		{
			name:    "Fetch valid definition",
			args:    args{url: fmt.Sprintf("%s/%s", server.URL, "validDef")},
			want:    validDef,
			wantErr: false,
		},
		{
			name:    "Fetch invalid definition",
			args:    args{url: fmt.Sprintf("%s/%s", server.URL, "invalidDef")},
			want:    invalidDef,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fetchDefinition(tt.args.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("fetchDefinition() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("fetchDefinition() got = %v, want %v", got, tt.want)
			}
		})
	}
}
