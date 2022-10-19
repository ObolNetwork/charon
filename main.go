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

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/obolnetwork/charon/cmd"
)

func main() {
	killCtx, killCancel := signal.NotifyContext(context.Background(), syscall.SIGKILL)
	defer killCancel()
	go func() {
		<-killCtx.Done()
		_, _ = fmt.Fprintln(os.Stderr, "Kill signal received")
		os.Exit(1)
	}()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	cobra.CheckErr(cmd.New().ExecuteContext(ctx))
}
