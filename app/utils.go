// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import "encoding/hex"

// Hex7 returns the first 7 (or less) hex chars of the provided bytes.
func Hex7(input []byte) string {
	resp := hex.EncodeToString(input)
	if len(resp) <= 7 {
		return resp
	}

	return resp[:7]
}
