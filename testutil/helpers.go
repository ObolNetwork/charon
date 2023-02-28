// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package testutil

// BuilderFalse is a core.BuilderEnabled function that always returns false.
var BuilderFalse = func(slot int64) bool { return false }

// BuilderTrue is a core.BuilderEnabled function that always returns true.
var BuilderTrue = func(slot int64) bool { return true }
