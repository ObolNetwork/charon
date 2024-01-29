// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package core

// BuilderEnabled determines whether the builderAPI is enabled for the provided slot.
type BuilderEnabled func(slot uint64) bool
