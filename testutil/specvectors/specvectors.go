// Copyright © 2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package specvectors loads the conformance vectors published by the Obol
// distributed validator specification.
//
// The vectors are an artifact of a pinned spec release, vendored into
// testdata/spec/. They are the same files every implementation runs, so a
// failure here means Charon has moved away from its own documented protocol —
// not that a fixture needs regenerating. Most of the expected values were
// produced by Charon in the first place, which makes these regression tests
// against the specification rather than snapshots of it.
//
// Refreshing the artifact is deliberately manual — build a release in a spec
// checkout (`uv run python scripts/build_release.py`), copy it into
// testdata/spec/, and update PinnedSpecVersion in the same change.
//
// This package only finds and version-checks the artifact. Each suite's shape
// belongs to the test that consumes it, so that a test reads as one thing rather
// than as a struct in one file and an assertion in another.
package specvectors

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// PinnedSpecVersion is the spec release vendored into testdata/spec.
//
// Checked against the artifact's own manifest on every load: vendoring a
// different release without updating this constant would silently change what
// Charon is being held to.
const PinnedSpecVersion = "0.1.0"

// DirEnv overrides the vendored artifact location, for running against a spec
// checkout or an unreleased build.
const DirEnv = "SPEC_VECTORS_DIR"

// CoveredSuites maps each suite in the artifact to the test that consumes it.
//
// TestEverySuiteIsCovered fails when the artifact gains a suite absent from this
// map, so a new suite upstream has to be consciously accepted or declined rather
// than silently ignored — an uncovered suite is indistinguishable from a passing
// one otherwise.
var CoveredSuites = map[string]string{
	"bls_threshold":           "testutil/specvectors (tbls)",
	"cluster_hashing":         "testutil/specvectors (cluster)",
	"cluster_validation":      "testutil/specvectors (cluster parse and verify)",
	"secp256k1_signatures":    "testutil/specvectors (k1util)",
	"qbft_hashing":            "core/consensus/qbft (hashProto)",
	"qbft_msg_limits":         "core/consensus/qbft (verifyMsgLimits)",
	"priority_scoring":        "core/priority (calculateResult)",
	"parsigex_sender_binding": "dkg (verifyPeerShareIdx, newExchanger)",
	"timer_deadlines":         "core/consensus/timer (round deadlines)",
	"qbft_decided_resends":    "core/qbft (decided rebroadcast limits)",
}

// Manifest describes a spec release: what it contains and which Charon it was
// validated against.
type Manifest struct {
	SpecVersion  string `json:"spec_version"`
	Tag          string `json:"tag"`
	CharonAnchor struct {
		Commit string `json:"commit"`
		Date   string `json:"date"`
	} `json:"charon_anchor"`
	Compatibility struct {
		Behaviours []Behaviour `json:"behaviours"`
	} `json:"compatibility"`
	TestVectors []Suite `json:"test_vectors"`
}

// Behaviour is a specified behaviour and the first Charon release carrying it.
type Behaviour struct {
	Name string `json:"name"`
	// FirstCharonRelease is nil for behaviour no final Charon release carries —
	// only main or a release candidate has it; Note says which.
	FirstCharonRelease *string `json:"first_charon_release"`
	// FirstCharonReleaseSemver is the comparable form. Charon's tags do not order
	// as strings: "v1.11.0" < "v1.9.0" lexically.
	FirstCharonReleaseSemver []int  `json:"first_charon_release_semver"`
	Spec                     string `json:"spec"`
	Note                     string `json:"note"`
}

// Suite summarises one vector file in the release.
type Suite struct {
	File        string         `json:"file"`
	Suite       string         `json:"suite"`
	Source      string         `json:"source"`
	CharonRef   string         `json:"charon_ref"`
	Cases       int            `json:"cases"`
	Groups      map[string]int `json:"groups"`
	Description string         `json:"description"`
}

// Dir returns the directory holding the vendored spec artifact.
func Dir(tb testing.TB) string {
	tb.Helper()

	if dir := os.Getenv(DirEnv); dir != "" {
		return dir
	}

	return filepath.Join(repoRoot(tb), "testdata", "spec")
}

// repoRoot walks up from the working directory to the module root, so that a
// test in any package finds the same artifact.
func repoRoot(tb testing.TB) string {
	tb.Helper()

	dir, err := os.Getwd()
	if err != nil {
		tb.Fatalf("working directory: %v", err)
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			tb.Fatalf("no go.mod found above the working directory")
			return ""
		}

		dir = parent
	}
}

// LoadManifest reads the artifact's manifest, failing if it is not the pinned
// release.
func LoadManifest(tb testing.TB) Manifest {
	tb.Helper()

	path := filepath.Join(Dir(tb), "manifest.json")

	raw, err := os.ReadFile(path)
	if err != nil {
		tb.Fatalf("read spec manifest (vendor a release into testdata/spec, or set %s): %v", DirEnv, err)
	}

	var manifest Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		tb.Fatalf("parse %s: %v", path, err)
	}

	if manifest.SpecVersion != PinnedSpecVersion {
		tb.Fatalf("vendored spec is %s but PinnedSpecVersion is %s; update the constant deliberately",
			manifest.SpecVersion, PinnedSpecVersion)
	}

	return manifest
}

// Load unmarshals one vector suite into the caller's own case types.
//
// Fails rather than skips when a suite is missing: a conformance test that
// silently does nothing is worse than one that is absent.
func Load(tb testing.TB, suite string, into any) {
	tb.Helper()

	if _, ok := CoveredSuites[suite]; !ok {
		tb.Fatalf("suite %q is not listed in CoveredSuites", suite)
	}

	path := filepath.Join(Dir(tb), "test_vectors", suite+".json")

	raw, err := os.ReadFile(path)
	if err != nil {
		tb.Fatalf("read vector suite %q: %v", suite, err)
	}

	if err := json.Unmarshal(raw, into); err != nil {
		tb.Fatalf("parse vector suite %q: %v", suite, err)
	}
}

// HexToBytes decodes a lower-case unprefixed hex string from a vector.
func HexToBytes(tb testing.TB, s string) []byte {
	tb.Helper()

	decoded, err := hex.DecodeString(s)
	if err != nil {
		tb.Fatalf("decode hex %q: %v", s, err)
	}

	return decoded
}
