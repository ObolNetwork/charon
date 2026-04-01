// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package eth1wrap

import (
	"context"
	"regexp"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/app/z"
)

var (
	minGethVersion       = mustParse("v1.16.7")
	minNethermindVersion = mustParse("v1.35.0")
	minBesuVersion       = mustParse("v25.11.0")
	minErigonVersion     = mustParse("v3.2.2")
	minRethVersion       = mustParse("v1.9.1")

	minimumExecutionEngineVersion = map[string]version.SemVer{
		"Geth":       minGethVersion,
		"Nethermind": minNethermindVersion,
		"besu":       minBesuVersion,
		"erigon":     minErigonVersion,
		"reth":       minRethVersion,
	}

	incompatibleExecutionEngineVersion = map[string][]version.SemVer{}
)

func mustParse(v string) version.SemVer {
	sv, err := version.Parse(v)
	if err != nil {
		panic(err)
	}

	return sv
}

type ExecutionEngineVersionStatus int

const (
	ELVersionOK ExecutionEngineVersionStatus = iota
	ELVersionFormatError
	ELVersionUnknownClient
	ELVersionTooOld
	ELVersionIncompatible
)

var elVersionExtractRegex = regexp.MustCompile(`^([^/]+)/v?([0-9]+\.[0-9]+\.[0-9]+)`)

// checkExecutionEngineVersionStatus checks the version of the execution engine client against the minimum required version.
func checkExecutionEngineVersionStatus(elVersion string) (status ExecutionEngineVersionStatus, clVer string, minVer string) {
	matches := elVersionExtractRegex.FindStringSubmatch(elVersion)
	if len(matches) != 3 {
		return ELVersionFormatError, "", ""
	}

	client := matches[1]

	clientVersion, err := version.Parse("v" + matches[2])
	if err != nil {
		return ELVersionFormatError, "", ""
	}

	minVersion, ok := minimumExecutionEngineVersion[client]
	if !ok {
		return ELVersionUnknownClient, "", ""
	}

	if version.Compare(clientVersion, minVersion) == -1 {
		return ELVersionTooOld, clientVersion.String(), minVersion.String()
	}

	for _, badVer := range incompatibleExecutionEngineVersion[client] {
		if version.Compare(clientVersion, badVer) == 0 {
			return ELVersionIncompatible, clientVersion.String(), ""
		}
	}

	return ELVersionOK, clientVersion.String(), minVersion.String()
}

// CheckExecutionEngineVersion checks the version of the execution engine client and logs a warning
// if the version is below the minimum, incompatible, or the client is not recognized.
func CheckExecutionEngineVersion(ctx context.Context, elVersion string) {
	status, currentVersion, minVersion := checkExecutionEngineVersionStatus(elVersion)

	//nolint:revive // enforce-switch-style: the list is exhaustive and there is no need for default
	switch status {
	case ELVersionFormatError:
		log.Warn(ctx, "Failed to parse execution engine version string due to unexpected format. This may indicate an unsupported or custom execution engine build",
			nil, z.Str("input", elVersion))
	case ELVersionUnknownClient:
		log.Warn(ctx, "Unknown execution engine client detected. The client is not in the supported client list and may cause compatibility issues",
			nil, z.Str("client", elVersion))
	case ELVersionTooOld:
		log.Warn(ctx, "Execution engine client version is below the minimum supported version. Please upgrade your execution engine to ensure compatibility and security",
			nil, z.Str("client_version", currentVersion), z.Str("minimum_required", minVersion))
	case ELVersionIncompatible:
		log.Warn(ctx, "Execution engine client version is known to be incompatible with Charon. Please upgrade or downgrade your execution engine to a compatible version",
			nil, z.Str("client_version", currentVersion))
	case ELVersionOK:
		// Do nothing
	}
}
