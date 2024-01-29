// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/errors"
)

func newViewClusterManifestCmd(runFunc func(io.Writer, string) error) *cobra.Command {
	var manifestFilePath string

	cmd := &cobra.Command{
		Use:   "view-cluster-manifest",
		Short: "Shows cluster manifest contents",
		Long:  `Opens and shows the specified cluster manifest by printing its content in JSON form.`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFunc(cmd.OutOrStdout(), manifestFilePath)
		},
	}

	cmd.Flags().StringVar(&manifestFilePath, "manifest-file", "cluster-manifest.pb", "The path to the cluster manifest file.")

	return cmd
}

func runViewClusterManifest(out io.Writer, manifestFilePath string) error {
	cluster, err := loadClusterManifest(manifestFilePath, "")
	if err != nil {
		return err
	}

	clusterJSON, err := protoToJSON(cluster)
	if err != nil {
		return err
	}

	if _, err := fmt.Fprintln(out, string(clusterJSON)); err != nil {
		return errors.Wrap(err, "cluster json output write")
	}

	return nil
}

// protoToJSON returns the JSON representation of msg, with key fields transformed in snake case and all byte slices
// expressed as 0x-prefixed hex encoded strings.
func protoToJSON(msg proto.Message) ([]byte, error) {
	rawJSON, err := protojson.Marshal(msg)
	if err != nil {
		return nil, errors.Wrap(err, "protojson marshal")
	}

	jmap := make(map[string]any)
	if err := json.Unmarshal(rawJSON, &jmap); err != nil {
		return nil, errors.Wrap(err, "json unmarshal protojson output")
	}

	jmap = formatMap(jmap)

	final, err := json.MarshalIndent(jmap, "", " ")
	if err != nil {
		return nil, errors.Wrap(err, "json marshal")
	}

	return final, nil
}

// formatMap explores input and tries to convert any string it encounters in either a 0x-prefixed hex string, or if
// applicable, JSON object.
func formatMap(input map[string]any) map[string]any {
	ret := make(map[string]any)

	for key, value := range input {
		switch concrete := value.(type) {
		case []any:
			ret[formatKey(key)] = formatArray(concrete)
		case map[string]any:
			ret[formatKey(key)] = formatMap(concrete)
		case string:
			ret[formatKey(key)] = rawString(concrete)
		}
	}

	return ret
}

// formatKey formats key from camel case to snake case.
func formatKey(key string) string {
	// remove "Json" suffix if any
	key = strings.ReplaceAll(key, "Json", "")

	var ret strings.Builder

	for _, c := range key {
		if unicode.IsUpper(c) {
			_, _ = ret.WriteRune('_')
		}

		_, _ = ret.WriteRune(unicode.ToLower(c))
	}

	return ret.String()
}

// rawString checks if data is the base64 string representation of a byte slice, and if so returns it as either a
// JSON object map or 0x-prefixed hex encoded string.
func rawString(data string) any {
	bytes, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return data // data might not be a base64 string, ignore
	}

	// if we're able to unmarshal in a map do it, otherwise hex encode and return
	brJSON := make(map[string]any)
	if err := json.Unmarshal(bytes, &brJSON); err != nil {
		return fmt.Sprintf("%#x", bytes)
	}

	return brJSON
}

// formatArray recursively explores arr to convert base64 strings 0x-prefixed hex encoded formats, or full JSON map objects.
func formatArray(arr []any) []any {
	ret := make([]any, len(arr))
	for idx, rawObj := range arr {
		switch concrete := rawObj.(type) {
		case []any:
			ret[idx] = formatArray(concrete)
		case map[string]any:
			ret[idx] = formatMap(concrete)
		case string:
			ret[idx] = rawString(concrete)
		}
	}

	return ret
}
