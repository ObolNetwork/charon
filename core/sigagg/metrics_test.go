// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package sigagg_test

import (
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/obolnetwork/charon/core/sigagg"
)

var updateMarkdown = flag.Bool("update-markdown", false, "Update markdown documentation")

func TestMetricReference(t *testing.T) {
	metrics := sigagg.Metrics()

	docPath := filepath.Join(findRepoRoot(t), "docs", "metrics.md")
	content, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("Failed to read docs/metrics.md: %v", err)
	}

	updatedContent := string(content)

	// Update or add entries for each metric
	for _, m := range metrics {
		entry := "| `" + m.Name + "` | " + m.Type + " | " + m.Help + " | `" + m.Labels + "` |"

		// Look for existing entry
		patternStr := "\\| \\`" + regexp.QuoteMeta(m.Name) + "\\` \\|.*\\|"
		pattern := regexp.MustCompile(patternStr)
		if pattern.MatchString(updatedContent) {
			updatedContent = pattern.ReplaceAllString(updatedContent, entry)
		} else {
			// Add new entry in the right alphabetical position
			updatedContent = insertMetricEntry(updatedContent, entry, m.Name)
		}
	}

	if *updateMarkdown {
		if err := os.WriteFile(docPath, []byte(updatedContent), 0o644); err != nil {
			t.Fatalf("Failed to write docs/metrics.md: %v", err)
		}
	} else {
		// Verify all metrics are documented
		for _, m := range metrics {
			if !strings.Contains(updatedContent, "`"+m.Name+"`") {
				t.Errorf("Metric %s not found in docs/metrics.md", m.Name)
			}
		}
	}
}

func insertMetricEntry(content, entry, metricName string) string {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		// Find the right place to insert (alphabetically before next metric)
		if strings.Contains(line, "| `core_") && strings.Contains(line, "| ") {
			// Extract metric name from line
			parts := strings.Split(line, "`")
			if len(parts) >= 2 {
				existingMetric := parts[1]
				if metricName < existingMetric {
					lines = append(lines[:i], append([]string{entry}, lines[i:]...)...)
					return strings.Join(lines, "\n")
				}
			}
		}
	}
	// If not found, append before next major section
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "| `p2p_") {
			lines = append(lines[:i], append([]string{entry}, lines[i:]...)...)
			return strings.Join(lines, "\n")
		}
	}
	return content
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	// Walk up from current directory to find go.mod
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("Could not find go.mod")
		}
		dir = parent
	}
}
