package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareDataRootCreatesOwnedPrivateDirectories(t *testing.T) {
	root := filepath.Join(t.TempDir(), "sabledb")
	if err := os.Mkdir(root, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := prepareDataRoot(root, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{root, filepath.Join(root, "data"), filepath.Join(root, "conf")} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !info.IsDir() {
			t.Fatalf("%s is not a directory", path)
		}
		if got := info.Mode().Perm(); got != 0o750 {
			t.Fatalf("%s mode = %o, want 750", path, got)
		}
	}
}

func TestPrepareDataRootRejectsSymlink(t *testing.T) {
	root := filepath.Join(t.TempDir(), "sabledb")
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "data")); err != nil {
		t.Fatal(err)
	}
	err := prepareDataRoot(root, os.Getuid(), os.Getgid())
	if err == nil || !strings.Contains(err.Error(), "refusing unsafe SableDB path") {
		t.Fatalf("prepareDataRoot() error = %v, want unsafe-path rejection", err)
	}
}

func TestPrepareDataRootRequiresAbsolutePath(t *testing.T) {
	err := prepareDataRoot("relative", os.Getuid(), os.Getgid())
	if err == nil || !strings.Contains(err.Error(), "must be absolute") {
		t.Fatalf("prepareDataRoot() error = %v, want absolute-path rejection", err)
	}
}

func TestPrepareUnprivilegedDataRootCreatesAndProbesDirectories(t *testing.T) {
	root := filepath.Join(t.TempDir(), "sabledb")
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := prepareUnprivilegedDataRoot(root); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"data", "conf"} {
		entries, err := os.ReadDir(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Fatalf("%s contains a leaked write probe: %v", name, entries)
		}
	}
}

func TestPrepareUnprivilegedDataRootRejectsSymlink(t *testing.T) {
	root := filepath.Join(t.TempDir(), "sabledb")
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(root, "conf")); err != nil {
		t.Fatal(err)
	}
	err := prepareUnprivilegedDataRoot(root)
	if err == nil || !strings.Contains(err.Error(), "refusing unsafe SableDB path") {
		t.Fatalf("prepareUnprivilegedDataRoot() error = %v, want unsafe-path rejection", err)
	}
}

func TestMaterializeRuntimeConfigOverridesValidatedBlockCache(t *testing.T) {
	root := t.TempDir()
	basePath := filepath.Join(root, "server.ini")
	targetPath := filepath.Join(root, "runtime-server.ini")
	if err := os.WriteFile(basePath, []byte("[general]\nworkers = 4\n[cron]\nscan_keys_secs = 60\n[rocksdb]\nblock_cache_size = 128MB\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := materializeRuntimeConfig(basePath, targetPath, "512MB", "3600", os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(contents); !strings.Contains(got, "block_cache_size = 512MB") ||
		strings.Contains(got, "block_cache_size = 128MB") ||
		!strings.Contains(got, "scan_keys_secs = 3600") ||
		strings.Contains(got, "scan_keys_secs = 60") {
		t.Fatalf("runtime config = %q, want only the validated override", got)
	}
	if info, err := os.Stat(targetPath); err != nil {
		t.Fatal(err)
	} else if got := info.Mode().Perm(); got != 0o640 {
		t.Fatalf("runtime config mode = %o, want 640", got)
	}
}

func TestMaterializeRuntimeConfigRejectsInjection(t *testing.T) {
	root := t.TempDir()
	basePath := filepath.Join(root, "server.ini")
	targetPath := filepath.Join(root, "runtime-server.ini")
	if err := os.WriteFile(basePath, []byte("[rocksdb]\nblock_cache_size = 128MB\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	err := materializeRuntimeConfig(basePath, targetPath, "512MB\nworkers = 99", "", os.Getuid(), os.Getgid())
	if err == nil || !strings.Contains(err.Error(), cacheEnv) {
		t.Fatalf("materializeRuntimeConfig() error = %v, want validated-size rejection", err)
	}
	if _, err := os.Stat(targetPath); !os.IsNotExist(err) {
		t.Fatalf("unsafe runtime config was created: %v", err)
	}
}

func TestMaterializeRuntimeConfigRequiresExactlyOneAssignment(t *testing.T) {
	root := t.TempDir()
	basePath := filepath.Join(root, "server.ini")
	if err := os.WriteFile(basePath, []byte("[rocksdb]\nwrite_buffer_size = 32MB\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	err := materializeRuntimeConfig(basePath, filepath.Join(root, "runtime-server.ini"), "512MB", "", os.Getuid(), os.Getgid())
	if err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("materializeRuntimeConfig() error = %v, want assignment-count rejection", err)
	}
}

func TestMaterializeRuntimeConfigRejectsUnsafeScanInterval(t *testing.T) {
	root := t.TempDir()
	basePath := filepath.Join(root, "server.ini")
	targetPath := filepath.Join(root, "runtime-server.ini")
	if err := os.WriteFile(basePath, []byte("[cron]\nscan_keys_secs = 60\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"0", "59", "86401", "3600\nworkers = 99", "not-a-number"} {
		err := materializeRuntimeConfig(basePath, targetPath, "", value, os.Getuid(), os.Getgid())
		if err == nil || !strings.Contains(err.Error(), scanEnv) {
			t.Fatalf("materializeRuntimeConfig(scan=%q) error = %v, want validated-interval rejection", value, err)
		}
		if _, err := os.Stat(targetPath); !os.IsNotExist(err) {
			t.Fatalf("unsafe runtime config was created for %q: %v", value, err)
		}
	}
}
