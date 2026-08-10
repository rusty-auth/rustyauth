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
