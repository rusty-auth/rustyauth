package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

const (
	sableDBUID = 10002
	sableDBGID = 10002
	dataRoot   = "/var/lib/sabledb"
	binaryPath = "/usr/local/bin/sabledb"
)

func prepareDirectory(path string, uid, gid int) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o750); err != nil {
			return fmt.Errorf("create %s: %w", path, err)
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return fmt.Errorf("inspect %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("refusing unsafe SableDB path %s: expected a directory", path)
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("own %s as %d:%d: %w", path, uid, gid, err)
	}
	if err := os.Chmod(path, 0o750); err != nil {
		return fmt.Errorf("set permissions on %s: %w", path, err)
	}
	return nil
}

func inspectDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("refusing unsafe SableDB path %s: expected a directory", path)
	}
	return nil
}

func verifyWritableDirectory(path string) error {
	probe, err := os.CreateTemp(path, ".rustyauth-write-probe-")
	if err != nil {
		return fmt.Errorf("verify write access to %s: %w", path, err)
	}
	probePath := probe.Name()
	if err := probe.Close(); err != nil {
		return fmt.Errorf("close write probe in %s: %w", path, err)
	}
	if err := os.Remove(probePath); err != nil {
		return fmt.Errorf("remove write probe in %s: %w", path, err)
	}
	return nil
}

func prepareDataRoot(root string, uid, gid int) error {
	if !filepath.IsAbs(root) {
		return fmt.Errorf("SableDB data root must be absolute: %s", root)
	}
	for _, path := range []string{root, filepath.Join(root, "data"), filepath.Join(root, "conf")} {
		if err := prepareDirectory(path, uid, gid); err != nil {
			return err
		}
	}
	return nil
}

// Kubernetes applies fsGroup before the process starts and intentionally runs
// this image as 10002 from the first instruction. In that mode no privileged
// bootstrap is necessary or permitted; validate the mount and prove that the
// two database directories are writable without following symlinks.
func prepareUnprivilegedDataRoot(root string) error {
	if !filepath.IsAbs(root) {
		return fmt.Errorf("SableDB data root must be absolute: %s", root)
	}
	if err := inspectDirectory(root); err != nil {
		return err
	}
	for _, path := range []string{filepath.Join(root, "data"), filepath.Join(root, "conf")} {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(path, 0o750); err != nil {
				return fmt.Errorf("create %s: %w", path, err)
			}
		} else if err != nil {
			return fmt.Errorf("inspect %s: %w", path, err)
		}
		if err := inspectDirectory(path); err != nil {
			return err
		}
		if err := verifyWritableDirectory(path); err != nil {
			return err
		}
	}
	return nil
}

func dropPrivileges(uid, gid int) error {
	if err := syscall.Setgroups([]int{}); err != nil {
		return fmt.Errorf("clear supplementary groups: %w", err)
	}
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("set gid %d: %w", gid, err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("set uid %d: %w", uid, err)
	}
	if os.Geteuid() != uid || os.Getegid() != gid {
		return fmt.Errorf("privilege drop did not take effect: got %d:%d", os.Geteuid(), os.Getegid())
	}
	return nil
}

func run() error {
	switch os.Geteuid() {
	case 0:
		if err := prepareDataRoot(dataRoot, sableDBUID, sableDBGID); err != nil {
			return err
		}
		if err := dropPrivileges(sableDBUID, sableDBGID); err != nil {
			return err
		}
	case sableDBUID:
		if os.Getegid() != sableDBGID {
			return fmt.Errorf("SableDB uid %d requires gid %d; got gid %d", sableDBUID, sableDBGID, os.Getegid())
		}
		if err := prepareUnprivilegedDataRoot(dataRoot); err != nil {
			return err
		}
	default:
		return fmt.Errorf("SableDB must start as root or uid %d; got uid %d", sableDBUID, os.Geteuid())
	}
	args := append([]string{"sabledb"}, os.Args[1:]...)
	return syscall.Exec(binaryPath, args, os.Environ())
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "sabledb-entrypoint: %v\n", err)
		os.Exit(1)
	}
}
