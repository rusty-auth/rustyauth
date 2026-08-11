package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

const (
	sableDBUID = 10002
	sableDBGID = 10002
	dataRoot   = "/var/lib/sabledb"
	binaryPath = "/usr/local/bin/sabledb"
	cacheEnv   = "SABLEDB_BLOCK_CACHE_SIZE"
	scanEnv    = "SABLEDB_SCAN_KEYS_SECS"
)

var byteSizePattern = regexp.MustCompile(`^[1-9][0-9]*(?:KB|MB|GB)$`)

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

// materializeRuntimeConfig applies the deployment-specific SableDB values that
// vary with realm size. The overrides are kept deliberately narrow and
// validated before they reach the INI document; this
// avoids treating an environment variable as an arbitrary configuration-file
// injection surface.
func materializeRuntimeConfig(basePath, targetPath, blockCacheSize, scanKeysSeconds string, uid, gid int) error {
	if blockCacheSize != "" && !byteSizePattern.MatchString(blockCacheSize) {
		return fmt.Errorf("%s must be a positive integer followed by KB, MB, or GB", cacheEnv)
	}
	if scanKeysSeconds != "" {
		seconds, err := strconv.ParseUint(scanKeysSeconds, 10, 32)
		if err != nil || seconds < 60 || seconds > 86_400 {
			return fmt.Errorf("%s must be an integer from 60 through 86400", scanEnv)
		}
	}
	contents, err := os.ReadFile(basePath)
	if err != nil {
		return fmt.Errorf("read SableDB base config %s: %w", basePath, err)
	}

	lines := strings.Split(string(contents), "\n")
	cacheReplacements := 0
	scanReplacements := 0
	for index, line := range lines {
		trimmed := strings.TrimSpace(line)
		if blockCacheSize != "" && strings.HasPrefix(trimmed, "block_cache_size =") {
			lines[index] = "block_cache_size = " + blockCacheSize
			cacheReplacements++
		}
		if scanKeysSeconds != "" && strings.HasPrefix(trimmed, "scan_keys_secs =") {
			lines[index] = "scan_keys_secs = " + scanKeysSeconds
			scanReplacements++
		}
	}
	if blockCacheSize != "" && cacheReplacements != 1 {
		return fmt.Errorf("SableDB base config must contain exactly one block_cache_size assignment; found %d", cacheReplacements)
	}
	if scanKeysSeconds != "" && scanReplacements != 1 {
		return fmt.Errorf("SableDB base config must contain exactly one scan_keys_secs assignment; found %d", scanReplacements)
	}

	directory := filepath.Dir(targetPath)
	if err := inspectDirectory(directory); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".runtime-server.ini-")
	if err != nil {
		return fmt.Errorf("create SableDB runtime config: %w", err)
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if _, err := temporary.WriteString(strings.Join(lines, "\n")); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write SableDB runtime config: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync SableDB runtime config: %w", err)
	}
	if err := temporary.Chmod(0o640); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set SableDB runtime config permissions: %w", err)
	}
	if os.Geteuid() == 0 {
		if err := temporary.Chown(uid, gid); err != nil {
			_ = temporary.Close()
			return fmt.Errorf("own SableDB runtime config as %d:%d: %w", uid, gid, err)
		}
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close SableDB runtime config: %w", err)
	}
	if err := os.Rename(temporaryPath, targetPath); err != nil {
		return fmt.Errorf("publish SableDB runtime config: %w", err)
	}
	removeTemporary = false
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
	runtimeConfig := ""
	blockCacheSize := os.Getenv(cacheEnv)
	scanKeysSeconds := os.Getenv(scanEnv)
	switch os.Geteuid() {
	case 0:
		if err := prepareDataRoot(dataRoot, sableDBUID, sableDBGID); err != nil {
			return err
		}
		if blockCacheSize != "" || scanKeysSeconds != "" {
			if len(os.Args) != 2 {
				return fmt.Errorf("SableDB runtime tuning requires exactly one config argument")
			}
			runtimeConfig = filepath.Join(dataRoot, "conf", "runtime-server.ini")
			if err := materializeRuntimeConfig(os.Args[1], runtimeConfig, blockCacheSize, scanKeysSeconds, sableDBUID, sableDBGID); err != nil {
				return err
			}
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
		if blockCacheSize != "" || scanKeysSeconds != "" {
			if len(os.Args) != 2 {
				return fmt.Errorf("SableDB runtime tuning requires exactly one config argument")
			}
			runtimeConfig = filepath.Join(dataRoot, "conf", "runtime-server.ini")
			if err := materializeRuntimeConfig(os.Args[1], runtimeConfig, blockCacheSize, scanKeysSeconds, sableDBUID, sableDBGID); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("SableDB must start as root or uid %d; got uid %d", sableDBUID, os.Geteuid())
	}
	configArgs := os.Args[1:]
	if runtimeConfig != "" {
		configArgs = []string{runtimeConfig}
	}
	args := append([]string{"sabledb"}, configArgs...)
	return syscall.Exec(binaryPath, args, os.Environ())
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "sabledb-entrypoint: %v\n", err)
		os.Exit(1)
	}
}
