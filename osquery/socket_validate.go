//go:build unix

package osquery

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// validateSocketPath checks that path is a safe absolute Unix socket path.
// It ensures the path is absolute, no path component is a symlink, every
// parent directory is owned by root or the current user and is not group- or
// world-writable, and if the socket already exists it is a real socket.
func validateSocketPath(path string) error {
	return validateSocketPathWithDeps(path, os.Geteuid, os.Lstat)
}

func validateSocketPathWithDeps(path string, geteuid func() int, lstat func(string) (os.FileInfo, error)) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("socket path %q is not an absolute path", path)
	}

	clean := filepath.Clean(path)
	if clean == "/" {
		return fmt.Errorf("socket path cannot be the root directory")
	}

	// Validate all parent directories, starting from the root. We use Lstat so
	// symlinks are not followed; a symlink anywhere in the path could be used
	// to redirect the connection to an attacker-controlled socket.
	current := "/"
	parts := strings.Split(clean, string(filepath.Separator))
	for _, part := range parts[1 : len(parts)-1] {
		current = filepath.Join(current, part)
		fi, err := lstat(current)
		if err != nil {
			return fmt.Errorf("cannot stat socket parent directory %q: %w", current, err)
		}
		if err := checkDirPermission(current, fi, geteuid()); err != nil {
			return err
		}
	}

	// If the socket already exists, make sure it is a real socket and not a
	// symlink. If osqueryd has not created it yet, we only validate the parent
	// directories above.
	if fi, err := lstat(clean); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("socket path %q is a symlink", clean)
		}
		if fi.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("socket path %q exists but is not a Unix socket", clean)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("cannot stat socket path %q: %w", clean, err)
	}

	return nil
}

func checkDirPermission(path string, fi os.FileInfo, euid int) error {
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("socket parent directory %q is a symlink", path)
	}
	if !fi.IsDir() {
		return fmt.Errorf("socket parent path %q is not a directory", path)
	}

	mode := fi.Mode().Perm()
	if mode&0o002 != 0 {
		return fmt.Errorf("socket parent directory %q is world-writable", path)
	}
	if mode&0o020 != 0 {
		return fmt.Errorf("socket parent directory %q is group-writable", path)
	}
	if mode&0o100 == 0 {
		return fmt.Errorf("socket parent directory %q is not executable by owner", path)
	}
	if mode&0o400 == 0 {
		return fmt.Errorf("socket parent directory %q is not readable by owner", path)
	}

	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot determine owner of socket parent directory %q", path)
	}
	if int(stat.Uid) != 0 && int(stat.Uid) != euid {
		return fmt.Errorf("socket parent directory %q is owned by uid %d, want root (0) or current user (%d)", path, stat.Uid, euid)
	}

	return nil
}
