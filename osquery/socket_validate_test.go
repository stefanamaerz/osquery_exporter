//go:build unix

package osquery

import (
	"os"
	"syscall"
	"testing"
	"time"
)

type fakeFileInfo struct {
	name    string
	mode    os.FileMode
	uid     uint32
	isDir   bool
	symlink bool
}

func (f *fakeFileInfo) Name() string       { return f.name }
func (f *fakeFileInfo) Size() int64        { return 0 }
func (f *fakeFileInfo) Mode() os.FileMode  { return f.mode }
func (f *fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f *fakeFileInfo) IsDir() bool        { return f.isDir }
func (f *fakeFileInfo) Sys() any           { return &syscall.Stat_t{Uid: f.uid} }

func fakeLstat(calls map[string]os.FileInfo) func(string) (os.FileInfo, error) {
	return func(path string) (os.FileInfo, error) {
		fi, ok := calls[path]
		if !ok {
			return nil, os.ErrNotExist
		}
		return fi, nil
	}
}

func TestValidateSocketPathRelative(t *testing.T) {
	if err := validateSocketPathWithDeps("./socket.em", func() int { return 1000 }, os.Lstat); err == nil {
		t.Fatal("expected error for relative path")
	}
}

func TestValidateSocketPathRoot(t *testing.T) {
	if err := validateSocketPathWithDeps("/", func() int { return 1000 }, os.Lstat); err == nil {
		t.Fatal("expected error for root path")
	}
}
func TestValidateSocketPathValidRootOwned(t *testing.T) {
	calls := map[string]os.FileInfo{
		"/var":             &fakeFileInfo{name: "var", mode: os.ModeDir | 0o755, uid: 0, isDir: true},
		"/var/run":         &fakeFileInfo{name: "run", mode: os.ModeDir | 0o755, uid: 0, isDir: true},
		"/var/run/osquery": &fakeFileInfo{name: "osquery", mode: os.ModeDir | 0o755, uid: 0, isDir: true},
	}
	if err := validateSocketPathWithDeps("/var/run/osquery/osquery.em", func() int { return 1000 }, fakeLstat(calls)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateSocketPathWorldWritable(t *testing.T) {
	calls := map[string]os.FileInfo{
		"/var":             &fakeFileInfo{name: "var", mode: os.ModeDir | 0o755, uid: 0, isDir: true},
		"/var/run":         &fakeFileInfo{name: "run", mode: os.ModeDir | 0o777, uid: 0, isDir: true},
		"/var/run/osquery": &fakeFileInfo{name: "osquery", mode: os.ModeDir | 0o755, uid: 0, isDir: true},
	}
	if err := validateSocketPathWithDeps("/var/run/osquery/osquery.em", func() int { return 1000 }, fakeLstat(calls)); err == nil {
		t.Fatal("expected error for world-writable parent")
	}
}

func TestValidateSocketPathGroupWritable(t *testing.T) {
	calls := map[string]os.FileInfo{
		"/var":             &fakeFileInfo{name: "var", mode: os.ModeDir | 0o755, uid: 0, isDir: true},
		"/var/run":         &fakeFileInfo{name: "run", mode: os.ModeDir | 0o770, uid: 0, isDir: true},
		"/var/run/osquery": &fakeFileInfo{name: "osquery", mode: os.ModeDir | 0o755, uid: 0, isDir: true},
	}
	if err := validateSocketPathWithDeps("/var/run/osquery/osquery.em", func() int { return 1000 }, fakeLstat(calls)); err == nil {
		t.Fatal("expected error for group-writable parent")
	}
}

func TestValidateSocketPathSymlinkParent(t *testing.T) {
	calls := map[string]os.FileInfo{
		"/var":             &fakeFileInfo{name: "var", mode: os.ModeDir | 0o755, uid: 0, isDir: true},
		"/var/run":         &fakeFileInfo{name: "run", mode: os.ModeSymlink | 0o777, uid: 0, isDir: false, symlink: true},
		"/var/run/osquery": &fakeFileInfo{name: "osquery", mode: os.ModeDir | 0o755, uid: 0, isDir: true},
	}
	if err := validateSocketPathWithDeps("/var/run/osquery/osquery.em", func() int { return 1000 }, fakeLstat(calls)); err == nil {
		t.Fatal("expected error for symlink parent")
	}
}

func TestValidateSocketPathForeignOwner(t *testing.T) {
	calls := map[string]os.FileInfo{
		"/var":             &fakeFileInfo{name: "var", mode: os.ModeDir | 0o755, uid: 0, isDir: true},
		"/var/run":         &fakeFileInfo{name: "run", mode: os.ModeDir | 0o755, uid: 1234, isDir: true},
		"/var/run/osquery": &fakeFileInfo{name: "osquery", mode: os.ModeDir | 0o755, uid: 0, isDir: true},
	}
	if err := validateSocketPathWithDeps("/var/run/osquery/osquery.em", func() int { return 1000 }, fakeLstat(calls)); err == nil {
		t.Fatal("expected error for foreign-owned parent")
	}
}

func TestValidateSocketPathCurrentUserOwned(t *testing.T) {
	calls := map[string]os.FileInfo{
		"/tmp":         &fakeFileInfo{name: "tmp", mode: os.ModeDir | 0o755, uid: 1000, isDir: true},
		"/tmp/osquery": &fakeFileInfo{name: "osquery", mode: os.ModeDir | 0o700, uid: 1000, isDir: true},
	}
	if err := validateSocketPathWithDeps("/tmp/osquery/osquery.em", func() int { return 1000 }, fakeLstat(calls)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateSocketPathExistingSocket(t *testing.T) {
	calls := map[string]os.FileInfo{
		"/var":                        &fakeFileInfo{name: "var", mode: os.ModeDir | 0o755, uid: 0, isDir: true},
		"/var/run":                    &fakeFileInfo{name: "run", mode: os.ModeDir | 0o755, uid: 0, isDir: true},
		"/var/run/osquery":            &fakeFileInfo{name: "osquery", mode: os.ModeDir | 0o755, uid: 0, isDir: true},
		"/var/run/osquery/osquery.em": &fakeFileInfo{name: "osquery.em", mode: os.ModeSocket, uid: 0, isDir: false},
	}
	if err := validateSocketPathWithDeps("/var/run/osquery/osquery.em", func() int { return 1000 }, fakeLstat(calls)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateSocketPathExistingNotSocket(t *testing.T) {
	calls := map[string]os.FileInfo{
		"/var":                        &fakeFileInfo{name: "var", mode: os.ModeDir | 0o755, uid: 0, isDir: true},
		"/var/run":                    &fakeFileInfo{name: "run", mode: os.ModeDir | 0o755, uid: 0, isDir: true},
		"/var/run/osquery":            &fakeFileInfo{name: "osquery", mode: os.ModeDir | 0o755, uid: 0, isDir: true},
		"/var/run/osquery/osquery.em": &fakeFileInfo{name: "osquery.em", mode: 0o644, uid: 0, isDir: false},
	}
	if err := validateSocketPathWithDeps("/var/run/osquery/osquery.em", func() int { return 1000 }, fakeLstat(calls)); err == nil {
		t.Fatal("expected error when final path is not a socket")
	}
}

func TestValidateSocketPathExistingSymlink(t *testing.T) {
	calls := map[string]os.FileInfo{
		"/var":                        &fakeFileInfo{name: "var", mode: os.ModeDir | 0o755, uid: 0, isDir: true},
		"/var/run":                    &fakeFileInfo{name: "run", mode: os.ModeDir | 0o755, uid: 0, isDir: true},
		"/var/run/osquery":            &fakeFileInfo{name: "osquery", mode: os.ModeDir | 0o755, uid: 0, isDir: true},
		"/var/run/osquery/osquery.em": &fakeFileInfo{name: "osquery.em", mode: os.ModeSymlink, uid: 0, isDir: false, symlink: true},
	}
	if err := validateSocketPathWithDeps("/var/run/osquery/osquery.em", func() int { return 1000 }, fakeLstat(calls)); err == nil {
		t.Fatal("expected error when final path is a symlink")
	}
}
