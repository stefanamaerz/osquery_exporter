package osquery

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stefanamaerz/osquery_exporter/model"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestNewRunnerInvalidTimeout(t *testing.T) {
	_, err := NewRunner("echo", "not-a-duration", nil, discardLogger())
	if err == nil {
		t.Fatal("expected error for invalid timeout, got nil")
	}
}

func TestNewRunnerExecutableNotFound(t *testing.T) {
	_, err := NewRunner("/definitely/not/osqueryi", "10s", nil, discardLogger())
	if err == nil {
		t.Fatal("expected error for missing executable, got nil")
	}
}

func TestNewRunnerLooksUpInPATH(t *testing.T) {
	// Use a fake osqueryi in a temporary directory.
	dir := t.TempDir()
	fake := filepath.Join(dir, "osqueryi")
	script := `#!/bin/sh
printf '[{"answer":"42"}]\n'
`
	if err := os.WriteFile(fake, []byte(script), 0755); err != nil {
		t.Fatalf("failed to write fake osqueryi: %v", err)
	}

	r, err := NewRunner(fake, "10s", []string{"--foo"}, discardLogger())
	if err != nil {
		t.Fatalf("NewRunner failed: %v", err)
	}
	res, err := r.Run("SELECT 42 AS answer")
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(res.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(res.Items))
	}
	if got := res.Items[0]["answer"]; got != "42" {
		t.Fatalf("answer = %q, want 42", got)
	}
}

func TestRunInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "osqueryi")
	script := `#!/bin/sh
printf 'not json\n'
`
	if err := os.WriteFile(fake, []byte(script), 0755); err != nil {
		t.Fatalf("failed to write fake osqueryi: %v", err)
	}

	r, err := NewRunner(fake, "10s", nil, discardLogger())
	if err != nil {
		t.Fatalf("NewRunner failed: %v", err)
	}
	_, err = r.Run("SELECT 1")
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestRunNonZeroExit(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "osqueryi")
	script := `#!/bin/sh
printf '[{"one":"1"}]\n'
exit 1
`
	if err := os.WriteFile(fake, []byte(script), 0755); err != nil {
		t.Fatalf("failed to write fake osqueryi: %v", err)
	}

	r, err := NewRunner(fake, "10s", nil, discardLogger())
	if err != nil {
		t.Fatalf("NewRunner failed: %v", err)
	}
	_, err = r.Run("SELECT 1")
	if err == nil {
		t.Fatal("expected error for non-zero exit, got nil")
	}
}

func TestRunRespectsDefaultFlags(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "osqueryi")
	script := `#!/bin/sh
if [ "$1" != "--foo" ]; then
  echo "expected --foo as first flag, got $1" >&2
  exit 1
fi
shift
printf '[{"args":"%s"}]\n' "$*"
`
	if err := os.WriteFile(fake, []byte(script), 0755); err != nil {
		t.Fatalf("failed to write fake osqueryi: %v", err)
	}

	r, err := NewRunner(fake, "10s", []string{"--foo"}, discardLogger())
	if err != nil {
		t.Fatalf("NewRunner failed: %v", err)
	}
	res, err := r.Run("SELECT 1")
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	want := "--json SELECT 1"
	if got := res.Items[0]["args"]; got != want {
		t.Fatalf("args = %q, want %q", got, want)
	}
}

func TestRunResultType(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "osqueryi")
	script := `#!/bin/sh
printf '[{"n":"3.14"}]\n'
`
	if err := os.WriteFile(fake, []byte(script), 0755); err != nil {
		t.Fatalf("failed to write fake osqueryi: %v", err)
	}

	r, err := NewRunner(fake, "10s", nil, discardLogger())
	if err != nil {
		t.Fatalf("NewRunner failed: %v", err)
	}
	res, err := r.Run("SELECT 1")
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	_ = res.Items
	_ = model.OsqueryItem(res.Items[0])
}

func TestRunEmptyResult(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "osqueryi")
	script := `#!/bin/sh
printf '[]\n'
`
	if err := os.WriteFile(fake, []byte(script), 0755); err != nil {
		t.Fatalf("failed to write fake osqueryi: %v", err)
	}

	r, err := NewRunner(fake, "10s", nil, discardLogger())
	if err != nil {
		t.Fatalf("NewRunner failed: %v", err)
	}
	res, err := r.Run("SELECT * FROM empty")
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(res.Items) != 0 {
		t.Fatalf("expected 0 items, got %d", len(res.Items))
	}
}
