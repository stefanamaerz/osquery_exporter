package osquery

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"time"

	"github.com/stefanamaerz/osquery_exporter/model"
)

// OsqueryRunner represents a command runner for osquery
type OsqueryRunner struct {
	executable   string
	timeout      time.Duration
	defaultFlags []string
	log          *slog.Logger
}

// NewRunner creates a new runner. The executable is looked up in $PATH if not provided as an absolute path
// timeout must be time.ParseDuration`able.
func NewRunner(executable, timeout string, defaultFlags []string, log *slog.Logger) (*OsqueryRunner, error) {
	to, err := time.ParseDuration(timeout)
	if err != nil {
		return nil, fmt.Errorf("can't parse timeout for runner: %w", err)
	}
	exe, err := exec.LookPath(executable)
	if err != nil {
		return nil, fmt.Errorf("osqueryi executable not found %q: %w", executable, err)
	}

	log.Info("created osquery runner", "executable", exe, "timeout", timeout)
	return &OsqueryRunner{
		executable:   exe,
		timeout:      to,
		defaultFlags: defaultFlags,
		log:          log,
	}, nil
}

// Run runs the provided query. The command invocation is cancelled after
// timeout.
func (runner *OsqueryRunner) Run(query string) (*model.OsqueryResult, error) {
	var items []model.OsqueryItem
	begin := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), runner.timeout)
	defer cancel()

	args := make([]string, 0, len(runner.defaultFlags)+2)
	args = append(args, runner.defaultFlags...)
	args = append(args, "--json", query)
	cmd := exec.CommandContext(ctx, runner.executable, args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	runner.log.Debug("running osquery query", "query", query, "args", args)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start osqueryi: %w", err)
	}
	defer func() { _ = cmd.Wait() }()

	if err := json.NewDecoder(stdout).Decode(&items); err != nil {
		return nil, fmt.Errorf("failed to decode osquery output: %w", err)
	}
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("osqueryi exited with error: %w", err)
	}
	duration := time.Since(begin)
	return &model.OsqueryResult{
		Items:   items,
		Runtime: duration,
	}, nil
}
