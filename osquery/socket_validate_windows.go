//go:build windows

package osquery

// validateSocketPath is a no-op on Windows. The exporter is expected to use
// named pipes rather than Unix domain sockets on Windows.
func validateSocketPath(path string) error {
	return nil
}
