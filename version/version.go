// Package version holds the osquery_exporter version string. It is intended to
// be set at build time via the -ldflags "-X" mechanism, falling back to "dev"
// for plain go builds.
package version

// Version is the osquery_exporter version. It is overridden by the linker when
// built with -ldflags "-X github.com/stefanamaerz/osquery_exporter/version.Version=<value>".
var Version = "dev"
