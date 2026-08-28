#!/bin/sh
# Validate all example YAML configs against config.cue.
# Requires Go (uses `go run` to fetch/run a pinned CUE version).
set -e

cd "$(dirname "$0")/.."

GOWORK=off go run cuelang.org/go/cmd/cue@v0.17.1 \
    vet --schema '#Config' \
    config.cue \
    config_example.yaml \
    examples/*.yaml
