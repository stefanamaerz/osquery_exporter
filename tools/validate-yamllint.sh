#!/bin/sh
# Validate YAML style/syntax on example configs.
set -e

cd "$(dirname "$0")/.."

if ! command -v yamllint >/dev/null 2>&1; then
    echo "yamllint not found; skipping YAML style validation" >&2
    exit 0
fi

yamllint -c .yamllint.yml \
    config_example.yaml \
    examples/*.yaml
