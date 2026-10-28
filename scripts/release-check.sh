#!/usr/bin/env bash
# Run gorelease against the previous release tag. The release workflow passes
# -version from the tag being cut; a local run lets gorelease suggest one.
set -euo pipefail

gorelease_version="v0.0.0-20261014143641-f0251eb4aa3e"

base="$(git describe --tags --abbrev=0 --match 'v[0-9]*' HEAD^ 2>/dev/null || true)"
if [[ -z "${base}" ]]; then
  base="none"
fi

exec go run "golang.org/x/exp/cmd/gorelease@${gorelease_version}" -base="${base}" "$@"
