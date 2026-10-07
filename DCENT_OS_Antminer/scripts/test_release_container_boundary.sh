#!/bin/sh
# Actual production Dockerfile and mount/layout probes; no firmware compilation.
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$script_dir/.."
owned_tag="dcentos-container-boundary:test-$(python3 -c 'import uuid; print(uuid.uuid4().hex)')"
cleanup() { docker image rm "$owned_tag" >/dev/null 2>&1 || :; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
docker build -f Dockerfile.build -t "$owned_tag" .
DCENT_TEST_RELEASE_CONTAINER_IMAGE=$(docker image inspect --format '{{.Id}}' "$owned_tag")
export DCENT_TEST_RELEASE_CONTAINER_IMAGE
python3 scripts/test_release_container_boundary.py
