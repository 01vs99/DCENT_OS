#!/usr/bin/env bash
# Retired per-model wrapper cannot alias Unsupported am3-s19kpro to Beta am3-s19k.
# Generic lifecycle and real signed packages are exercised by the capsule harness.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LANE="$SCRIPT_DIR/build_s19kpro_beta_capsule.sh"
TMP_TEST="$(mktemp -d "${TMPDIR:-/tmp}/s19k-capsule-refusal.XXXXXX")"
trap 'rm -rf -- "$TMP_TEST"' EXIT
mkdir "$TMP_TEST/bin"
cat > "$TMP_TEST/bin/docker" <<'SH'
#!/bin/sh
printf 'unexpected Docker execution\n' >> "$DCENT_REFUSAL_DOCKER_LOG"
exit 99
SH
chmod +x "$TMP_TEST/bin/docker"
for channel in beta stable; do
    set +e
    PATH="$TMP_TEST/bin:$PATH" DCENT_REFUSAL_DOCKER_LOG="$TMP_TEST/docker.log" \
        DCENT_RELEASE_PRODUCER=am3-s19k \
        bash "$LANE" --channel "$channel" --output-root "$TMP_TEST/output" > "$TMP_TEST/stdout" 2> "$TMP_TEST/stderr"
    status=$?
    set -e
    test "$status" -eq 2
    grep -Fq 'am3-s19kpro is Unsupported' "$TMP_TEST/stderr"
    test ! -e "$TMP_TEST/output"
    test ! -e "$TMP_TEST/docker.log"
done
python3 - "$SCRIPT_DIR" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from release_producer import get_producer, ProducerError
from runtime_image_manifest import registry_channel
from release_capsule_target_policy import policy_for
row = get_producer("am3-s19k")
assert row.board_target == "am3-s19k"
assert row.build_target == "am3-s19kpro"
assert row.cargo_variant == "amlogic"
registry_channel(row.board_target, "beta")
try:
    get_producer("am3-s19kpro")
except ProducerError:
    pass
else:
    raise AssertionError("Unsupported row became a producer alias")
for channel in ("beta", "stable"):
    try:
        registry_channel("am3-s19kpro", channel)
    except ValueError:
        pass
    else:
        raise AssertionError("Unsupported row admitted to a signed release channel")
assert policy_for("am3-s19kpro").publication_admitted is False
PY
printf 'S19k historical wrapper refusal and exact Beta producer tests passed\n'
