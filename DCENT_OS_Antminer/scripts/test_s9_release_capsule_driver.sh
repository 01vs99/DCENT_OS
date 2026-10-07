#!/usr/bin/env bash
# Generic capsule lifecycle with fake Docker/build work and a real signed runtime package.
# Caller holds the shared heavy lock for the one production ELF fixture build.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP_BASE="$(cd "${TMPDIR:-/tmp}" && pwd -P)"
TMPDIR_TEST="$(mktemp -d "$TMP_BASE/dcentos-s9-capsule.XXXXXX")"
TMPDIR_TEST="$(cd "$TMPDIR_TEST" && pwd -P)"
safe_test_cleanup() {
    case "$TMPDIR_TEST" in
        "$TMP_BASE"/dcentos-s9-capsule.*) ;;
        *) echo "refusing unsafe harness cleanup: $TMPDIR_TEST" >&2; return 1;;
    esac
    [ "$(dirname "$TMPDIR_TEST")" = "$TMP_BASE" ] && [ ! -L "$TMPDIR_TEST" ] || {
        echo "refusing changed harness cleanup root: $TMPDIR_TEST" >&2; return 1
    }
    rm -rf -- "$TMPDIR_TEST"
}
trap safe_test_cleanup EXIT

LIVE_REPO="$TMPDIR_TEST/live-repo"
OUTPUT_ROOT="$TMPDIR_TEST/public-output"
FAKE_BIN="$TMPDIR_TEST/fake-bin"
FAKE_STATE="$TMPDIR_TEST/docker-state"
DOCKER_LOG="$TMPDIR_TEST/docker.log"
AUDIT_LOG="$TMPDIR_TEST/audit.log"
mkdir -p "$LIVE_REPO/DCENT_OS_Antminer/scripts" "$FAKE_BIN" \
    "$FAKE_STATE/volumes" "$FAKE_STATE/images" "$FAKE_STATE/containers"
: > "$DOCKER_LOG"

# Pin the production driver invariants that the lightweight authenticated test
# driver below models. These assertions prevent the harness from passing after
# a regression back to the live tree, global volume, mutable tag execution, or
# direct public output.
grep -Fq 'EXPECTED_CAPSULE_PROJECT="$(cd "$CAPSULE_SOURCE_TREE/DCENT_OS_Antminer" && pwd)"' \
    "$SCRIPT_DIR/build_in_docker.sh"
grep -Fq 'VOLUME_NAME="$(python3 "$SCRIPT_DIR/release_invocation.py" query' \
    "$SCRIPT_DIR/build_in_docker.sh"
grep -Fq 'IMAGE_NAME="$(python3 "$SCRIPT_DIR/release_docker_resources.py"' \
    "$SCRIPT_DIR/build_in_docker.sh"
grep -Fq 'docker build -f "$DOCKER_BUILD_DOCKERFILE" -t "$IMAGE_NAME" "$DOCKER_BUILD_CTX"' \
    "$SCRIPT_DIR/build_in_docker.sh"
grep -Fq 'BUILD_CONTAINER_ID="$(docker image inspect --format' \
    "$SCRIPT_DIR/build_in_docker.sh"
grep -Fq '"$BUILD_CONTAINER_ID" bash -c' "$SCRIPT_DIR/build_in_docker.sh"
grep -Fq -- '-v "${POSIX_PROJECT_DIR}:/src:ro"' "$SCRIPT_DIR/build_in_docker.sh"
grep -Fq -- '--output-dir for its private release-set stage' "$SCRIPT_DIR/build_in_docker.sh"
grep -Fq 'release_producer.py" create-result' "$SCRIPT_DIR/build_release_capsule.sh"
grep -Fq 'release_producer.py" create-cohort-result' "$SCRIPT_DIR/build_release_capsule.sh"
grep -Fq 'release_producer_evidence.py" retain-live' "$SCRIPT_DIR/build_release_capsule.sh"
grep -Fq 'exec bash "$SCRIPT_DIR/build_release_capsule.sh" --producer' "$SCRIPT_DIR/build_s9_release_capsule.sh"
grep -Fq 'for RELEASE_PRODUCER in "${RELEASE_PRODUCERS[@]}"' "$SCRIPT_DIR/build_release_capsule.sh"
grep -Fq 'tee "$PUBLIC_OUTPUT_ROOT/../lane-${RELEASE_PRODUCER}.log"' \
    "$SCRIPT_DIR/build_release_capsule.sh"
grep -Fq 'release_signing_authority.py" create' \
    "$SCRIPT_DIR/build_release_capsule.sh"
grep -Fq -- '--result-output "$RESULT_CREATE_RESULT_FILE"' \
    "$SCRIPT_DIR/build_release_capsule.sh"
grep -Fq 'result-stage cleanup failed; recovery result retained:' \
    "$SCRIPT_DIR/build_release_capsule.sh"
grep -Fq 'result-stage creation recovery failed; locator retained:' \
    "$SCRIPT_DIR/build_release_capsule.sh"
grep -Fq 'result-stage recovery result is unreadable; retained:' \
    "$SCRIPT_DIR/build_release_capsule.sh"
grep -Fq -- '--result-output "$SIGNING_AUTHORITY_RESULT_FILE"' \
    "$SCRIPT_DIR/build_release_capsule.sh"
grep -Fq 'signing-authority cleanup failed; recovery result retained:' \
    "$SCRIPT_DIR/build_release_capsule.sh"
grep -Fq 'registered signing-authority recovery result is missing; upstream authority retained:' \
    "$SCRIPT_DIR/build_release_capsule.sh"
grep -Fq 'dependent cleanup failed; invocation retained for recovery:' \
    "$SCRIPT_DIR/build_release_capsule.sh"
grep -Fq 'cleanup helper source retained for recovery:' \
    "$SCRIPT_DIR/build_release_capsule.sh"
grep -Fq 'DCENT_RELEASE_SIGNING_KEY="$SIGNING_AUTHORITY_PRIVATE_KEY"' \
    "$SCRIPT_DIR/build_release_capsule.sh"
grep -Fq 'clean|exact_git_object_snapshot' "$SCRIPT_DIR/lib/release_envelope.sh"
if grep -Fq 'VOLUME_NAME="dcentos-build-work"' \
    <(sed -n '/if \[ "${DCENT_RELEASE_CAPSULE_MODE/,/fi/p' "$SCRIPT_DIR/build_in_docker.sh"); then
    echo "capsule branch names a global Buildroot volume" >&2
    exit 1
fi

for helper in \
    atomic_publish_directory.py atomic_publish_file.py durable_file_io.py \
    build_s9_release_capsule.sh build_release_capsule.sh source_snapshot.py release_source_git.py release_invocation.py \
    release_result_stage.py release_set_publication.py release_publication.py \
    release_docker_resources.py release_signing_authority.py \
    release_capsule_target_policy.py release_producer.py release_train.py runtime_image_manifest.py release_runtime_exports.py sign_release_artifact.py \
    sign_release_receipt.py \
    firmware_release_name.sh verify_release_keypair.sh release_host_tools.py; do
    cp "$SCRIPT_DIR/$helper" "$LIVE_REPO/DCENT_OS_Antminer/scripts/$helper"
done
# The release helper imports its packaged canonical verifier in this isolated
# source snapshot too; copying only scripts must not hide that dependency.
TOOLBOX_FIXTURE="$LIVE_REPO/projects/dcent-toolbox/src/dcent_toolbox"
mkdir -p "$TOOLBOX_FIXTURE/core"
for helper in __init__.py core/__init__.py core/signed_runtime_image.py core/squashfs_files.py; do
    cp "$SCRIPT_DIR/../../dcent-toolbox/src/dcent_toolbox/$helper" "$TOOLBOX_FIXTURE/$helper"
done
grep -Fq 'from atomic_publish_file import' \
    "$LIVE_REPO/DCENT_OS_Antminer/scripts/release_set_publication.py"
grep -Fq 'from atomic_publish_directory import' \
    "$LIVE_REPO/DCENT_OS_Antminer/scripts/release_set_publication.py"
grep -Fq 'from durable_file_io import' \
    "$LIVE_REPO/DCENT_OS_Antminer/scripts/atomic_publish_file.py"
chmod +x "$LIVE_REPO/DCENT_OS_Antminer/scripts/build_release_capsule.sh"
grep -Fq 'release-set cleanup failed; capability retained for recovery:' \
    "$LIVE_REPO/DCENT_OS_Antminer/scripts/build_release_capsule.sh"
grep -Fq 'release_set_destroy_error' \
    "$LIVE_REPO/DCENT_OS_Antminer/scripts/build_release_capsule.sh"

# The orchestrator needs only create/query/destroy from this outer-owned input
# authority. The production helper has its own exhaustive adversarial suite.
cat > "$LIVE_REPO/DCENT_OS_Antminer/scripts/build_input_snapshot.py" <<'PY'
#!/usr/bin/env python3
import argparse, hashlib, json, pathlib, secrets, shutil, tempfile
p=argparse.ArgumentParser(); s=p.add_subparsers(dest="cmd", required=True)
c=s.add_parser("create"); c.add_argument("--repo-root"); c.add_argument("--selection-root")
c.add_argument("--build-input-manifest"); c.add_argument("--target"); c.add_argument("--stage-parent", required=True)
q=s.add_parser("query-result"); q.add_argument("--field", required=True)
d=s.add_parser("destroy"); d.add_argument("--token", required=True); d.add_argument("snapshot")
a=p.parse_args()
if a.cmd=="create":
    parent=pathlib.Path(a.stage_parent); parent.mkdir(parents=True, exist_ok=True)
    stage=pathlib.Path(tempfile.mkdtemp(prefix="input-", dir=parent)); token=secrets.token_hex(32)
    snap=stage/"snapshot.json"; snap.write_text(json.dumps({"token_sha256":hashlib.sha256(token.encode()).hexdigest()}))
    print(json.dumps({"snapshot":str(snap),"stage":str(stage),"destroy_token":token}))
elif a.cmd=="query-result": print(json.load(__import__("sys").stdin)[a.field])
else:
    snap=pathlib.Path(a.snapshot); value=json.loads(snap.read_text())
    if hashlib.sha256(a.token.encode()).hexdigest()!=value["token_sha256"]: raise SystemExit("bad token")
    shutil.rmtree(snap.parent)
PY

# This lifecycle model uses a synthetic Cargo input snapshot above. Retain its
# exact descriptor with the real source/invocation/result projections here;
# test_source_closure.sh exercises the production retain/audit implementation
# against actual signed receipts and destroyed private authorities.
cat > "$LIVE_REPO/DCENT_OS_Antminer/scripts/release_producer_evidence.py" <<'PY'
import argparse, pathlib, shutil
import release_invocation, release_result_stage
p = argparse.ArgumentParser()
p.add_argument("command", choices=["retain-live"])
for name in ("repo-root", "source-commit", "source-snapshot", "release-invocation",
             "cargo-input-snapshot", "result-stage", "artifact-dir"):
    p.add_argument("--" + name, required=True)
a = p.parse_args()
directory = pathlib.Path(a.artifact_dir)
invocation = release_invocation.verify_invocation(pathlib.Path(a.release_invocation))
result = release_result_stage.verify_result_stage(pathlib.Path(a.result_stage), pathlib.Path(a.release_invocation))
assert result.descriptor["state"] == "sealed"
shutil.copyfile(a.source_snapshot, directory / "release-source-snapshot.json")
shutil.copyfile(a.cargo_input_snapshot, directory / "release-cargo-input.json")
(directory / "release-invocation.json").write_bytes(release_invocation.canonical_bytes(invocation.descriptor))
(directory / "release-result-audit.json").write_bytes(release_result_stage.canonical_bytes(release_result_stage.audit_projection(result)))
PY

# These copies supply the real registry/version readers inside the authenticated
# source snapshot. The hardware engine itself is never built or run here.
mkdir -p "$LIVE_REPO/DCENT_OS_Antminer/dcentrald/dcentrald-common/src"
cp "$SCRIPT_DIR/../dcentrald/dcentrald-common/src/board_desc.rs" \
    "$LIVE_REPO/DCENT_OS_Antminer/dcentrald/dcentrald-common/src/board_desc.rs"
printf '[workspace.package]\nversion = "1.2.3"\n' > "$LIVE_REPO/DCENT_OS_Antminer/dcentrald/Cargo.toml"
# Real package verification imports this production read-only decoder from the
# authenticated repository snapshot, exactly as a real release does.
TOOLBOX_SOURCE="$SCRIPT_DIR/../../dcent-toolbox/src/dcent_toolbox"
TOOLBOX_FIXTURE="$LIVE_REPO/projects/dcent-toolbox/src/dcent_toolbox"
mkdir -p "$TOOLBOX_FIXTURE/core"
cp "$TOOLBOX_SOURCE/__init__.py" "$TOOLBOX_FIXTURE/__init__.py"
cp "$TOOLBOX_SOURCE/core/__init__.py" "$TOOLBOX_FIXTURE/core/__init__.py"
cp "$TOOLBOX_SOURCE/core/squashfs_files.py" "$TOOLBOX_FIXTURE/core/squashfs_files.py"

cat > "$LIVE_REPO/DCENT_OS_Antminer/scripts/build-dcentrald.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd "$(dirname "$0")" && pwd)"
printf 'compile=%s\n' "$1" >> "$HARNESS_AUDIT_LOG"
case "$DCENT_RELEASE_SIGNING_KEY" in
  "$HARNESS_OUTPUT_ROOT"/.dcent-release-capsules/signing-authorities/*/private-key.pem) ;;
  *) echo 'Cargo signer did not receive the private authority snapshot' >&2; exit 1;;
esac
case "$DCENT_RELEASE_PUBKEY_FILE" in
  "$HARNESS_OUTPUT_ROOT"/.dcent-release-capsules/signing-authorities/*/public-key.pem) ;;
  *) echo 'Cargo verifier did not receive the public authority snapshot' >&2; exit 1;;
esac
python3 "$script_dir/release_signing_authority.py" verify \
    --invocation-stage "$DCENT_CAPSULE_INVOCATION_STAGE" \
    "$(dirname "$DCENT_RELEASE_SIGNING_KEY")" >/dev/null
test "$(cat "$DCENT_RELEASE_SIGNING_KEY")" = "$HARNESS_EXPECTED_PRIVATE_KEY"
test "$(cat "$DCENT_RELEASE_PUBKEY_FILE")" = "$HARNESS_EXPECTED_PUBLIC_KEY"
# Rotate both original operator pathnames after admission. All later signing
# and verification must continue through the invocation snapshot. The signal
# cleanup case opts out only because its wrapper is intentionally killed.
if [ "${HARNESS_ROTATE_KEYS:-1}" = 1 ]; then
    cp "$HARNESS_OTHER_PRIVATE_KEY" "$HARNESS_ORIGINAL_PRIVATE_KEY"
    cp "$HARNESS_OTHER_PUBLIC_KEY" "$HARNESS_ORIGINAL_PUBLIC_KEY"
    printf 'signing-private=%s\nsigning-public=%s\noriginal-keys-rotated=yes\n' \
        "$DCENT_RELEASE_SIGNING_KEY" "$DCENT_RELEASE_PUBKEY_FILE" >> "$HARNESS_AUDIT_LOG"
fi
python3 "$script_dir/release_result_stage.py" verify \
    --invocation-stage "$DCENT_CAPSULE_INVOCATION_STAGE" "$DCENT_CAPSULE_RESULT_STAGE" >/dev/null
root="$(python3 "$script_dir/release_result_stage.py" query --field result_root \
    --invocation-stage "$DCENT_CAPSULE_INVOCATION_STAGE" "$DCENT_CAPSULE_RESULT_STAGE")"
mkdir -p "$root/target/armv7-unknown-linux-musleabihf/release"
printf 'sealed cargo result from snapshot A\n' > \
    "$root/target/armv7-unknown-linux-musleabihf/release/dcentrald"
python3 "$script_dir/release_result_stage.py" seal \
    --capability "$DCENT_CAPSULE_RESULT_CAPABILITY" \
    --invocation-stage "$DCENT_CAPSULE_INVOCATION_STAGE" "$DCENT_CAPSULE_RESULT_STAGE" >/dev/null
SH
chmod +x "$LIVE_REPO/DCENT_OS_Antminer/scripts/build-dcentrald.sh"

cat > "$LIVE_REPO/DCENT_OS_Antminer/scripts/build_in_docker.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd "$(dirname "$0")" && pwd)"; project_dir="$(dirname "$script_dir")"
output=""; while [ "$#" -gt 0 ]; do case "$1" in --output-dir) output=$2; shift 2;; *) shift;; esac; done
stage="$(python3 "$script_dir/release_set_publication.py" query --field stage-path \
    < "$DCENT_CAPSULE_RELEASE_SET_CAPABILITY_FILE")"
[ "$output" = "$stage" ]
verified="$(python3 "$script_dir/source_snapshot.py" verify-against-git \
    --repo-root "$DCENT_CAPSULE_GIT_OBJECT_REPO" --commit "$DCENT_CAPSULE_SOURCE_COMMIT" \
    "$DCENT_CAPSULE_SOURCE_SNAPSHOT")"
tree="$(printf '%s\n' "$verified" | python3 "$script_dir/source_snapshot.py" query-verified --field tree)"
[ "$project_dir" = "$tree/DCENT_OS_Antminer" ]
[ "$(cat "$project_dir/source-marker.txt")" = snapshot-A ]
[ "$(cat "$HARNESS_LIVE_ROOT/DCENT_OS_Antminer/source-marker.txt")" = mutated-live-B ]
invocation="$(python3 "$script_dir/release_invocation.py" query --field invocation_id "$DCENT_CAPSULE_INVOCATION_STAGE")"
volume="$(python3 "$script_dir/release_invocation.py" query --field buildroot_volume "$DCENT_CAPSULE_INVOCATION_STAGE")"
tag="$(python3 "$script_dir/release_docker_resources.py" query-builder-tag "$DCENT_CAPSULE_INVOCATION_STAGE")"
[ "$volume" != dcentos-build-work ]
docker volume inspect -- "$volume" >/dev/null 2>&1 && { echo 'pre-existing volume adopted' >&2; exit 1; }
docker volume create --label "invocation=$invocation" --label role=buildroot -- "$volume" >/dev/null
docker build -t "$tag" "$project_dir" >/dev/null
image_id="$(docker image inspect --format '{{.Id}}' "$tag")"
case "$image_id" in sha256:[0-9a-f][0-9a-f]*) ;; *) exit 1;; esac
cleanup() { docker volume rm -- "$volume" >/dev/null 2>&1 || true; docker image rm "$tag" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker run --rm -v "$project_dir:/src:ro" -v "$output:/out" "$image_id" true
printf 'source=%s\nlive=%s\nvolume=%s\ntag=%s\nimage=%s\nprivate=%s\n' \
    "$(cat "$project_dir/source-marker.txt")" \
    "$(cat "$HARNESS_LIVE_ROOT/DCENT_OS_Antminer/source-marker.txt")" \
    "$volume" "$tag" "$image_id" "$output" >> "$HARNESS_AUDIT_LOG"
primary="$(python3 "$script_dir/release_producer.py" query "$DCENT_RELEASE_PRODUCER" primary_artifact)"
case "$DCENT_RELEASE_PRODUCER" in
    s9) artifact=$HARNESS_ARTIFACT ;;
    am2-s19jpro) artifact=$HARNESS_AM2_ARTIFACT ;;
    *) echo 'unexpected fixture producer' >&2; exit 1 ;;
esac
printf 'producer=%s\n' "$DCENT_RELEASE_PRODUCER" >> "$HARNESS_AUDIT_LOG"
for suffix in '' .sig .runtime-image.json .runtime-image.sig; do
    cp "$artifact$suffix" "$output/$primary$suffix"
done
printf 'SD/installer policy remains independent. https://d-central.tech/fund/\n' > "$output/TESTER_README.txt"
printf '{"schema":"harness-packaging-input.v1"}\n' > "$output/release-packaging-input.json"
printf '{"schema":"harness-source-closure.v1"}\n' > \
    "$output/$primary.source-closure.json"
head -c 64 /dev/zero > "$output/$primary.source-closure.json.sig"
if [ "${HARNESS_FAIL_AFTER_PRIVATE:-0}" = 1 ]; then exit 91; fi
if [ -n "${HARNESS_SIGNAL_READY:-}" ]; then
    # Docker resources are already disposed in the real driver before control
    # returns. Model that state, then let the outer signal cleanup own stages.
    cleanup; trap - EXIT; : > "$HARNESS_SIGNAL_READY"; sleep 30
fi
SH
chmod +x "$LIVE_REPO/DCENT_OS_Antminer/scripts/build_in_docker.sh"
printf 'snapshot-A\n' > "$LIVE_REPO/DCENT_OS_Antminer/source-marker.txt"
printf '# test selection authority\n' > "$LIVE_REPO/DCENT_OS_Antminer/scripts/build_inputs.manifest"

cat > "$FAKE_BIN/docker" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
state=${FAKE_DOCKER_STATE:?}; log=${FAKE_DOCKER_LOG:?}; printf '%q ' "$@" >> "$log"; printf '\n' >> "$log"
digest="sha256:$(printf '7%.0s' {1..64})"; kind=${1:-}; shift || true
case "$kind" in
info) exit 0;;
volume)
    action=$1; shift
    [ "${1:-}" = -- ] && shift || true; name=${!#}
    case "$action" in
      inspect) [ -f "$state/volumes/$name" ];;
      create) printf '%s\n' "$*" > "$state/volumes/$name"; printf '%s\n' "$name";;
      rm) rm -f -- "$state/volumes/$name";; esac;;
image)
    action=$1; shift
    case "$action" in
      inspect) [ "${1:-}" = --format ] && shift 2; tag=$1; [ -f "$state/images/$tag" ]; printf '%s\n' "$digest";;
      rm) rm -f -- "$state/images/$1";;
      tag) cp "$state/images/$1" "$state/images/$2";; esac;;
build)
    tag=""; while [ "$#" -gt 0 ]; do case "$1" in -t) tag=$2; shift 2;; *) shift;; esac; done
    printf '%s\n' "$digest" > "$state/images/$tag";;
run)
    source_mount=""; image=""
    while [ "$#" -gt 0 ]; do case "$1" in --rm) shift;; -v) case "$2" in *:/src:ro) source_mount=${2%:/src:ro};; esac; shift 2;; sha256:*) image=$1; shift; break;; *) shift;; esac; done
    [ "$image" = "$digest" ]; [ "$(cat "$source_mount/source-marker.txt")" = snapshot-A ];;
container) exit 1;;
*) exit 99;; esac
SH
chmod +x "$FAKE_BIN/docker"

git -C "$LIVE_REPO" init -q
git -C "$LIVE_REPO" config user.email test@example.invalid
git -C "$LIVE_REPO" config user.name 'Capsule Harness'
git -C "$LIVE_REPO" add .
mkdir -p "$LIVE_REPO/public-releases/unrelated"
git -C "$LIVE_REPO" update-index --add --cacheinfo 160000 \
    abababababababababababababababababababab public-releases/unrelated
git -C "$LIVE_REPO" commit -qm 'snapshot A'
printf 'mutated-live-B\n' > "$LIVE_REPO/DCENT_OS_Antminer/source-marker.txt"

SIGNING_KEY="$TMPDIR_TEST/signing.pem"; PUBLIC_KEY="$TMPDIR_TEST/public.pem"
OTHER_KEY="$TMPDIR_TEST/other.pem"; OTHER_PUBLIC_KEY="$TMPDIR_TEST/other-public.pem"
# Only this fixture compiles; package/signature verification below is production.
python3 - "$SCRIPT_DIR" "$TMPDIR_TEST/package-fixture" <<'PYFIXTURE'
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from test_release_runtime_exports import package_fixture
base = package_fixture(Path(sys.argv[2]))
package_fixture(Path(sys.argv[2]) / "am2", board="am2-s19j", key=base["key"], pubkey=base["pubkey"], daemon=base["daemon"])
PYFIXTURE
cp "$TMPDIR_TEST/package-fixture/elf/test-key.pem" "$SIGNING_KEY"
cp "$TMPDIR_TEST/package-fixture/elf/test-pub.pem" "$PUBLIC_KEY"
HARNESS_ARTIFACT="$TMPDIR_TEST/package-fixture/dcentos-sysupgrade-118.tar"
HARNESS_AM2_ARTIFACT="$TMPDIR_TEST/package-fixture/am2/dcentos-sysupgrade-am2-s19jpro.tar"
COHORT_EXTRA_ARGS=()
openssl genpkey -algorithm ED25519 -out "$OTHER_KEY" >/dev/null 2>&1
openssl pkey -in "$OTHER_KEY" -pubout -out "$OTHER_PUBLIC_KEY" >/dev/null 2>&1
EXPECTED_PRIVATE_KEY="$(cat "$SIGNING_KEY")"
EXPECTED_PUBLIC_KEY="$(cat "$PUBLIC_KEY")"
SIGNING_KEY_BASELINE="$TMPDIR_TEST/signing-baseline.pem"
PUBLIC_KEY_BASELINE="$TMPDIR_TEST/public-baseline.pem"
cp "$SIGNING_KEY" "$SIGNING_KEY_BASELINE"
cp "$PUBLIC_KEY" "$PUBLIC_KEY_BASELINE"
MANIFEST_PUBLIC_KEY_HEX="$(openssl pkey -pubin -in "$PUBLIC_KEY" -outform DER \
    | python3 -c 'import sys; print(sys.stdin.buffer.read()[-32:].hex())')"
run_capsule_raw() {
    env PATH="$FAKE_BIN:$PATH" FAKE_DOCKER_STATE="$FAKE_STATE" FAKE_DOCKER_LOG="$DOCKER_LOG" \
        HARNESS_LIVE_ROOT="$LIVE_REPO" HARNESS_OUTPUT_ROOT="$OUTPUT_ROOT" HARNESS_AUDIT_LOG="$AUDIT_LOG" \
        HARNESS_ORIGINAL_PRIVATE_KEY="$SIGNING_KEY" HARNESS_ORIGINAL_PUBLIC_KEY="$PUBLIC_KEY" \
        HARNESS_OTHER_PRIVATE_KEY="$OTHER_KEY" HARNESS_OTHER_PUBLIC_KEY="$OTHER_PUBLIC_KEY" \
        HARNESS_EXPECTED_PRIVATE_KEY="$EXPECTED_PRIVATE_KEY" HARNESS_EXPECTED_PUBLIC_KEY="$EXPECTED_PUBLIC_KEY" \
        HARNESS_ARTIFACT="$HARNESS_ARTIFACT" HARNESS_AM2_ARTIFACT="$HARNESS_AM2_ARTIFACT" \
        DCENT_RELEASE_SIGNING_KEY="$SIGNING_KEY" DCENT_RELEASE_PUBKEY_FILE="$PUBLIC_KEY" \
        DCENT_REQUIRE_RELEASE_KEY=1 \
        DCENT_MANIFEST_PUBLIC_KEY_HEX="$MANIFEST_PUBLIC_KEY_HEX" \
        DCENT_RUST_BUILDER_BASE="rust-test@sha256:$(printf 'b%.0s' {1..64})" \
        DCENT_TOOLCHAIN_SHA256_VERIFIED=1 "$@" \
        "$LIVE_REPO/DCENT_OS_Antminer/scripts/build_release_capsule.sh" --producer s9 "${COHORT_EXTRA_ARGS[@]}" --output-root "$OUTPUT_ROOT" --result-json "$OUTPUT_ROOT/cohort-result.json"
}
run_capsule() {
    set +e
    run_capsule_raw "$@"
    status=$?
    cp "$SIGNING_KEY_BASELINE" "$SIGNING_KEY"
    cp "$PUBLIC_KEY_BASELINE" "$PUBLIC_KEY"
    set -e
    return "$status"
}

# Admission rejects malformed builder identity before allocating an invocation.
# A mismatched signing pair allocates only its invocation/signing authority;
# cleanup may inspect the derived Docker names but must never create or run one.
if run_capsule DCENT_RUST_BUILDER_BASE='rust-test@sha256:abcd-junk' \
    > "$TMPDIR_TEST/bad-builder.out" 2>&1; then
    echo 'malformed builder digest unexpectedly admitted' >&2; exit 1
fi
grep -q 'exact lowercase sha256 digest' "$TMPDIR_TEST/bad-builder.out"
if run_capsule DCENT_RELEASE_PUBKEY_FILE="$OTHER_PUBLIC_KEY" \
    > "$TMPDIR_TEST/bad-key.out" 2>&1; then
    echo 'mismatched release keypair unexpectedly admitted' >&2; exit 1
fi
grep -Eq 'match|mismatch|public key' "$TMPDIR_TEST/bad-key.out"
! grep -Eq '^volume create |^build |^run ' "$DOCKER_LOG"
test -z "$(find "$FAKE_STATE/volumes" -mindepth 1 -print -quit)"

# Failure after private bytes never creates a public release and destroys all
# invocation/source/result/release-set stages and exact Docker resources.
if run_capsule HARNESS_FAIL_AFTER_PRIVATE=1 > "$TMPDIR_TEST/failure.out" 2>&1; then
    echo 'injected private-stage failure unexpectedly succeeded' >&2; exit 1
fi
test ! -d "$OUTPUT_ROOT/releases" || ! find "$OUTPUT_ROOT/releases" -mindepth 1 -print -quit | grep -q .
test ! -e "$FAKE_STATE/volumes/dcentos-build-work"
test -z "$(find "$FAKE_STATE/volumes" -mindepth 1 -print -quit)"
test ! -d "$OUTPUT_ROOT/.dcent-release-capsules/signing-authorities" \
    || test -z "$(find "$OUTPUT_ROOT/.dcent-release-capsules/signing-authorities" -name private-key.pem -print -quit)"
test ! -d "$OUTPUT_ROOT/.dcent-release-capsules" \
    || test -z "$(find "$OUTPUT_ROOT/.dcent-release-capsules" -name 'result-stage-*.result.json' -print -quit)"

# A TERM while the private stage is active is never reported as success and
# cannot create a public set.
READY="$TMPDIR_TEST/signal.ready"; rm -f "$READY"
(run_capsule_raw HARNESS_ROTATE_KEYS=0 HARNESS_SIGNAL_READY="$READY" \
    > "$TMPDIR_TEST/signal.out" 2>&1) & signal_pid=$!
# The aggregate may be CPU-starved after Cargo-heavy phases. Bound only this
# fixture-readiness wait at 30 seconds; production capsule timeouts are not
# changed.
for _ in $(seq 1 1500); do [ -e "$READY" ] && break; sleep 0.02; done
test -e "$READY"
capsule_children="$(pgrep -P "$signal_pid" || true)"
test "$(printf '%s\n' "$capsule_children" | grep -c '[0-9]')" -eq 1
kill -TERM "$capsule_children"
if wait "$signal_pid"; then echo 'terminated capsule reported success' >&2; exit 1; fi
test ! -d "$OUTPUT_ROOT/releases" || ! find "$OUTPUT_ROOT/releases" -mindepth 1 -print -quit | grep -q .

# A successful run publishes one exact directory only after the private driver
# returned; live mutation B never becomes a source mount or artifact input.
run_capsule > "$TMPDIR_TEST/success.out"
test ! -d "$OUTPUT_ROOT/.dcent-release-capsules" \
    || test -z "$(find "$OUTPUT_ROOT/.dcent-release-capsules" -name 'result-stage-*.result.json' -print -quit)"
PUBLISHED="$(find "$OUTPUT_ROOT/releases" -mindepth 1 -maxdepth 1 -type d -print -quit)"
test -n "$PUBLISHED"
cmp "$PUBLISHED/dcentos-sysupgrade-118.tar" "$HARNESS_ARTIFACT"
test -f "$PUBLISHED/producer-result.json"
test -f "$PUBLISHED/producer-result.json.sig"
python3 - "$SCRIPT_DIR" "$OUTPUT_ROOT/cohort-result.json" "$OUTPUT_ROOT" "$PUBLIC_KEY" <<'PYVERIFY'
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from release_producer import load_result, verify_cohort
value = load_result(Path(sys.argv[2]))
verify_cohort(value, Path(sys.argv[3]), ["s9"], value["source_commit"], "1.2.3", "beta", Path(sys.argv[4]))
PYVERIFY
test ! -e "$PUBLISHED/knowledge-base/extractions/s9/kernel.bin"
grep -q '^signing-private=.*/.dcent-release-capsules/signing-authorities/.*/private-key.pem$' "$AUDIT_LOG"
grep -q '^signing-public=.*/.dcent-release-capsules/signing-authorities/.*/public-key.pem$' "$AUDIT_LOG"
grep -q '^original-keys-rotated=yes$' "$AUDIT_LOG"
grep -q '^source=snapshot-A$' "$AUDIT_LOG"
grep -q '^live=mutated-live-B$' "$AUDIT_LOG"
grep -q '^volume=dcentos-ri-s9-.*-buildroot$' "$AUDIT_LOG"
grep -q '^tag=dcentos-release-builder:' "$AUDIT_LOG"
grep -q '^image=sha256:7777777777777777777777777777777777777777777777777777777777777777$' "$AUDIT_LOG"
grep -q '/src:ro' "$DOCKER_LOG"
! grep -q 'dcentos-build-work' "$DOCKER_LOG"
openssl pkeyutl -verify -rawin -pubin -inkey "$PUBLIC_KEY" \
    -in "$PUBLISHED/producer-result.json" \
    -sigfile "$PUBLISHED/producer-result.json.sig" >/dev/null
test ! -d "$OUTPUT_ROOT/.dcent-release-capsules/signing-authorities" \
    || test -z "$(find "$OUTPUT_ROOT/.dcent-release-capsules/signing-authorities" -name private-key.pem -print -quit)"
FIRST_SHA="$(sha256sum "$PUBLISHED/dcentos-sysupgrade-118.tar" | awk '{print $1}')"

# Same-name publication is no-replace. A fresh result destination still fails and
# cannot modify or delete the already authoritative release set.
rm "$OUTPUT_ROOT/cohort-result.json"
if run_capsule > "$TMPDIR_TEST/collision.out" 2>&1; then
    echo 'same-name release collision unexpectedly succeeded' >&2; exit 1
fi
test "$(sha256sum "$PUBLISHED/dcentos-sysupgrade-118.tar" | awk '{print $1}')" = "$FIRST_SHA"
test "$(find "$OUTPUT_ROOT/releases" -mindepth 1 -maxdepth 1 -type d | wc -l)" -eq 1

# Two real signed packages share one sealed Cargo result, with distinct private
# stages. Verification requires both exact selected producer identities.
OUTPUT_ROOT="$TMPDIR_TEST/cohort-output"
COHORT_EXTRA_ARGS=(--producer am2-s19jpro)
: > "$AUDIT_LOG"
run_capsule > "$TMPDIR_TEST/cohort.out"
test "$(grep -c '^compile=zynq$' "$AUDIT_LOG")" -eq 1
test "$(grep -c '^producer=' "$AUDIT_LOG")" -eq 2
test "$(grep '^private=' "$AUDIT_LOG" | sort -u | wc -l)" -eq 2
python3 - "$SCRIPT_DIR" "$OUTPUT_ROOT/cohort-result.json" "$OUTPUT_ROOT" "$PUBLIC_KEY" <<'PYCOHORT'
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from release_producer import load_result, verify_cohort
value = load_result(Path(sys.argv[2]))
verify_cohort(value, Path(sys.argv[3]), ["s9", "am2-s19jpro"], value["source_commit"], "1.2.3", "beta", Path(sys.argv[4]))
assert len({record["files"]["primary"]["path"].rsplit("/", 1)[0] for record in value["results"]}) == 2
PYCOHORT
test -z "$(find "$FAKE_STATE/volumes" -mindepth 1 -print -quit)"

# Invocation/result descriptor swapping is rejected by the production helper.
CONTROL="$TMPDIR_TEST/swap-control"; mkdir -p "$CONTROL"
i1="$(python3 "$SCRIPT_DIR/release_invocation.py" create --stage-parent "$CONTROL" --name one)"
i2="$(python3 "$SCRIPT_DIR/release_invocation.py" create --stage-parent "$CONTROL" --name two)"
s1="$(printf '%s\n' "$i1" | python3 "$SCRIPT_DIR/release_invocation.py" query-result --field stage)"
s2="$(printf '%s\n' "$i2" | python3 "$SCRIPT_DIR/release_invocation.py" query-result --field stage)"
r1="$(python3 "$SCRIPT_DIR/release_result_stage.py" create --stage-parent "$CONTROL" \
    --invocation-stage "$s1" --result-output "$TMPDIR_TEST/swap-result.json")"
r1s="$(printf '%s\n' "$r1" | python3 "$SCRIPT_DIR/release_result_stage.py" query-result --field stage)"
if python3 "$SCRIPT_DIR/release_result_stage.py" verify --invocation-stage "$s2" "$r1s" \
    > "$TMPDIR_TEST/swap.out" 2>&1; then
    echo 'result descriptor swap unexpectedly verified' >&2; exit 1
fi
grep -Eq 'invocation|different|bound' "$TMPDIR_TEST/swap.out"

echo 'Generic release capsule lifecycle and real signed-package tests passed'
