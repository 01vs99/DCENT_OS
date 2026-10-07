#!/bin/sh
# Mount-free regression tests for the Zynq A/B persistent-state migration
# helper.  These tests operate only below a temporary directory.

set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
HELPER=$PROJECT_ROOT/br2_external_dcentos/board/zynq/rootfs-overlay/usr/libexec/dcentos/sysupgrade-persistent-state.sh
SEED_SOURCE=$PROJECT_ROOT/br2_external_dcentos/packages/seed-entropy/src/seed-entropy.c
TEST_BOOT_ID=11111111-1111-4111-8111-111111111111
SOURCE_BOOT_ID=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa

# shellcheck source=/dev/null
. "$HELPER"

failures=0
tests=0
WORK_ROOT=${TMPDIR:-/tmp}/dcent-persist-test.$$
SEED_BIN=$WORK_ROOT/seed-entropy-test

cleanup()
{
    rm -rf "$WORK_ROOT"
}
trap cleanup EXIT HUP INT TERM

pass()
{
    tests=$((tests + 1))
    printf 'PASS: %s\n' "$1"
}

fail()
{
    tests=$((tests + 1))
    failures=$((failures + 1))
    printf 'FAIL: %s\n' "$1" >&2
}

expect_success()
{
    _test_label=$1
    shift
    if "$@"; then
        pass "$_test_label"
    else
        fail "$_test_label"
    fi
}

expect_failure()
{
    _test_label=$1
    shift
    if "$@" >/dev/null 2>&1; then
        fail "$_test_label (unexpected success)"
    else
        pass "$_test_label"
    fi
}

assert_absent()
{
    [ ! -e "$1" ] && [ ! -L "$1" ]
}

assert_empty_dir()
{
    [ -d "$1" ] && [ ! -L "$1" ] && \
        [ -z "$(find "$1" -mindepth 1 -print -quit)" ]
}

new_fixture()
{
    _fixture=$1
    SOURCE=$WORK_ROOT/$_fixture/source
    DESTINATION=$WORK_ROOT/$_fixture/destination
    unset SEED_ENTROPY_TEST_READINESS SEED_ENTROPY_TEST_BOOT_ID
    mkdir -p "$SOURCE/keys/dropbear" "$SOURCE/config/nested" \
        "$SOURCE/profiles" "$SOURCE/dcent/ota-native/update" "$DESTINATION" \
        "$SOURCE/network" "$SOURCE/vendor-first-install"

    chmod 700 "$SOURCE/dcent"
    printf 'host-private-key\n' >"$SOURCE/keys/dropbear/dropbear_ed25519_host_key"
    printf 'ssh-ed25519 operator\n' >"$SOURCE/keys/dropbear/authorized_keys"
    awk 'BEGIN { for (i = 0; i < 256; i++) printf "A." }' \
        >"$SOURCE/keys/random-seed"
    _source_seed_digest=$(sha256sum "$SOURCE/keys/random-seed" | awk '{print $1}')
    printf 'v1 %s %s' "$SOURCE_BOOT_ID" "$_source_seed_digest" \
        >"$SOURCE/keys/.random-seed.born"
    printf '{"password_hash":"secret"}\n' >"$SOURCE/dcent/auth.json"
    printf 'ssh-ed25519 dashboard\n' >"$SOURCE/dcent/authorized_keys"
    printf 'IP=192.0.2.10\nMASK=255.255.255.0\n' >"$SOURCE/network/static"
    printf 'complete-stock-backup-receipt\n' >"$SOURCE/vendor-first-install/receipt.json"
    printf 'native-ota-complete-boot-tuple\n' >"$SOURCE/dcent/ota-native/update/env.rollback"
    chmod 600 "$SOURCE/dcent/ota-native/update/env.rollback"
    chmod 600 "$SOURCE/keys/random-seed" "$SOURCE/keys/.random-seed.born" \
        "$SOURCE/keys/dropbear/dropbear_ed25519_host_key" \
        "$SOURCE/keys/dropbear/authorized_keys" "$SOURCE/dcent/auth.json" \
        "$SOURCE/dcent/authorized_keys"

    printf 'hidden\n' >"$SOURCE/config/.hidden"
    printf 'nested\n' >"$SOURCE/config/nested/value"
    ln -s nested/value "$SOURCE/config/value-link"
    printf 'profile\n' >"$SOURCE/profiles/home.toml"
    printf 'enabled\n' >"$SOURCE/dcent/.ssh-enabled"
    printf 'unresolved\n' >"$SOURCE/dcent/dcentrald-hardware-session.unresolved"
    printf '[mining]\nenabled = false\n' >"$SOURCE/dcentrald.toml"
    printf 'BOSMINER_PIC_BOOTSTRAP=0\n' >"$SOURCE/dcentos-compat"
    printf 'export DCENT_AM2_LAB_OVERRIDE=1\n' >"$SOURCE/dcentrald-env"
    printf '#!/bin/sh\nexit 1\n' >"$SOURCE/dcentrald_standalone_boot.sh"
    printf '[mining]\nenabled = false\n' >"$SOURCE/dcentrald.toml.mgmt-bak"

    chmod 751 "$SOURCE/config"
    chmod 640 "$SOURCE/dcentrald.toml"
    touch -t 202401020304 "$SOURCE/config" "$SOURCE/config/.hidden" \
        "$SOURCE/dcentrald.toml"
}

mkdir -p "$WORK_ROOT"

CC=${CC:-cc}
COMMON_CFLAGS=${SEED_ENTROPY_TEST_CFLAGS:-"-std=c99 -O2 -Wall -Wextra -Werror"}
# shellcheck disable=SC2086
$CC $COMMON_CFLAGS -DSEED_ENTROPY_TESTING -o "$SEED_BIN" "$SEED_SOURCE"

# Exercise the production helper's fixed command boundary with the real native
# state machine.  Only this in-process test override changes the implementation.
dcent_persist_seed_entropy_initialize()
{
    "$SEED_BIN" "$@"
}

grep -F -- '--initialize-if-missing-at 9 random-seed' "$HELPER" >/dev/null || {
    printf 'FAIL: persistence helper does not delegate seed creation by directory fd\n' >&2
    exit 1
}
if grep -F '/dev/urandom' "$HELPER" >/dev/null; then
    printf 'FAIL: persistence helper still generates seed bytes in shell\n' >&2
    exit 1
fi

new_fixture complete
mkdir -p "$DESTINATION/keys" "$DESTINATION/config" "$DESTINATION/profiles" \
    "$DESTINATION/dcent" "$DESTINATION/overlay/etc/upper" \
    "$DESTINATION/overlay/etc/work" "$DESTINATION/dcentrald"
printf 'stale\n' >"$DESTINATION/config/stale"
printf 'stale\n' >"$DESTINATION/overlay/etc/upper/stale"
printf 'stale\n' >"$DESTINATION/overlay/etc/work/stale"
printf 'old binary\n' >"$DESTINATION/dcentrald/binary"
printf 'stale unresolved\n' >"$DESTINATION/dcent/dcentrald-hardware-session.unresolved"
printf 'stale crash latch\n' >"$DESTINATION/dcent/dcentrald-hardware-session.crash-latched"
mkdir "$DESTINATION/dcent/.dcentrald-session-latch.lock"
printf 'stale env\n' >"$DESTINATION/dcentrald-env"
printf 'stale launcher\n' >"$DESTINATION/dcentrald_standalone_boot.sh"
printf 'stale fallback\n' >"$DESTINATION/dcentrald.toml.mgmt-bak"

expect_success "stage copies the complete persistent contract" \
    dcent_persist_stage "$SOURCE" "$DESTINATION"
expect_success "read-only verifier accepts the staged contract" \
    dcent_persist_verify "$SOURCE" "$DESTINATION"
expect_success "static network survives slot migration" \
    cmp "$SOURCE/network/static" "$DESTINATION/network/static"
expect_success "first-install recovery custody survives slot migration" \
    cmp "$SOURCE/vendor-first-install/receipt.json" "$DESTINATION/vendor-first-install/receipt.json"
expect_success "complete native OTA rollback custody survives slot migration" \
    sh -c 'cmp "$1" "$2" && [ "$(stat -c %a "$2")" = 600 ]' sh \
        "$SOURCE/dcent/ota-native/update/env.rollback" "$DESTINATION/dcent/ota-native/update/env.rollback"
expect_success "dotfiles survive exact replacement" \
    test -f "$DESTINATION/config/.hidden"
expect_success "symlink targets are preserved without dereference" \
    test "$(readlink "$DESTINATION/config/value-link")" = nested/value
expect_success "directory mode is preserved" \
    test "$(stat -c '%a' "$DESTINATION/config")" = 751
expect_success "file mode is preserved" \
    test "$(stat -c '%a' "$DESTINATION/dcentrald.toml")" = 640
expect_success "file ownership is preserved" \
    test "$(stat -c '%u:%g' "$SOURCE/config/.hidden")" = \
        "$(stat -c '%u:%g' "$DESTINATION/config/.hidden")"
expect_success "directory timestamp is preserved" \
    test "$(stat -c '%Y' "$SOURCE/config")" = "$(stat -c '%Y' "$DESTINATION/config")"
expect_success "critical credential bytes and mode are preserved" \
    sh -c 'cmp -s "$1" "$2" && [ "$(stat -c %a "$2")" = 600 ]' sh \
        "$SOURCE/dcent/auth.json" "$DESTINATION/dcent/auth.json"
expect_success "inactive entropy seed is exactly 512 bytes and mode 0600" \
    sh -c '[ "$(stat -c %s "$1")" = 512 ] && [ "$(stat -c %a "$1")" = 600 ]' sh \
        "$DESTINATION/keys/random-seed"
expect_success "inactive entropy seed is fresh rather than copied" \
    sh -c '! cmp -s "$1" "$2"' sh \
        "$SOURCE/keys/random-seed" "$DESTINATION/keys/random-seed"
expect_success "inactive entropy birth marker has exact metadata and format" \
    sh -c '[ "$(stat -c %s "$1")" = 104 ] && [ "$(stat -c %a "$1")" = 600 ] && LC_ALL=C grep -Eq "^v1 [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12} [0-9a-f]{64}$" "$1" && [ "$(cut -c 41-104 "$1")" = "$(sha256sum "$2" | awk '\''{print $1}'\'')" ]' sh \
        "$DESTINATION/keys/.random-seed.born" \
        "$DESTINATION/keys/random-seed"
expect_success "inactive entropy birth marker records the staging boot" \
    sh -c '[ "$(cat "$1")" = "v1 $2 $(sha256sum "$3" | awk '\''{print $1}'\'')" ]' sh \
        "$DESTINATION/keys/.random-seed.born" "$TEST_BOOT_ID" \
        "$DESTINATION/keys/random-seed"
expect_success "inactive entropy birth marker is not copied from the active slot" \
    sh -c '! cmp -s "$1" "$2"' sh \
        "$SOURCE/keys/.random-seed.born" "$DESTINATION/keys/.random-seed.born"
expect_success "overlay upper is reset" assert_empty_dir "$DESTINATION/overlay/etc/upper"
expect_success "overlay work is reset" assert_empty_dir "$DESTINATION/overlay/etc/work"
expect_success "inactive hot-deploy is removed" assert_absent "$DESTINATION/dcentrald"
expect_success "runtime-derived env marker is reset" assert_absent "$DESTINATION/dcentrald-env"
expect_success "runtime-derived launcher is reset" \
    assert_absent "$DESTINATION/dcentrald_standalone_boot.sh"
expect_success "runtime-derived management fallback is reset" \
    assert_absent "$DESTINATION/dcentrald.toml.mgmt-bak"
expect_success "unresolved hardware-session evidence remains fail-closed across slots" \
    grep -q '^unresolved$' "$DESTINATION/dcent/dcentrald-hardware-session.unresolved"
expect_success "stale crash latch is not resurrected from the inactive slot" \
    assert_absent "$DESTINATION/dcent/dcentrald-hardware-session.crash-latched"
expect_success "stale session admission lock is not resurrected" \
    assert_absent "$DESTINATION/dcent/.dcentrald-session-latch.lock"
expect_success "stale merged content is absent" assert_absent "$DESTINATION/config/stale"

cp "$DESTINATION/keys/random-seed" "$WORK_ROOT/first-inactive-seed"
expect_success "repeated staging rotates the inactive entropy seed again" \
    dcent_persist_stage "$SOURCE" "$DESTINATION"
expect_success "successive inactive seeds are distinct" \
    sh -c '! cmp -s "$1" "$2"' sh \
        "$WORK_ROOT/first-inactive-seed" "$DESTINATION/keys/random-seed"

# A missing or indeterminate CRNG readiness proof must fail before the inactive
# slot is mutated.  Sysupgrade cannot turn unproven random bytes into a seed
# that the next boot will credit.
new_fixture entropy-not-ready
printf 'sentinel\n' >"$DESTINATION/sentinel"
export SEED_ENTROPY_TEST_READINESS=not-ready
expect_failure "staging refuses an uninitialized kernel CRNG" \
    dcent_persist_stage "$SOURCE" "$DESTINATION"
expect_success "CRNG refusal leaves the destination untouched" \
    grep -q '^sentinel$' "$DESTINATION/sentinel"
expect_success "CRNG refusal does not install an inactive seed" \
    assert_absent "$DESTINATION/keys/random-seed"

new_fixture entropy-probe-error
printf 'sentinel\n' >"$DESTINATION/sentinel"
export SEED_ENTROPY_TEST_READINESS=probe-error
expect_failure "staging refuses an indeterminate CRNG probe" \
    dcent_persist_stage "$SOURCE" "$DESTINATION"
expect_success "probe failure leaves the destination untouched" \
    grep -q '^sentinel$' "$DESTINATION/sentinel"

new_fixture entropy-unresolved-source
mv "$SOURCE/keys/random-seed" "$SOURCE/keys/.random-seed.consumed"
printf 'sentinel\n' >"$DESTINATION/sentinel"
expect_failure "staging refuses unresolved active seed lifecycle state" \
    dcent_persist_stage "$SOURCE" "$DESTINATION"
expect_success "unresolved source refusal precedes destination mutation" \
    grep -q '^sentinel$' "$DESTINATION/sentinel"

new_fixture entropy-orphan-birth-marker
rm -f "$SOURCE/keys/random-seed"
printf 'sentinel\n' >"$DESTINATION/sentinel"
expect_failure "staging refuses a source birth marker without its public seed" \
    dcent_persist_stage "$SOURCE" "$DESTINATION"
expect_success "orphan birth-marker refusal precedes destination mutation" \
    grep -q '^sentinel$' "$DESTINATION/sentinel"

new_fixture entropy-malformed-birth-marker
printf 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA' \
    >"$SOURCE/keys/.random-seed.born"
printf 'sentinel\n' >"$DESTINATION/sentinel"
expect_failure "staging refuses a malformed source birth marker" \
    dcent_persist_stage "$SOURCE" "$DESTINATION"
expect_success "malformed birth-marker refusal precedes destination mutation" \
    grep -q '^sentinel$' "$DESTINATION/sentinel"

new_fixture entropy-mismatched-birth-marker
awk 'BEGIN { for (i = 0; i < 256; i++) printf "Z." }' \
    >"$SOURCE/keys/random-seed"
chmod 600 "$SOURCE/keys/random-seed"
printf 'sentinel\n' >"$DESTINATION/sentinel"
expect_failure "staging refuses a birth marker bound to different seed bytes" \
    dcent_persist_stage "$SOURCE" "$DESTINATION"
expect_success "mismatched birth-marker refusal precedes destination mutation" \
    grep -q '^sentinel$' "$DESTINATION/sentinel"

new_fixture entropy-permissive-birth-marker
chmod 644 "$SOURCE/keys/.random-seed.born"
printf 'sentinel\n' >"$DESTINATION/sentinel"
expect_failure "staging refuses a permissive source birth marker" \
    dcent_persist_stage "$SOURCE" "$DESTINATION"
expect_success "permissive birth-marker refusal precedes destination mutation" \
    grep -q '^sentinel$' "$DESTINATION/sentinel"

new_fixture entropy-unresolved-birth-transaction
printf 'partial\n' >"$SOURCE/keys/.random-seed.born.new"
printf 'sentinel\n' >"$DESTINATION/sentinel"
expect_failure "staging refuses an unresolved source birth-marker transaction" \
    dcent_persist_stage "$SOURCE" "$DESTINATION"
expect_success "birth-marker transaction refusal precedes destination mutation" \
    grep -q '^sentinel$' "$DESTINATION/sentinel"

# A hostile inactive overlay symlink is removed as a leaf.  The helper must not
# follow it while clearing upper/work state.
new_fixture overlay-symlink
OUTSIDE=$WORK_ROOT/overlay-symlink/outside
mkdir -p "$OUTSIDE"
printf 'must-survive\n' >"$OUTSIDE/sentinel"
ln -s "$OUTSIDE" "$DESTINATION/overlay"
expect_success "overlay symlink is replaced without traversal" \
    dcent_persist_stage "$SOURCE" "$DESTINATION"
expect_success "overlay symlink target remains untouched" \
    grep -q '^must-survive$' "$OUTSIDE/sentinel"
expect_success "replacement overlay upper is empty" \
    assert_empty_dir "$DESTINATION/overlay/etc/upper"

# Exact replacement is symmetric: absence in the active slot removes stale
# state in the inactive slot rather than resurrecting it after reboot.
rm -rf "$SOURCE/config" "$SOURCE/dcentrald.toml" "$SOURCE/dcentos-compat"
mkdir -p "$DESTINATION/config"
printf 'stale\n' >"$DESTINATION/config/old"
printf 'stale\n' >"$DESTINATION/dcentrald.toml"
printf 'stale\n' >"$DESTINATION/dcentos-compat"
expect_success "a second stage deletes source-absent managed entries" \
    dcent_persist_stage "$SOURCE" "$DESTINATION"
expect_success "source-absent config is deleted" assert_absent "$DESTINATION/config"
expect_success "source-absent runtime config is deleted" assert_absent "$DESTINATION/dcentrald.toml"
expect_success "source-absent compatibility config is deleted" assert_absent "$DESTINATION/dcentos-compat"

# Verification must detect divergence but must never repair it.
printf 'tampered\n' >"$DESTINATION/profiles/home.toml"
expect_failure "verifier detects content divergence" \
    dcent_persist_verify "$SOURCE" "$DESTINATION"
expect_success "failed verification leaves destination bytes untouched" \
    grep -q '^tampered$' "$DESTINATION/profiles/home.toml"
cp -a "$SOURCE/profiles/." "$DESTINATION/profiles/"
chmod 600 "$DESTINATION/profiles/home.toml"
expect_failure "verifier detects mode divergence" \
    dcent_persist_verify "$SOURCE" "$DESTINATION"
chmod "$(stat -c '%a' "$SOURCE/profiles/home.toml")" "$DESTINATION/profiles/home.toml"
printf 'extra\n' >"$DESTINATION/profiles/extra"
expect_failure "verifier detects destination-only tree entries" \
    dcent_persist_verify "$SOURCE" "$DESTINATION"

# Root admission prevents a fixed-name rm -rf from ever being evaluated below
# an ambiguous, recursive, or symlink-substituted root.
expect_failure "filesystem root is refused as source" \
    dcent_persist_stage / "$DESTINATION"
expect_failure "filesystem root is refused as destination" \
    dcent_persist_stage "$SOURCE" /
expect_failure "identical roots are refused" \
    dcent_persist_stage "$SOURCE" "$SOURCE"
mkdir -p "$WORK_ROOT/nested/source/destination"
expect_failure "nested roots are refused" \
    dcent_persist_stage "$WORK_ROOT/nested/source" "$WORK_ROOT/nested/source/destination"
ln -s "$DESTINATION" "$WORK_ROOT/destination-link"
expect_failure "symlink destination roots are refused" \
    dcent_persist_stage "$SOURCE" "$WORK_ROOT/destination-link"

# Credential permission regressions fail before destination mutation.
new_fixture unsafe-auth
printf 'sentinel\n' >"$DESTINATION/sentinel"
chmod 644 "$SOURCE/dcent/auth.json"
expect_failure "world-readable dashboard credentials are refused" \
    dcent_persist_stage "$SOURCE" "$DESTINATION"
expect_success "unsafe auth refusal happens before destination mutation" \
    grep -q '^sentinel$' "$DESTINATION/sentinel"

new_fixture unsafe-host-key
printf 'sentinel\n' >"$DESTINATION/sentinel"
chmod 640 "$SOURCE/keys/dropbear/dropbear_ed25519_host_key"
expect_failure "group-readable SSH host keys are refused" \
    dcent_persist_stage "$SOURCE" "$DESTINATION"
expect_success "unsafe host-key refusal happens before destination mutation" \
    grep -q '^sentinel$' "$DESTINATION/sentinel"

new_fixture unsafe-dcent-dir
printf 'sentinel\n' >"$DESTINATION/sentinel"
chmod 755 "$SOURCE/dcent"
expect_failure "permissive credential directories are refused" \
    dcent_persist_stage "$SOURCE" "$DESTINATION"
expect_success "unsafe directory refusal happens before destination mutation" \
    grep -q '^sentinel$' "$DESTINATION/sentinel"

new_fixture unsafe-shape
printf 'sentinel\n' >"$DESTINATION/sentinel"
rm -rf "$SOURCE/config"
ln -s /tmp "$SOURCE/config"
expect_failure "top-level managed symlinks are refused" \
    dcent_persist_stage "$SOURCE" "$DESTINATION"
expect_success "unsafe shape refusal happens before destination mutation" \
    grep -q '^sentinel$' "$DESTINATION/sentinel"

new_fixture crash-latched-session
rm -f "$SOURCE/dcent/dcentrald-hardware-session.unresolved"
printf 'crash-latched:test\n' \
    >"$SOURCE/dcent/dcentrald-hardware-session.crash-latched"
expect_success "crash-latched hardware evidence is preserved across slots" \
    dcent_persist_stage "$SOURCE" "$DESTINATION"
expect_success "inactive slot retains the exact crash latch" \
    grep -q '^crash-latched:test$' \
        "$DESTINATION/dcent/dcentrald-hardware-session.crash-latched"

expect_failure "stage reports missing arguments" dcent_persist_stage "$SOURCE"
expect_failure "verify reports missing arguments" dcent_persist_verify "$SOURCE"

if [ "$failures" -ne 0 ]; then
    printf '\npersistent-state helper tests failed: %s/%s failed\n' "$failures" "$tests" >&2
    exit 1
fi

printf '\npersistent-state helper tests passed: %s assertions\n' "$tests"
