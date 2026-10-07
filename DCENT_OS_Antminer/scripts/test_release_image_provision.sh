#!/bin/sh
# Adversarial host-side tests for release-image marker provisioning.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/release_image_provision.sh"

TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/dcentos-release-image-test.XXXXXX")
cleanup() {
    chmod -R u+w "$TEST_ROOT" 2>/dev/null || true
    rm -rf "$TEST_ROOT"
}
trap cleanup EXIT HUP INT TERM

# Real production identity and throwaway signing keys, shared by all posture
# fixtures. The caller holds /tmp/dcent-heavy.lock for the small Rust compile.
python3 "$SCRIPT_DIR/test_runtime_image_manifest.py" --fixture-dir "$TEST_ROOT/identity"
BR2_EXTERNAL_DCENTOS_PATH="$SCRIPT_DIR/../br2_external_dcentos"
DCENT_RELEASE_SIGNING_KEY="$TEST_ROOT/identity/test-key.pem"
DCENT_RELEASE_PUBKEY_FILE="$TEST_ROOT/identity/test-pub.pem"
DCENT_RELEASE_CHANNEL=beta
export BR2_EXTERNAL_DCENTOS_PATH DCENT_RELEASE_SIGNING_KEY DCENT_RELEASE_PUBKEY_FILE DCENT_RELEASE_CHANNEL

fail_test() {
    echo "release image provisioning test failed: $*" >&2
    exit 1
}

make_target() {
    _test_target="$1"
    _test_root_hash="$2"
    mkdir -p "${_test_target}/etc/dcentos"
    mkdir -p "${_test_target}/usr/local/bin"
    cp "$TEST_ROOT/identity/daemon" "${_test_target}/usr/local/bin/dcentrald"
    printf 'am1-s9\n' > "${_test_target}/etc/dcentos/board_target"
    printf '1.2.3\n' > "${_test_target}/etc/dcentos-version"
    printf '[mining]\nenabled = false\n' > "${_test_target}/etc/dcentrald.toml"
    printf 'root:%s:20000:0:99999:7:::\n' "$_test_root_hash" > "${_test_target}/etc/shadow"
    printf 'daemon:*:20000:0:99999:7:::\n' >> "${_test_target}/etc/shadow"
    # Buildroot's post-build staging tree may still be 0644; its device table
    # applies the final 0600 mode later under fakeroot.
    chmod 644 "${_test_target}/etc/shadow"
}

provision_dev() {
    DCENT_RELEASE_IMAGE=0 dcent_provision_release_image "$1" test >/dev/null 2>&1
}

provision_release() {
    DCENT_RELEASE_IMAGE=1 dcent_provision_release_image "$1" test >/dev/null 2>&1
}

# WS-A4 (2026-09-01): the DEFAULT posture is RELEASE. These helpers run the
# provisioner with the posture environment fully unset (subshell) and with the
# canonical DCENT_DEV_IMAGE=1 opt-out so the flipped default is pinned
# independently of any CI-exported variables.
provision_default() {
    (
        unset DCENT_RELEASE_IMAGE DCENT_DEV_IMAGE
        dcent_provision_release_image "$1" test
    ) >/dev/null 2>&1
}

provision_dev_alias() {
    (
        unset DCENT_RELEASE_IMAGE
        DCENT_DEV_IMAGE=1 dcent_provision_release_image "$1" test
    ) >/dev/null 2>&1
}

provision_alias_precedence() {
    (
        DCENT_RELEASE_IMAGE=1 DCENT_DEV_IMAGE=1 dcent_provision_release_image "$1" test
    ) >/dev/null 2>&1
}

# --- WS-A4: default posture resolution pins --------------------------------
# (a) DEFAULT build (no posture env) => RELEASE posture: marker stamped on a
#     locked root, refused on an unlocked root.
TARGET="${TEST_ROOT}/default-release"
make_target "$TARGET" '*'
provision_default "$TARGET" || fail_test "default posture (no env) refused a locked release root"
[ -f "${TARGET}/etc/dcentos/release-image" ] || fail_test "default posture did not stamp the release marker"
python3 "$SCRIPT_DIR/runtime_image_manifest.py" verify --rootfs "$TARGET" --board-target am1-s9 --channel beta --version 1.2.3 >/dev/null || fail_test "provisioned runtime metadata did not verify"

TARGET="${TEST_ROOT}/unsigned-release"
make_target "$TARGET" '*'
if (unset DCENT_RELEASE_SIGNING_KEY; provision_release "$TARGET"); then
    fail_test "unsigned release preparation succeeded"
fi
[ ! -e "${TARGET}/etc/dcentos/release-image" ] || fail_test "unsigned release left posture marker"
[ ! -e "${TARGET}/etc/dcentos/runtime-image.json" ] || fail_test "unsigned release left runtime metadata"

TARGET="${TEST_ROOT}/default-unlocked-refused"
make_target "$TARGET" dcentral
if provision_default "$TARGET"; then
    fail_test "default posture stamped a release marker on an unlocked (root:dcentral) shadow"
fi
[ ! -e "${TARGET}/etc/dcentos/release-image" ] || fail_test "default unlocked refusal left a marker"

# (b) explicit DCENT_DEV_IMAGE=1 opt-out => DEV posture (marker removed,
#     rescue SSH preserved) even though nothing else is set.
TARGET="${TEST_ROOT}/dev-alias"
make_target "$TARGET" dcentral
printf 'stale\n' > "${TARGET}/etc/dcentos/release-image"
printf 'lab-rescue\n' > "${TARGET}/etc/dcentos/rescue_ssh_enabled"
printf 'stale\n' > "${TARGET}/etc/dcentos/runtime-image.json"
printf 'stale\n' > "${TARGET}/etc/dcentos/runtime-image.sig"
provision_dev_alias "$TARGET" || fail_test "DCENT_DEV_IMAGE=1 opt-out was rejected"
[ ! -e "${TARGET}/etc/dcentos/release-image" ] || fail_test "DCENT_DEV_IMAGE=1 dev marker survived"
[ ! -e "${TARGET}/etc/dcentos/runtime-image.json" ] || fail_test "dev image inherited signed runtime metadata"
[ ! -e "${TARGET}/etc/dcentos/runtime-image.sig" ] || fail_test "dev image inherited runtime signature"
[ -f "${TARGET}/etc/dcentos/rescue_ssh_enabled" ] || fail_test "DCENT_DEV_IMAGE=1 stripped the lab rescue SSH marker"

# (c) an explicit DCENT_RELEASE_IMAGE=1 beats the DCENT_DEV_IMAGE alias
#     (fail-safe: the stricter posture wins on conflict).
TARGET="${TEST_ROOT}/alias-precedence"
make_target "$TARGET" '*'
if provision_alias_precedence "$TARGET"; then
    [ -f "${TARGET}/etc/dcentos/release-image" ] || fail_test "explicit RELEASE_IMAGE=1 lost to the DCENT_DEV_IMAGE alias"
else
    fail_test "explicit RELEASE_IMAGE=1 + DCENT_DEV_IMAGE=1 alias refused a locked release root"
fi

# --- WS-A4: canonical resolver / inline fallback byte-sync pin -------------
# release_image_provision.sh carries an inline fallback copy of the canonical
# resolver (for contexts where release_posture.sh cannot be located). The two
# MUST stay identical so the RELEASE default cannot drift between them; the
# functional cases above pin the semantics, this pins the copy.
_extract_posture_fn() {
    sed -n '/^dcent_release_posture_is_release() {/,/^}/p' "$1"
}
_posture_canon="$(_extract_posture_fn "$SCRIPT_DIR/lib/release_posture.sh")"
_posture_fallback="$(_extract_posture_fn "$SCRIPT_DIR/lib/release_image_provision.sh")"
[ -n "$_posture_canon" ] || fail_test "cannot extract canonical posture resolver"
[ "$_posture_canon" = "$_posture_fallback" ] || fail_test "release_image_provision.sh inline posture fallback drifted from release_posture.sh"


TARGET="${TEST_ROOT}/dev-regular"
make_target "$TARGET" dcentral
printf 'stale\n' > "${TARGET}/etc/dcentos/release-image"
printf 'lab-rescue\n' > "${TARGET}/etc/dcentos/rescue_ssh_enabled"
provision_dev "$TARGET" || fail_test "dev build rejected removable regular marker"
[ ! -e "${TARGET}/etc/dcentos/release-image" ] || fail_test "dev marker survived"
[ -f "${TARGET}/etc/dcentos/rescue_ssh_enabled" ] || fail_test "DEV lab rescue SSH marker was stripped"

TARGET="${TEST_ROOT}/dev-directory"
make_target "$TARGET" dcentral
mkdir "${TARGET}/etc/dcentos/release-image"
printf 'preserve-dev-directory\n' > "${TARGET}/etc/dcentos/release-image/sentinel"
provision_dev "$TARGET" || fail_test "dev build rejected a quarantinable marker directory"
[ ! -e "${TARGET}/etc/dcentos/release-image" ] || fail_test "dev marker directory retained its runtime name"
set -- "${TARGET}/etc/dcentos"/.release-image.rejected.*
[ "$#" -eq 1 ] && [ -d "$1" ] || fail_test "dev marker directory was not quarantined"
[ "$(cat "$1/sentinel")" = preserve-dev-directory ] || fail_test "dev marker quarantine lost contents"

TARGET="${TEST_ROOT}/dev-symlink"
make_target "$TARGET" dcentral
VICTIM="${TEST_ROOT}/dev-symlink-victim"
printf 'important-dev-bytes\n' > "$VICTIM"
ln -s "$VICTIM" "${TARGET}/etc/dcentos/release-image"
provision_dev "$TARGET" || fail_test "dev build rejected removable marker symlink"
[ "$(cat "$VICTIM")" = important-dev-bytes ] || fail_test "dev marker symlink target changed"

TARGET="${TEST_ROOT}/unlocked-release"
make_target "$TARGET" dcentral
printf 'stale-release-claim\n' > "${TARGET}/etc/dcentos/release-image"
if provision_release "$TARGET"; then
    fail_test "release marker was stamped with an unlocked root account"
fi
[ ! -e "${TARGET}/etc/dcentos/release-image" ] || fail_test "unlocked release retained a stale marker"

TARGET="${TEST_ROOT}/duplicate-root"
make_target "$TARGET" '*'
printf 'root:*:20000:0:99999:7:::\n' >> "${TARGET}/etc/shadow"
if provision_release "$TARGET"; then
    fail_test "release accepted duplicate root shadow entries"
fi

TARGET="${TEST_ROOT}/shadow-symlink"
make_target "$TARGET" '*'
SHADOW_VICTIM="${TEST_ROOT}/shadow-victim"
cp "${TARGET}/etc/shadow" "$SHADOW_VICTIM"
rm "${TARGET}/etc/shadow"
ln -s "$SHADOW_VICTIM" "${TARGET}/etc/shadow"
if provision_release "$TARGET"; then
    fail_test "release accepted a symlinked shadow database"
fi
[ ! -e "${TARGET}/etc/dcentos/release-image" ] || fail_test "shadow symlink failure left a marker"

TARGET="${TEST_ROOT}/shadow-writable-mode"
make_target "$TARGET" '*'
chmod 666 "${TARGET}/etc/shadow"
if provision_release "$TARGET"; then
    fail_test "release accepted a group/world-writable shadow database"
fi
[ ! -e "${TARGET}/etc/dcentos/release-image" ] || fail_test "unsafe shadow mode failure left a marker"

TARGET="${TEST_ROOT}/locked-release"
make_target "$TARGET" '*'
printf 'grace\n' > "${TARGET}/etc/dcentos/first-boot-grace"
printf 'am3-bb-s19jpro rescue SSH enabled for lab bring-up\n' > "${TARGET}/etc/dcentos/rescue_ssh_enabled"
provision_release "$TARGET" || fail_test "locked release was rejected"
[ ! -e "${TARGET}/etc/dcentos/first-boot-grace" ] || fail_test "grace marker survived"
[ ! -e "${TARGET}/etc/dcentos/rescue_ssh_enabled" ] || fail_test "AM3-BB rescue SSH marker survived RELEASE provision"
[ -f "${TARGET}/etc/dcentos/release-image" ] || fail_test "release marker is absent"
[ ! -L "${TARGET}/etc/dcentos/release-image" ] || fail_test "release marker is a symlink"
[ "$(stat -c '%h' "${TARGET}/etc/dcentos/release-image")" = 1 ] || fail_test "release marker is multiply linked"
[ "$(stat -c '%a' "${TARGET}/etc/dcentos/release-image")" = 644 ] || fail_test "release marker mode is not 0644"

TARGET="${TEST_ROOT}/release-symlink"
make_target "$TARGET" '!'
VICTIM="${TEST_ROOT}/release-symlink-victim"
printf 'important-release-bytes\n' > "$VICTIM"
ln -s "$VICTIM" "${TARGET}/etc/dcentos/release-image"
provision_release "$TARGET" || fail_test "release rejected a safely replaceable marker symlink"
[ "$(cat "$VICTIM")" = important-release-bytes ] || fail_test "release marker symlink target changed"
[ ! -L "${TARGET}/etc/dcentos/release-image" ] || fail_test "release marker remained a symlink"

TARGET="${TEST_ROOT}/release-hardlink"
make_target "$TARGET" '*LOCKED*'
VICTIM="${TEST_ROOT}/release-hardlink-victim"
printf 'important-hardlink-bytes\n' > "$VICTIM"
ln "$VICTIM" "${TARGET}/etc/dcentos/release-image"
provision_release "$TARGET" || fail_test "release rejected a safely replaceable marker hardlink"
[ "$(cat "$VICTIM")" = important-hardlink-bytes ] || fail_test "release marker hardlink target changed"
[ "$(stat -c '%h' "$VICTIM")" = 1 ] || fail_test "release marker hardlink was retained"

TARGET="${TEST_ROOT}/grace-directory"
make_target "$TARGET" '*'
mkdir "${TARGET}/etc/dcentos/first-boot-grace"
printf 'preserve-grace-directory\n' > "${TARGET}/etc/dcentos/first-boot-grace/sentinel"
provision_release "$TARGET" || fail_test "release rejected a quarantinable grace directory"
[ ! -e "${TARGET}/etc/dcentos/first-boot-grace" ] || fail_test "grace directory retained its runtime name"
[ -f "${TARGET}/etc/dcentos/release-image" ] || fail_test "quarantined grace prevented release marker publication"
set -- "${TARGET}/etc/dcentos"/.first-boot-grace.rejected.*
[ "$#" -eq 1 ] && [ -d "$1" ] || fail_test "grace directory was not quarantined"
[ "$(cat "$1/sentinel")" = preserve-grace-directory ] || fail_test "grace quarantine lost contents"

TARGET="${TEST_ROOT}/marker-directory"
make_target "$TARGET" '*'
mkdir "${TARGET}/etc/dcentos/release-image"
printf 'preserve-marker-directory\n' > "${TARGET}/etc/dcentos/release-image/sentinel"
provision_release "$TARGET" || fail_test "release rejected a quarantinable marker directory"
[ -f "${TARGET}/etc/dcentos/release-image" ] || fail_test "release marker did not replace the retired directory name"
[ ! -L "${TARGET}/etc/dcentos/release-image" ] || fail_test "release marker replaced a directory with a symlink"
set -- "${TARGET}/etc/dcentos"/.release-image.rejected.*
[ "$#" -eq 1 ] && [ -d "$1" ] || fail_test "prior marker directory was not quarantined"
[ "$(cat "$1/sentinel")" = preserve-marker-directory ] || fail_test "marker quarantine lost contents"

TARGET="${TEST_ROOT}/config-symlink"
make_target "$TARGET" '*'
OUTSIDE="${TEST_ROOT}/outside-config"
mkdir "$OUTSIDE"
rm "${TARGET}/etc/dcentos/board_target"
rmdir "${TARGET}/etc/dcentos"
ln -s "$OUTSIDE" "${TARGET}/etc/dcentos"
if provision_release "$TARGET"; then
    fail_test "release accepted a symlinked /etc/dcentos"
fi
[ ! -e "${OUTSIDE}/release-image" ] || fail_test "marker escaped through config symlink"

TARGET="${TEST_ROOT}/marker-write-failure"
make_target "$TARGET" '*'
cat() {
    return 1
}
if provision_release "$TARGET"; then
    fail_test "release ignored a marker write failure"
fi
unset -f cat
[ ! -e "${TARGET}/etc/dcentos/release-image" ] || fail_test "marker write failure left a marker"

TARGET="${TEST_ROOT}/marker-verification-failure"
make_target "$TARGET" '*'
stat() {
    for _test_stat_arg do
        case "$_test_stat_arg" in
            */etc/dcentos/release-image) return 1 ;;
        esac
    done
    command stat "$@"
}
if provision_release "$TARGET"; then
    fail_test "release ignored a published marker verification failure"
fi
unset -f stat
[ ! -e "${TARGET}/etc/dcentos/release-image" ] || fail_test "marker verification failure left a runtime claim"

TARGET="${TEST_ROOT}/shadow-publication-race"
make_target "$TARGET" '*'
mv() {
    _test_mv_last=
    for _test_mv_arg do
        _test_mv_last=$_test_mv_arg
    done
    command mv "$@" || return 1
    if [ "$_test_mv_last" = "${TARGET}/etc/dcentos/release-image" ]; then
        printf 'root:dcentral:20000:0:99999:7:::\n' > "${TARGET}/etc/shadow.replacement"
        printf 'daemon:*:20000:0:99999:7:::\n' >> "${TARGET}/etc/shadow.replacement"
        command mv -f "${TARGET}/etc/shadow.replacement" "${TARGET}/etc/shadow"
    fi
}
if provision_release "$TARGET"; then
    fail_test "release ignored /etc/shadow replacement during marker publication"
fi
unset -f mv
grep -F 'root:dcentral:' "${TARGET}/etc/shadow" >/dev/null || fail_test "shadow race injection did not run"
[ ! -e "${TARGET}/etc/dcentos/release-image" ] || fail_test "shadow replacement race left a runtime claim"
[ ! -e "${TARGET}/etc/dcentos/runtime-image.json" ] || fail_test "shadow replacement race left signed runtime claim"

TARGET="${TEST_ROOT}/shadow-hardlink-open-race"
make_target "$TARGET" '*'
dcent_release_stat_signature() {
    if [ "$1" = "${TARGET}/etc/shadow" ] && [ ! -e "${TARGET}/hardlink-race-injected" ]; then
        cp "$1" "${TARGET}/etc/shadow.alias"
        rm "$1"
        ln "${TARGET}/etc/shadow.alias" "$1"
        : > "${TARGET}/hardlink-race-injected"
    fi
    command stat -c '%d:%i:%h:%s:%f:%y:%z' "$1" 2>/dev/null
}
if provision_release "$TARGET"; then
    fail_test "release accepted a hardlink introduced at the authoritative shadow open"
fi
[ -e "${TARGET}/hardlink-race-injected" ] || fail_test "shadow hardlink race injection did not run"
[ "$(stat -c '%h' "${TARGET}/etc/shadow")" = 2 ] || fail_test "shadow hardlink race did not produce two names"
[ ! -e "${TARGET}/etc/dcentos/release-image" ] || fail_test "shadow hardlink race left a runtime claim"

echo "release image provisioning tests passed"
