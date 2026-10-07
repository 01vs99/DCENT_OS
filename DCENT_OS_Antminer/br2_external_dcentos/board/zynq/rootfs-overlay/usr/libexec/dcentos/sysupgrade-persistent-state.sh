#!/bin/sh
# Copy the complete persistent-state contract between two already-mounted
# rootfs_data trees.  This helper deliberately owns no mount, UBI, boot-env,
# firmware, sync, or reboot operations; sysupgrade callers retain those duties.
#
# Public API (all functions return nonzero on every refused/incomplete state):
#   dcent_persist_preflight SOURCE_ROOT
#   dcent_persist_stage  SOURCE_ROOT DESTINATION_ROOT
#   dcent_persist_verify SOURCE_ROOT DESTINATION_ROOT
#
# `keys/random-seed` and `keys/.random-seed.born` form one semantic pair rather
# than byte-for-byte state.  Every inactive slot receives a new 512-byte seed
# and matching boot-epoch marker through seed-entropy's CRNG-readiness and
# atomic-install boundary.  Runtime-derived launcher state is reset as one unit
# so a stale marker can never outlive its matching baked binary, launcher, or
# management fallback.

dcent_persist_fail()
{
    printf '%s\n' "persistent-state: ERROR: $*" >&2
    return 1
}

# Keep the production command immutable.  Offline tests replace this shell
# function after sourcing the helper; deployed callers cannot redirect it with
# an inherited environment variable or PATH entry.
dcent_persist_seed_entropy_initialize()
{
    /usr/sbin/seed-entropy "$@"
}

dcent_persist_path_exists()
{
    [ -e "$1" ] || [ -L "$1" ]
}

dcent_persist_validate_roots()
{
    _dcent_source=$1
    _dcent_destination=$2

    case "$_dcent_source" in
        /*) ;;
        *) dcent_persist_fail "source root must be an absolute path"; return 1 ;;
    esac
    case "$_dcent_destination" in
        /*) ;;
        *) dcent_persist_fail "destination root must be an absolute path"; return 1 ;;
    esac

    [ -d "$_dcent_source" ] && [ ! -L "$_dcent_source" ] || {
        dcent_persist_fail "source root is not a real directory: $_dcent_source"
        return 1
    }
    [ -d "$_dcent_destination" ] && [ ! -L "$_dcent_destination" ] || {
        dcent_persist_fail "destination root is not a real directory: $_dcent_destination"
        return 1
    }

    _dcent_source_real=$(CDPATH= cd -P "$_dcent_source" 2>/dev/null && pwd -P) || {
        dcent_persist_fail "cannot resolve source root: $_dcent_source"
        return 1
    }
    _dcent_destination_real=$(CDPATH= cd -P "$_dcent_destination" 2>/dev/null && pwd -P) || {
        dcent_persist_fail "cannot resolve destination root: $_dcent_destination"
        return 1
    }

    [ "$_dcent_source_real" != / ] || {
        dcent_persist_fail "refusing filesystem root as source"
        return 1
    }
    [ "$_dcent_destination_real" != / ] || {
        dcent_persist_fail "refusing filesystem root as destination"
        return 1
    }
    [ "$_dcent_source_real" != "$_dcent_destination_real" ] || {
        dcent_persist_fail "source and destination roots are identical"
        return 1
    }

    case "$_dcent_source_real/" in
        "$_dcent_destination_real/"*)
            dcent_persist_fail "source root is nested below destination root"
            return 1
            ;;
    esac
    case "$_dcent_destination_real/" in
        "$_dcent_source_real/"*)
            dcent_persist_fail "destination root is nested below source root"
            return 1
            ;;
    esac

    return 0
}

dcent_persist_require_directory_or_absent()
{
    _dcent_path=$1
    _dcent_label=$2
    dcent_persist_path_exists "$_dcent_path" || return 0
    [ -d "$_dcent_path" ] && [ ! -L "$_dcent_path" ] || {
        dcent_persist_fail "$_dcent_label must be a non-symlink directory"
        return 1
    }
    return 0
}

dcent_persist_require_file_or_absent()
{
    _dcent_path=$1
    _dcent_label=$2
    dcent_persist_path_exists "$_dcent_path" || return 0
    [ -f "$_dcent_path" ] && [ ! -L "$_dcent_path" ] || {
        dcent_persist_fail "$_dcent_label must be a non-symlink regular file"
        return 1
    }
    return 0
}

dcent_persist_require_mode()
{
    _dcent_path=$1
    _dcent_expected=$2
    _dcent_label=$3
    dcent_persist_path_exists "$_dcent_path" || return 0
    [ ! -L "$_dcent_path" ] || {
        dcent_persist_fail "$_dcent_label must not be a symlink"
        return 1
    }
    _dcent_mode=$(stat -c '%a' "$_dcent_path" 2>/dev/null) || {
        dcent_persist_fail "cannot inspect mode for $_dcent_label"
        return 1
    }
    [ "$_dcent_mode" = "$_dcent_expected" ] || {
        dcent_persist_fail "unsafe mode $_dcent_mode for $_dcent_label (expected $_dcent_expected)"
        return 1
    }
    return 0
}

dcent_persist_require_entropy_birth_marker()
{
    _dcent_path=$1
    _dcent_seed=$2
    _dcent_label=$3

    dcent_persist_require_file_or_absent "$_dcent_path" "$_dcent_label" || return 1
    dcent_persist_path_exists "$_dcent_path" || {
        dcent_persist_fail "$_dcent_label is missing"
        return 1
    }
    dcent_persist_require_mode "$_dcent_path" 600 "$_dcent_label" || return 1

    _dcent_size=$(stat -c '%s' "$_dcent_path" 2>/dev/null) || {
        dcent_persist_fail "cannot inspect size for $_dcent_label"
        return 1
    }
    [ "$_dcent_size" = 104 ] || {
        dcent_persist_fail "$_dcent_label is $_dcent_size bytes (expected 104)"
        return 1
    }

    _dcent_owner=$(stat -c '%u:%g' "$_dcent_path" 2>/dev/null) || {
        dcent_persist_fail "cannot inspect ownership for $_dcent_label"
        return 1
    }
    _dcent_expected_owner=$(id -u 2>/dev/null):$(id -g 2>/dev/null) || {
        dcent_persist_fail "cannot resolve persistent-state helper identity"
        return 1
    }
    [ "$_dcent_owner" = "$_dcent_expected_owner" ] || {
        dcent_persist_fail "$_dcent_label is owned by $_dcent_owner (expected $_dcent_expected_owner)"
        return 1
    }

    LC_ALL=C grep -Eq \
        '^v1 [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12} [0-9a-f]{64}$' \
        "$_dcent_path" || {
        dcent_persist_fail "$_dcent_label has an invalid boot identifier or seed digest"
        return 1
    }
    command -v sha256sum >/dev/null 2>&1 || {
        dcent_persist_fail "sha256sum is unavailable for $_dcent_label validation"
        return 1
    }
    _dcent_recorded_digest=$(cut -c 41-104 "$_dcent_path" 2>/dev/null) || {
        dcent_persist_fail "cannot read seed digest from $_dcent_label"
        return 1
    }
    _dcent_seed_digest=$(sha256sum "$_dcent_seed" 2>/dev/null | awk '{print $1}') || {
        dcent_persist_fail "cannot hash the seed bound to $_dcent_label"
        return 1
    }
    [ "$_dcent_recorded_digest" = "$_dcent_seed_digest" ] || {
        dcent_persist_fail "$_dcent_label does not match its seed payload"
        return 1
    }
    return 0
}

dcent_persist_validate_source()
{
    _dcent_source=$1

    dcent_persist_require_directory_or_absent \
        "$_dcent_source/keys" "source keys" || return 1
    [ -d "$_dcent_source/keys" ] || {
        dcent_persist_fail "source keys directory is required for entropy-seed rotation"
        return 1
    }
    for _dcent_name in config profiles dcent network vendor-first-install; do
        dcent_persist_require_directory_or_absent \
            "$_dcent_source/$_dcent_name" "source $_dcent_name" || return 1
    done
    for _dcent_name in dcentrald.toml dcentos-compat; do
        dcent_persist_require_file_or_absent \
            "$_dcent_source/$_dcent_name" "source $_dcent_name" || return 1
    done

    if [ -d "$_dcent_source/dcent" ]; then
        dcent_persist_require_mode "$_dcent_source/dcent" 700 "source dcent directory" || return 1
        dcent_persist_require_file_or_absent "$_dcent_source/dcent/auth.json" \
            "source dashboard credential" || return 1
        dcent_persist_require_mode "$_dcent_source/dcent/auth.json" 600 \
            "source dashboard credential" || return 1
        dcent_persist_require_file_or_absent "$_dcent_source/dcent/authorized_keys" \
            "source dashboard SSH authorized_keys" || return 1
        dcent_persist_require_mode "$_dcent_source/dcent/authorized_keys" 600 \
            "source dashboard SSH authorized_keys" || return 1
    fi

    if dcent_persist_path_exists "$_dcent_source/keys/dropbear"; then
        dcent_persist_require_directory_or_absent "$_dcent_source/keys/dropbear" \
            "source persistent SSH key directory" || return 1
        dcent_persist_require_file_or_absent "$_dcent_source/keys/dropbear/authorized_keys" \
            "source persistent SSH authorized_keys" || return 1
        dcent_persist_require_mode "$_dcent_source/keys/dropbear/authorized_keys" 600 \
            "source persistent SSH authorized_keys" || return 1
        for _dcent_key in "$_dcent_source"/keys/dropbear/dropbear_*_host_key; do
            dcent_persist_path_exists "$_dcent_key" || continue
            dcent_persist_require_file_or_absent "$_dcent_key" "source SSH host key" || return 1
            dcent_persist_require_mode "$_dcent_key" 600 "source SSH host key" || return 1
        done
    fi
    dcent_persist_require_file_or_absent "$_dcent_source/keys/random-seed" \
        "source entropy seed" || return 1
    if dcent_persist_path_exists "$_dcent_source/keys/.random-seed.born"; then
        dcent_persist_path_exists "$_dcent_source/keys/random-seed" || {
            dcent_persist_fail "source entropy birth marker exists without its public seed"
            return 1
        }
        dcent_persist_require_entropy_birth_marker \
            "$_dcent_source/keys/.random-seed.born" \
            "$_dcent_source/keys/random-seed" \
            "source entropy birth marker" || return 1
    fi
    for _dcent_name in .random-seed.consumed .random-seed.credited \
        .random-seed.new .random-seed.born.new; do
        if dcent_persist_path_exists "$_dcent_source/keys/$_dcent_name"; then
            dcent_persist_fail "source entropy lifecycle is unresolved: $_dcent_name"
            return 1
        fi
    done

    return 0
}

# Validate every active persistent-state input before callers mutate the
# inactive slot. Operate on the resolved root so an ancestor symlink cannot
# redirect later reads through the caller-provided spelling.
dcent_persist_preflight()
(
    [ "$#" -eq 1 ] || {
        dcent_persist_fail "dcent_persist_preflight requires SOURCE_ROOT"
        return 1
    }
    _dcent_source=$1
    case "$_dcent_source" in
        /*) ;;
        *) dcent_persist_fail "source root must be an absolute path"; return 1 ;;
    esac
    [ -d "$_dcent_source" ] && [ ! -L "$_dcent_source" ] || {
        dcent_persist_fail "source root is not a real directory: $_dcent_source"
        return 1
    }
    _dcent_source_real=$(CDPATH= cd -P "$_dcent_source" 2>/dev/null && pwd -P) || {
        dcent_persist_fail "cannot resolve source root: $_dcent_source"
        return 1
    }
    [ "$_dcent_source_real" != / ] || {
        dcent_persist_fail "refusing filesystem root as source"
        return 1
    }
    dcent_persist_validate_source "$_dcent_source_real"
)

# Compare one managed entry without writing either root.  Sorted path inventories
# avoid depending on filesystem-specific directory enumeration order.  Every
# node then has its type, mode, uid/gid, mtime, and link count checked; regular
# file bytes and symlink targets are compared separately.  Newlines in names
# fail closed because their split inventory rows cannot be inspected as paths.
dcent_persist_entry_matches()
(
    _dcent_source=$1
    _dcent_destination=$2
    _dcent_name=$3
    _dcent_scratch=/tmp/dcent-persist-verify.$$

    umask 077
    mkdir "$_dcent_scratch" 2>/dev/null || {
        dcent_persist_fail "cannot create verification scratch directory"
        return 1
    }

    if ! (CDPATH= cd "$_dcent_source" && find "$_dcent_name" -print) \
        >"$_dcent_scratch/source.unsorted" 2>/dev/null; then
        rm -rf "$_dcent_scratch"
        dcent_persist_fail "cannot inventory source $_dcent_name"
        return 1
    fi
    if ! (CDPATH= cd "$_dcent_destination" && find "$_dcent_name" -print) \
        >"$_dcent_scratch/destination.unsorted" 2>/dev/null; then
        rm -rf "$_dcent_scratch"
        dcent_persist_fail "cannot inventory destination $_dcent_name"
        return 1
    fi
    if [ "$_dcent_name" = keys ]; then
        if ! awk '$0 != "keys/random-seed" && $0 != "keys/.random-seed.born"' \
            "$_dcent_scratch/source.unsorted" >"$_dcent_scratch/source.semantic" || \
           ! awk '$0 != "keys/random-seed" && $0 != "keys/.random-seed.born"' \
            "$_dcent_scratch/destination.unsorted" >"$_dcent_scratch/destination.semantic"; then
            rm -rf "$_dcent_scratch"
            dcent_persist_fail "cannot build semantic entropy-seed inventories"
            return 1
        fi
        if ! mv "$_dcent_scratch/source.semantic" \
            "$_dcent_scratch/source.unsorted" || \
           ! mv "$_dcent_scratch/destination.semantic" \
            "$_dcent_scratch/destination.unsorted"; then
            rm -rf "$_dcent_scratch"
            dcent_persist_fail "cannot install semantic entropy-seed inventories"
            return 1
        fi
    fi
    if ! LC_ALL=C sort "$_dcent_scratch/source.unsorted" >"$_dcent_scratch/source.list" || \
        ! LC_ALL=C sort "$_dcent_scratch/destination.unsorted" >"$_dcent_scratch/destination.list"; then
        rm -rf "$_dcent_scratch"
        dcent_persist_fail "cannot sort inventories for $_dcent_name"
        return 1
    fi
    if ! cmp -s "$_dcent_scratch/source.list" "$_dcent_scratch/destination.list"; then
        rm -rf "$_dcent_scratch"
        dcent_persist_fail "destination $_dcent_name path inventory differs from source"
        return 1
    fi

    while IFS= read -r _dcent_relative; do
        _dcent_source_path=$_dcent_source/$_dcent_relative
        _dcent_destination_path=$_dcent_destination/$_dcent_relative

        if [ -L "$_dcent_source_path" ]; then
            _dcent_source_type=symlink
        elif [ -f "$_dcent_source_path" ]; then
            _dcent_source_type=file
        elif [ -d "$_dcent_source_path" ]; then
            _dcent_source_type=directory
        else
            rm -rf "$_dcent_scratch"
            dcent_persist_fail "unsupported source node in $_dcent_name: $_dcent_relative"
            return 1
        fi

        if [ -L "$_dcent_destination_path" ]; then
            _dcent_destination_type=symlink
        elif [ -f "$_dcent_destination_path" ]; then
            _dcent_destination_type=file
        elif [ -d "$_dcent_destination_path" ]; then
            _dcent_destination_type=directory
        else
            rm -rf "$_dcent_scratch"
            dcent_persist_fail "unsupported destination node in $_dcent_name: $_dcent_relative"
            return 1
        fi
        if [ "$_dcent_source_type" != "$_dcent_destination_type" ]; then
            rm -rf "$_dcent_scratch"
            dcent_persist_fail "node type differs for $_dcent_relative"
            return 1
        fi

        _dcent_source_metadata=$(stat -c '%a:%u:%g:%Y:%h' "$_dcent_source_path" 2>/dev/null) || {
            rm -rf "$_dcent_scratch"
            dcent_persist_fail "cannot inspect source metadata for $_dcent_relative"
            return 1
        }
        _dcent_destination_metadata=$(stat -c '%a:%u:%g:%Y:%h' \
            "$_dcent_destination_path" 2>/dev/null) || {
            rm -rf "$_dcent_scratch"
            dcent_persist_fail "cannot inspect destination metadata for $_dcent_relative"
            return 1
        }
        if [ "$_dcent_source_metadata" != "$_dcent_destination_metadata" ]; then
            rm -rf "$_dcent_scratch"
            dcent_persist_fail "metadata differs for $_dcent_relative"
            return 1
        fi

        case "$_dcent_source_type" in
            file)
                if ! cmp -s "$_dcent_source_path" "$_dcent_destination_path"; then
                    rm -rf "$_dcent_scratch"
                    dcent_persist_fail "file bytes differ for $_dcent_relative"
                    return 1
                fi
                ;;
            symlink)
                _dcent_source_link=$(readlink "$_dcent_source_path" 2>/dev/null) || {
                    rm -rf "$_dcent_scratch"
                    dcent_persist_fail "cannot read source symlink $_dcent_relative"
                    return 1
                }
                _dcent_destination_link=$(readlink "$_dcent_destination_path" 2>/dev/null) || {
                    rm -rf "$_dcent_scratch"
                    dcent_persist_fail "cannot read destination symlink $_dcent_relative"
                    return 1
                }
                if [ "$_dcent_source_link" != "$_dcent_destination_link" ]; then
                    rm -rf "$_dcent_scratch"
                    dcent_persist_fail "symlink target differs for $_dcent_relative"
                    return 1
                fi
                ;;
        esac
    done <"$_dcent_scratch/source.list"

    rm -rf "$_dcent_scratch" || {
        dcent_persist_fail "cannot remove verification scratch directory"
        return 1
    }
    return 0
)

dcent_persist_directory_is_empty()
{
    _dcent_path=$1
    [ -d "$_dcent_path" ] && [ ! -L "$_dcent_path" ] || return 1
    _dcent_first=$(find "$_dcent_path" -mindepth 1 -print -quit 2>/dev/null) || return 1
    [ -z "$_dcent_first" ]
}

dcent_persist_verify_entropy_seed()
{
    _dcent_source=$1
    _dcent_destination=$2
    _dcent_seed=$_dcent_destination/keys/random-seed
    _dcent_birth=$_dcent_destination/keys/.random-seed.born

    dcent_persist_require_file_or_absent "$_dcent_seed" \
        "destination entropy seed" || return 1
    dcent_persist_path_exists "$_dcent_seed" || {
        dcent_persist_fail "destination entropy seed is missing"
        return 1
    }
    dcent_persist_require_mode "$_dcent_seed" 600 \
        "destination entropy seed" || return 1
    _dcent_seed_size=$(stat -c '%s' "$_dcent_seed" 2>/dev/null) || {
        dcent_persist_fail "cannot inspect destination entropy-seed size"
        return 1
    }
    [ "$_dcent_seed_size" = 512 ] || {
        dcent_persist_fail "destination entropy seed is $_dcent_seed_size bytes (expected 512)"
        return 1
    }
    _dcent_seed_owner=$(stat -c '%u:%g' "$_dcent_seed" 2>/dev/null) || {
        dcent_persist_fail "cannot inspect destination entropy-seed ownership"
        return 1
    }
    _dcent_expected_owner=$(id -u 2>/dev/null):$(id -g 2>/dev/null) || {
        dcent_persist_fail "cannot resolve persistent-state helper identity"
        return 1
    }
    [ "$_dcent_seed_owner" = "$_dcent_expected_owner" ] || {
        dcent_persist_fail "destination entropy seed is owned by $_dcent_seed_owner (expected $_dcent_expected_owner)"
        return 1
    }
    if dcent_persist_path_exists "$_dcent_source/keys/random-seed" && \
        cmp -s "$_dcent_source/keys/random-seed" "$_dcent_seed"; then
        dcent_persist_fail "destination entropy seed was reused from the active slot"
        return 1
    fi
    dcent_persist_require_entropy_birth_marker "$_dcent_birth" \
        "$_dcent_seed" \
        "destination entropy birth marker" || return 1
    return 0
}

# Verification is intentionally read-only with respect to both roots.
dcent_persist_verify()
(
    [ "$#" -eq 2 ] || {
        dcent_persist_fail "dcent_persist_verify requires SOURCE_ROOT DESTINATION_ROOT"
        return 1
    }
    _dcent_source=$1
    _dcent_destination=$2

    dcent_persist_validate_roots "$_dcent_source" "$_dcent_destination" || return 1
    _dcent_source=$_dcent_source_real
    _dcent_destination=$_dcent_destination_real
    dcent_persist_validate_source "$_dcent_source" || return 1

    for _dcent_name in keys config profiles dcent network vendor-first-install dcentrald.toml dcentos-compat; do
        _dcent_source_path=$_dcent_source/$_dcent_name
        _dcent_destination_path=$_dcent_destination/$_dcent_name
        if dcent_persist_path_exists "$_dcent_source_path"; then
            dcent_persist_path_exists "$_dcent_destination_path" || {
                dcent_persist_fail "destination $_dcent_name is missing"
                return 1
            }
            dcent_persist_entry_matches \
                "$_dcent_source" "$_dcent_destination" "$_dcent_name" || return 1
        elif dcent_persist_path_exists "$_dcent_destination_path"; then
            dcent_persist_fail "stale destination $_dcent_name exists without a source"
            return 1
        fi
    done
    dcent_persist_verify_entropy_seed \
        "$_dcent_source" "$_dcent_destination" || return 1

    dcent_persist_directory_is_empty "$_dcent_destination/overlay/etc/upper" || {
        dcent_persist_fail "destination overlay/etc/upper is absent, unsafe, or nonempty"
        return 1
    }
    dcent_persist_directory_is_empty "$_dcent_destination/overlay/etc/work" || {
        dcent_persist_fail "destination overlay/etc/work is absent, unsafe, or nonempty"
        return 1
    }
    for _dcent_name in dcentrald dcentrald-env \
        dcentrald_standalone_boot.sh dcentrald.toml.mgmt-bak; do
        if dcent_persist_path_exists "$_dcent_destination/$_dcent_name"; then
            dcent_persist_fail "inactive runtime-derived state still exists: $_dcent_name"
            return 1
        fi
    done

    return 0
)

dcent_persist_prepare_overlay()
{
    _dcent_destination=$1

    if dcent_persist_path_exists "$_dcent_destination/overlay" && \
        { [ ! -d "$_dcent_destination/overlay" ] || [ -L "$_dcent_destination/overlay" ]; }; then
        rm -rf "$_dcent_destination/overlay" || return 1
    fi
    mkdir -p "$_dcent_destination/overlay" || return 1

    if dcent_persist_path_exists "$_dcent_destination/overlay/etc" && \
        { [ ! -d "$_dcent_destination/overlay/etc" ] || [ -L "$_dcent_destination/overlay/etc" ]; }; then
        rm -rf "$_dcent_destination/overlay/etc" || return 1
    fi
    mkdir -p "$_dcent_destination/overlay/etc" || return 1

    rm -rf "$_dcent_destination/overlay/etc/upper" \
        "$_dcent_destination/overlay/etc/work" || return 1
    mkdir "$_dcent_destination/overlay/etc/upper" \
        "$_dcent_destination/overlay/etc/work" || return 1
    chmod 700 "$_dcent_destination/overlay/etc/upper" \
        "$_dcent_destination/overlay/etc/work" || return 1
    return 0
}

dcent_persist_prepare_entropy_seed()
{
    _dcent_source=$1
    _dcent_payload=$2
    _dcent_seed_dir=$_dcent_payload/keys

    [ -d "$_dcent_seed_dir" ] && [ ! -L "$_dcent_seed_dir" ] || {
        dcent_persist_fail "staged keys directory is absent or unsafe"
        return 1
    }
    rm -f "$_dcent_seed_dir/random-seed" \
        "$_dcent_seed_dir/.random-seed.born" || return 1
    if ! (
        exec 9<"$_dcent_seed_dir" || exit 1
        dcent_persist_seed_entropy_initialize \
            --initialize-if-missing-at 9 random-seed
    ); then
        dcent_persist_fail "cannot initialize a fresh, CRNG-proven entropy seed"
        return 1
    fi
    dcent_persist_path_exists "$_dcent_seed_dir/.random-seed.consumed" && {
        dcent_persist_fail "seed initializer left a consumed lifecycle state"
        return 1
    }
    dcent_persist_path_exists "$_dcent_seed_dir/.random-seed.credited" && {
        dcent_persist_fail "seed initializer left a credited lifecycle state"
        return 1
    }
    dcent_persist_path_exists "$_dcent_seed_dir/.random-seed.new" && {
        dcent_persist_fail "seed initializer left an unresolved install witness"
        return 1
    }
    dcent_persist_path_exists "$_dcent_seed_dir/.random-seed.born.new" && {
        dcent_persist_fail "seed initializer left an unresolved birth-marker transaction"
        return 1
    }
    dcent_persist_require_entropy_birth_marker \
        "$_dcent_seed_dir/.random-seed.born" \
        "$_dcent_seed_dir/random-seed" \
        "initialized entropy birth marker" || return 1
    # Creating/replacing the semantic seed changes the keys directory mtime;
    # restore the copied directory metadata before exact verification.
    touch -r "$_dcent_source/keys" "$_dcent_seed_dir" || {
        dcent_persist_fail "cannot restore staged keys directory timestamp"
        return 1
    }
    return 0
}

dcent_persist_stage()
(
    [ "$#" -eq 2 ] || {
        dcent_persist_fail "dcent_persist_stage requires SOURCE_ROOT DESTINATION_ROOT"
        return 1
    }
    _dcent_source=$1
    _dcent_destination=$2

    dcent_persist_validate_roots "$_dcent_source" "$_dcent_destination" || return 1
    _dcent_source=$_dcent_source_real
    _dcent_destination=$_dcent_destination_real
    dcent_persist_validate_source "$_dcent_source" || return 1

    umask 077
    _dcent_stage=$_dcent_destination/.dcentos-persist-stage.$$
    mkdir "$_dcent_stage" || {
        dcent_persist_fail "cannot create destination staging directory"
        return 1
    }
    mkdir "$_dcent_stage/payload" || {
        rm -rf "$_dcent_stage"
        dcent_persist_fail "cannot create destination staging payload"
        return 1
    }

    for _dcent_name in keys config profiles dcent network vendor-first-install dcentrald.toml dcentos-compat; do
        if dcent_persist_path_exists "$_dcent_source/$_dcent_name"; then
            if ! cp -a "$_dcent_source/$_dcent_name" "$_dcent_stage/payload/$_dcent_name"; then
                rm -rf "$_dcent_stage"
                dcent_persist_fail "cannot stage $_dcent_name"
                return 1
            fi
            if ! dcent_persist_entry_matches \
                "$_dcent_source" "$_dcent_stage/payload" "$_dcent_name"; then
                rm -rf "$_dcent_stage"
                return 1
            fi
        fi
    done
    dcent_persist_prepare_entropy_seed \
        "$_dcent_source" "$_dcent_stage/payload" || {
        rm -rf "$_dcent_stage"
        return 1
    }

    # Install only after every present source entry has a complete, verified
    # staging copy.  Absent source entries intentionally remove stale state.
    for _dcent_name in keys config profiles dcent network vendor-first-install dcentrald.toml dcentos-compat; do
        if ! rm -rf "$_dcent_destination/$_dcent_name"; then
            rm -rf "$_dcent_stage"
            dcent_persist_fail "cannot remove old destination $_dcent_name"
            return 1
        fi
        if dcent_persist_path_exists "$_dcent_stage/payload/$_dcent_name"; then
            if ! mv "$_dcent_stage/payload/$_dcent_name" \
                "$_dcent_destination/$_dcent_name"; then
                rm -rf "$_dcent_stage"
                dcent_persist_fail "cannot install destination $_dcent_name"
                return 1
            fi
        fi
    done

    if ! dcent_persist_prepare_overlay "$_dcent_destination"; then
        rm -rf "$_dcent_stage"
        dcent_persist_fail "cannot reset destination overlay state"
        return 1
    fi
    for _dcent_name in dcentrald dcentrald-env \
        dcentrald_standalone_boot.sh dcentrald.toml.mgmt-bak; do
        if ! rm -rf "$_dcent_destination/$_dcent_name"; then
            rm -rf "$_dcent_stage"
            dcent_persist_fail "cannot reset inactive runtime-derived state: $_dcent_name"
            return 1
        fi
    done
    if ! rm -rf "$_dcent_stage"; then
        dcent_persist_fail "cannot remove destination staging directory"
        return 1
    fi

    dcent_persist_verify "$_dcent_source" "$_dcent_destination" || return 1
    return 0
)

if [ "${0##*/}" = sysupgrade-persistent-state.sh ]; then
    if [ "$#" -ne 2 ]; then
        printf '%s\n' "usage: $0 SOURCE_ROOT DESTINATION_ROOT" >&2
        exit 2
    fi
    dcent_persist_stage "$1" "$2" || exit 1
    dcent_persist_verify "$1" "$2" || exit 1
fi
