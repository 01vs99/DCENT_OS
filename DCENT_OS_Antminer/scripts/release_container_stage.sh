#!/bin/bash
# Stage authenticated sources into a fresh private Docker volume. Preserve the
# workspace ancestry used by Python Path.resolve(), with legacy path aliases.
set -euo pipefail
[ "$#" -eq 4 ] || { echo "usage: $0 PROJECT_SOURCE TOOLBOX_SOURCE BUILD_ROOT BUILD_ARCH" >&2; exit 2; }
project_source=$1
toolbox_source=$2
build_root=$3
build_arch=$4
case "$build_arch" in armv7-unknown-linux-musleabihf|aarch64-unknown-linux-musl) ;;
    *) echo "ERROR: exact release architecture required" >&2; exit 2;;
esac
for stage_path in "$project_source" "$toolbox_source" "$build_root"; do
    case "$stage_path" in /*) ;; *) echo "ERROR: absolute staging paths required" >&2; exit 2;; esac
    [ -d "$stage_path" ] && [ ! -L "$stage_path" ] || {
        echo "ERROR: real staging directories required" >&2; exit 2;
    }
done
for stage_name in projects dcentos dcent-toolbox; do
    [ ! -e "$build_root/$stage_name" ] && [ ! -L "$build_root/$stage_name" ] || {
        echo "ERROR: source staging destination is not fresh: $stage_name" >&2; exit 2;
    }
done
mkdir -p "$build_root/DCENT_OS_Antminer" "$build_root/projects/dcent-toolbox/src"
rsync -a --exclude=__pycache__/ "$toolbox_source/src/" "$build_root/projects/dcent-toolbox/src/"
rsync -a \
    --exclude=buildroot/ --exclude=output/ --exclude=dcentrald/target/ \
    --exclude=dashboard/node_modules/ --exclude=dashboard/dist/ \
    --exclude=.tmp_* --exclude=*.log --exclude=.git/ --exclude=__pycache__/ \
    "$project_source/" "$build_root/DCENT_OS_Antminer/"
ln -s DCENT_OS_Antminer "$build_root/dcentos"
ln -s projects/dcent-toolbox "$build_root/dcent-toolbox"
binary_root="$build_root/DCENT_OS_Antminer/dcentrald"
[ -d "$binary_root" ] && [ ! -L "$binary_root" ] || {
    echo "ERROR: staged Cargo workspace must be a real directory" >&2; exit 2;
}
# Source snapshots exclude build outputs. Create only fresh real staging
# directories; Phase 5 independently checks every component before installation.
mkdir "$binary_root/target"
mkdir "$binary_root/target/$build_arch"
mkdir "$binary_root/target/$build_arch/release"
python3 "$build_root/dcentos/scripts/release_native_sd.py" preflight
