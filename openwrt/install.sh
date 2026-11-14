#!/bin/sh
set -eu

# Install the architecture-independent Python source on OpenWrt.
# OpenWrt provides its own musl-compatible Python and native libraries.
if [ "$(id -u)" != 0 ]; then
    echo 'Run this installer as root.' >&2
    exit 1
fi

prefix=${RDHEADLESS_DESTDIR:-}
case "$prefix" in
    ''|/*) ;;
    *) echo 'RDHEADLESS_DESTDIR must be an absolute directory' >&2; exit 1 ;;
esac
here=$(CDPATH= cd "$(dirname "$0")" && pwd)
source_dir=$(CDPATH= cd "$here/.." && pwd)
[ -f "$source_dir/rdheadless/__main__.py" ] || {
    echo 'The source archive must contain the rdheadless Python package.' >&2
    exit 1
}

if [ "${RDHEADLESS_SKIP_PACKAGES:-0}" != 1 ]; then
    if command -v apk >/dev/null 2>&1; then
        apk update
        apk add python3 python3-ctypes libsodium libzstd
    elif command -v opkg >/dev/null 2>&1; then
        opkg update
        opkg install python3 python3-ctypes libsodium libzstd
    else
        echo 'OpenWrt apk or opkg is required to install dependencies.' >&2
        exit 1
    fi
fi

python3 -c 'import ctypes, pwd, tomllib; import sys; assert sys.version_info >= (3,11), "Python 3.11 or newer is required"'

# Test native dependencies before modifying the installed application.
PYTHONPATH="$source_dir" python3 -c 'from rdheadless import crypto, zstd; assert crypto.sign_keypair; assert zstd.decompress; from rdheadless.native import load_library; assert load_library("zstd", "libzstd.so.1"); assert load_library("sodium", "libsodium.so.23")'

umask 077
mkdir -p "$prefix/usr/lib/rdheadless/rdheadless" "$prefix/usr/bin" "$prefix/etc/rdheadless" "$prefix/etc/init.d"
cp "$source_dir"/rdheadless/*.py "$prefix/usr/lib/rdheadless/rdheadless/"
cp "$here/rdheadless.sh" "$prefix/usr/bin/rdheadless"
cp "$here/rdheadless.init" "$prefix/etc/init.d/rdheadless"
chmod 755 "$prefix/usr/bin/rdheadless" "$prefix/etc/init.d/rdheadless"
chmod 700 "$prefix/etc/rdheadless"

if [ ! -e "$prefix/etc/rdheadless/config.toml" ]; then
    cp "$here/private.toml" "$prefix/etc/rdheadless/config.toml"
    device_id=$(python3 -c 'import secrets; print("RDW" + secrets.token_hex(6))')
    sed -i "s/RDOpenWrtExample/$device_id/" "$prefix/etc/rdheadless/config.toml"
fi
chmod 600 "$prefix/etc/rdheadless/config.toml"

if [ ! -e "$prefix/etc/rdheadless/password" ]; then
    python3 -c 'import secrets; print(secrets.token_urlsafe(32))' > "$prefix/etc/rdheadless/password"
fi
chmod 600 "$prefix/etc/rdheadless/password"

if [ -z "$prefix" ]; then
    /usr/bin/rdheadless --help >/dev/null
fi

printf '%s\n' 'RustDesk Headless installed.'
printf '%s\n' 'Configure /etc/rdheadless/config.toml before starting the service.'
printf '%s\n' 'Connection password: /etc/rdheadless/password (owner-readable only).'
printf '%s\n' 'Run /etc/init.d/rdheadless enable and /etc/init.d/rdheadless start when ready.'
