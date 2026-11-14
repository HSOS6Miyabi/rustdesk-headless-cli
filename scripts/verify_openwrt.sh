#!/usr/bin/env bash
set -euo pipefail

# Test against the official OpenWrt musl root filesystem, not an Alpine substitute.
IMAGE="${RDHEADLESS_OPENWRT_IMAGE:-openwrt/rootfs:x86-64-openwrt-25.12}"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

docker run --rm --network host -v "${PROJECT_DIR}:/source:ro" -w /source \
  "$IMAGE" /bin/sh -ec '
    if [ -f /setup.sh ]; then /bin/sh /setup.sh; fi
    echo "OpenWrt release:"
    cat /etc/openwrt_release
    sh /source/openwrt/install.sh
    PYTHONPATH=/usr/lib/rdheadless python3 /source/scripts/openwrt_smoke.py
  '
