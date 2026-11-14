"""OpenWrt installer source layout, safe secrets and upgrade preservation."""
import os
from pathlib import Path
import re
import subprocess

import pytest


ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.skipif(os.geteuid() != 0, reason='staged installer requires root')
def test_install_preserves_device_and_password(tmp_path):
    destination = tmp_path / 'target'
    env = dict(os.environ, RDHEADLESS_SKIP_PACKAGES='1', RDHEADLESS_DESTDIR=str(destination))
    installer = ROOT / 'openwrt' / 'install.sh'

    for iteration in (0, 1):
        subprocess.run(['/bin/sh', str(installer)], cwd=ROOT, env=env, check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        cfg = destination / 'etc/rdheadless/config.toml'
        password = destination / 'etc/rdheadless/password'
        assert cfg.stat().st_mode & 0o777 == 0o600
        assert password.stat().st_mode & 0o777 == 0o600
        assert (destination / 'etc/rdheadless').stat().st_mode & 0o777 == 0o700
        assert (destination / 'etc/init.d/rdheadless').stat().st_mode & 0o777 == 0o755
        assert (destination / 'usr/bin/rdheadless').stat().st_mode & 0o777 == 0o755
        assert (destination / 'usr/lib/rdheadless/rdheadless/native.py').is_file()
        cfg_text, pw_text = cfg.read_text(), password.read_text()
        assert re.search(r'device_id\s*=\s*"RDW[0-9a-f]{12}"', cfg_text)
        assert pw_text.strip() and len(pw_text.strip()) >= 20
        assert 'shell = "/bin/ash"' in cfg_text
        assert 'file_root = "/root"' in cfg_text
        assert 'mode = "private"' in cfg_text
        if iteration == 0:
            saved_cfg, saved_password = cfg_text, pw_text
        else:
            assert cfg_text == saved_cfg
            assert pw_text == saved_password


def test_procd_service_uses_installed_python_and_root_config():
    init = (ROOT/'openwrt/rdheadless.init').read_text()
    assert 'procd_set_param command /usr/bin/python3 -m rdheadless host' in init
    assert 'procd_set_param env PYTHONPATH=/usr/lib/rdheadless' in init
    assert 'procd_set_param respawn' in init
