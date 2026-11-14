"""Test the compiled Linux single-file executable with a real socket session."""
from __future__ import annotations

import base64
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

from rdheadless.client import Peer


def main(binary: str) -> int:
    with tempfile.TemporaryDirectory(prefix='rdheadless-binary-smoke-') as workspace:
        directory = Path(workspace)
        (directory / 'hello.txt').write_bytes(b'compiled-linux-host-verified')
        password_file = directory / 'password'
        password_file.write_text('A-unique-local-test-password\n')
        password_file.chmod(0o600)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        config = directory / 'config.toml'
        config.write_text(
            '[server]\nmode="private"\ndevice_id="FrozenHost123"\n'
            f'identity_file="{directory / "identity.json"}"\n'
            f'password_file="{password_file}"\n'
            f'file_root="{directory}"\n'
            f'listen_host="127.0.0.1"\nlisten_port={port}\n'
        )
        identity = subprocess.run([binary, 'identity', '--config', str(config)],
                                  capture_output=True, text=True, timeout=60, check=True)
        key = next(line.split(':', 1)[1].strip() for line in identity.stdout.splitlines()
                   if line.startswith('Public key (base64):'))
        process = subprocess.Popen([binary, 'host', '--config', str(config)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 35
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError(f'compiled host exited: {process.communicate()[1]!r}')
                try:
                    client = Peer.connect(('127.0.0.1', port), 'FrozenHost123',
                                          base64.b64decode(key), 'private', 'file',
                                          'A-unique-local-test-password')
                    break
                except (OSError, EOFError, ConnectionError):
                    time.sleep(0.3)
            else:
                raise TimeoutError('compiled host did not accept a file session')
            with client.stream.sock:
                names = {name for name, _, _ in client.ls(str(directory))}
                assert 'hello.txt' in names
                target = directory / 'retrieved.txt'
                client.get_file(str(directory / 'hello.txt'), str(target))
                assert target.read_bytes() == b'compiled-linux-host-verified'
            print('Compiled Linux host, unprivileged worker, secure login and file transfer: passed')
        finally:
            process.terminate()
            try:
                process.communicate(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=5)
    return 0


if __name__ == '__main__':
    raise SystemExit(main(str(Path(sys.argv[1]).resolve())))
