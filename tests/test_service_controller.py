"""Exercise service ownership using an isolated fake launcher, never the real app."""
import importlib.util
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
import pytest

pytestmark = pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Linux/WSL service control')


def test_stop_only_owns_its_launcher(tmp_path):
    source = Path(__file__).parents[1] / 'scripts/service.py'
    scripts = tmp_path / 'scripts'
    scripts.mkdir()
    (scripts / 'service.py').write_bytes(source.read_bytes())
    (scripts / 'start-web.sh').write_text('exec sleep 120\n')
    spec = importlib.util.spec_from_file_location('isolated_service', scripts / 'service.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    unrelated = subprocess.Popen(['sleep', '120'])
    server = subprocess.Popen([sys.executable, str(scripts / 'service.py'), 'serve'])
    try:
        for _ in range(100):
            if module.command('status'):
                break
            time.sleep(.05)
        assert module.command('status') == 'CloudSentinel launcher is running.'
        duplicate = subprocess.run([sys.executable, str(scripts / 'service.py'), 'serve'], timeout=5)
        assert duplicate.returncode == 0
        assert 'Stopped CloudSentinel' in module.command('stop')
        server.wait(timeout=5)
        assert server.returncode == 0
        assert unrelated.poll() is None
        assert module.command('status') is None
    finally:
        if server.poll() is None:
            server.terminate(); server.wait(timeout=20)
        unrelated.terminate(); unrelated.wait()
