"""Linux/WSL local service controller; stops only the process group it starts."""
import fcntl
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / '.runtime'
# Unix socket path length is bounded; use a per-user, per-project directory.
import hashlib
CONTROL = Path('/tmp') / ('cloudsentinel-' + str(os.getuid()) + '-' + hashlib.sha256(str(ROOT).encode()).hexdigest()[:16])
SOCKET = CONTROL / 'control.sock'


def command(value):
    try:
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(20)
            client.connect(str(SOCKET))
            client.sendall(value.encode())
            return client.recv(4096).decode()
    except (OSError, TimeoutError):
        return None


def stop_child(child):
    if child.poll() is None:
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            child.wait(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()


def serve():
    CONTROL.mkdir(mode=0o700, exist_ok=True)
    if CONTROL.is_symlink() or CONTROL.stat().st_uid != os.getuid():
        raise RuntimeError('Unsafe service control directory')
    os.chmod(CONTROL, 0o700)
    with open(CONTROL / 'lock', 'w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        SOCKET.unlink(missing_ok=True)
        with socket.socket(socket.AF_UNIX) as server:
            server.bind(str(SOCKET)); server.listen(4); server.settimeout(1)
            child = subprocess.Popen(['bash', 'scripts/start-web.sh'], cwd=ROOT, start_new_session=True)
            def terminate(*_):
                stop_child(child)
                raise SystemExit(0)
            signal.signal(signal.SIGTERM, terminate)
            signal.signal(signal.SIGINT, terminate)
            try:
                while child.poll() is None:
                    try:
                        conn, _ = server.accept()
                    except socket.timeout:
                        continue
                    with conn:
                        conn.settimeout(2)
                        try:
                            value = conn.recv(100).decode()
                        except (OSError, UnicodeError):
                            continue
                        if value == 'stop':
                            stop_child(child)
                            conn.sendall(b'Stopped CloudSentinel. Other WSL/Linux applications were not stopped.')
                            return
                        conn.sendall(b'CloudSentinel launcher is running.')
            finally:
                stop_child(child)
                SOCKET.unlink(missing_ok=True)


def start():
    if command('status'):
        print('CloudSentinel is already starting or running. Open http://127.0.0.1:3000 .')
        return
    for port in (3000, 8000):
        with socket.socket() as check:
            check.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                check.bind(('127.0.0.1', port))
            except OSError:
                raise SystemExit(f'Port {port} is occupied. Stop the existing service first; no process was stopped.')
    RUNTIME.mkdir(mode=0o700, exist_ok=True)
    os.chmod(RUNTIME, 0o700)
    with open(RUNTIME / 'service.log', 'a') as log:
        child = subprocess.Popen([sys.executable, __file__, 'serve'], cwd=ROOT,
                                 stdout=log, stderr=log, stdin=subprocess.DEVNULL, start_new_session=True)
    print('Starting CloudSentinel. First startup may build the UI.', flush=True)
    for i in range(600):
        if child.poll() is not None:
            print('Startup failed. Review .runtime/service.log. Check dependencies and ports 3000/8000.')
            raise SystemExit(1)
        try:
            with urllib.request.urlopen('http://127.0.0.1:3000/api/v1/health', timeout=1) as response:
                if response.status == 200 and command('status'):
                    print('Ready: http://127.0.0.1:3000', flush=True)
                    return
        except OSError:
            pass
        if i and i % 15 == 0:
            print('Still starting; progress is recorded in .runtime/service.log.', flush=True)
        time.sleep(1)
    print('Startup is taking longer than expected. Inspect .runtime/service.log or run the stop script.')
    raise SystemExit(1)


if __name__ == '__main__':
    action = sys.argv[1] if len(sys.argv) > 1 else 'status'
    if action == 'serve':
        serve()
    elif action == 'start':
        start()
    elif action == 'stop':
        print(command('stop') or 'No managed CloudSentinel service is running for this project.')
    else:
        print(command('status') or 'CloudSentinel is stopped.')
