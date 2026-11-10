"""Local installation diagnostics. Never reads credentials or contacts AWS/AI."""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def run(args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=25, cwd=ROOT)
        return result.returncode == 0, result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return False, ""


def diagnose(root=ROOT, *, startup=False):
    checks = []
    def add(name, state, detail, fix=""):
        checks.append(dict(name=name, state=state, detail=detail, fix=fix))
    if not sys.platform.startswith("linux"):
        add("Platform", "error", "The backend requires Linux or WSL.", "On Windows, run Check CloudSentinel.cmd after installing WSL.")
        return checks
    add("Platform", "ok", "Linux/WSL")
    env = Path(os.getenv("CLOUDSENTINEL_VENV", str(Path.home() / ".venvs/cloudsentinel-ai"))).expanduser()
    python = env / "bin/python"
    ok, version = run([str(python), "-c", "import sys; print('.'.join(map(str,sys.version_info[:3]))); sys.exit(sys.version_info[:2] != (3,12))"])
    add("Python environment", "ok" if ok else "error", version or "Application Python environment is missing or inaccessible.", "Install Python 3.12 with venv support, then run bash scripts/setup-linux.sh.")
    if ok:
        ok, _ = run([str(python), "-c", "import fastapi, uvicorn, boto3, cryptography, pydantic, httpx"])
        add("Backend dependencies", "ok" if ok else "error", "Required backend imports are available." if ok else "Required backend imports failed.", "Run bash scripts/setup-linux.sh; use the same CLOUDSENTINEL_VENV for setup and start.")
        consistent, _ = run([str(python), "-m", "pip", "check"])
        add("Python dependency consistency", "ok" if consistent else "error", "No incompatible installed requirements." if consistent else "Installed requirements are missing or incompatible.", "Run bash scripts/setup-linux.sh to install the pinned environment.")
    ok, version = run(["node", "--version"])
    add("Node.js", "ok" if ok and version.startswith("v22.") else "error", version if ok else "Node.js not found.", "Install or select Node.js 22; with nvm, run nvm use 22.")
    ok, _ = run(["npm", "--version"])
    add("npm", "ok" if ok else "error", "npm is available." if ok else "npm not found.", "Install Node.js 22 with npm.")
    available = (root / "apps/web/node_modules/next/package.json").is_file()
    add("Frontend dependencies", "ok" if available else "error", "Next.js is installed." if available else "Next.js is not installed.", "Run bash scripts/setup-linux.sh.")
    built = (root / "apps/web/.next/BUILD_ID").is_file()
    add("Frontend build", "ok" if built else "info", "Production build exists; startup rebuilds changed source." if built else "The first start will build the UI.")
    writable = os.access(root, os.W_OK)
    add("Project access", "ok" if writable else "error", "Project is writable." if writable else "Project is not writable.", "Move the checkout into your Linux home directory or correct its ownership; do not run the app with sudo.")
    free = shutil.disk_usage(root).free
    add("Free disk space", "warning" if free < 1024**3 else "ok", f"{free / 1024**3:.1f} GiB available.", "Free disk space before dependency installation/build if needed.")
    from service import command
    managed = bool(command("status"))
    for port in (3000, 8000):
        with socket.socket() as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("127.0.0.1", port))
                occupied = False
            except OSError:
                occupied = True
        state = "info" if managed else "error" if occupied else "ok"
        add(f"Port {port}", state, "A managed launcher is active; inspect health below." if managed else "Occupied by an existing process." if occupied else "Available.", "Use the matching stop script for CloudSentinel; inspect other services yourself. No process is killed by this check.")
    if not startup:
        for label, url in [("Backend API", "http://127.0.0.1:8000/api/v1/health"), ("Web API proxy", "http://127.0.0.1:3000/api/v1/health")]:
            try:
                with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(url, timeout=3) as response:
                    healthy = json.loads(response.read(4096)).get("status") == "ok"
            except (OSError, ValueError):
                healthy = False
            add(label, "ok" if healthy else "warning" if managed else "info", "Responding." if healthy else "Not ready or stopped.", "Start CloudSentinel. If startup fails, inspect .runtime/service.log and the checks above.")
    return checks


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--startup", action="store_true")
    args = parser.parse_args()
    checks = diagnose(startup=args.startup)
    if args.json:
        print(json.dumps({"checks": checks, "ready": not any(c["state"] == "error" for c in checks)}))
    else:
        print("CloudSentinel local checks (no AWS or AI requests)")
        for c in checks:
            print(f'[{c["state"].upper()}] {c["name"]}: {c["detail"]}')
            if c["fix"] and c["state"] in ("error", "warning"):
                print("  Next: " + c["fix"])
    sys.exit(1 if any(c["state"] == "error" for c in checks) else 0)
