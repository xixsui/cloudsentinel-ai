"""Linux subprocess entry point: stop the scanner if its API parent dies."""
import ctypes
import os
import signal
import sys

if __name__ == "__main__":
    parent = int(sys.argv[1])
    libc = ctypes.CDLL(None, use_errno=True)
    # PR_SET_PDEATHSIG survives exec. Establish it before checking the parent race.
    if libc.prctl(1, signal.SIGTERM, 0, 0, 0) != 0:
        raise SystemExit("Could not establish scanner parent lifecycle")
    if os.getppid() != parent:
        raise SystemExit(1)
    os.execv(sys.argv[2], sys.argv[2:])
