"""Stand-in for dumpcap used by the live-capture tests. Never touches a real interface.

Environment:
  FAKE_DUMPCAP_DIR   directory with head.bin (SHB, IDBs, packets) and tail.bin (ISB)
  FAKE_DUMPCAP_MODE  "stream": write head, wait for SIGINT, write tail, exit 0
                     "eof":    write head and tail, exit 0
                     "fail":   print an error on stderr, exit 1
"""

import os
import signal
import sys
import time
from pathlib import Path

directory = Path(os.environ["FAKE_DUMPCAP_DIR"])
(directory / "args.txt").write_text("\n".join(sys.argv[1:]))
mode = os.environ.get("FAKE_DUMPCAP_MODE", "stream")
out = sys.stdout.buffer

if mode == "fail":
    print("dumpcap: You don't have permission to capture on that device.", file=sys.stderr)
    sys.exit(1)

stop = False


def on_signal(signum, frame):  # type: ignore[no-untyped-def]
    global stop
    stop = True


signal.signal(signal.SIGINT, on_signal)
out.write((directory / "head.bin").read_bytes())
out.flush()
if mode == "stream":
    deadline = time.monotonic() + 20
    while not stop and time.monotonic() < deadline:
        time.sleep(0.02)
out.write((directory / "tail.bin").read_bytes())
out.flush()
