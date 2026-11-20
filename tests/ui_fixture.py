"""Serve the UI with the scripted run from fakes.py, for looking at the page offline.

    python3 tests/ui_fixture.py [port]

No AWS or model calls. Policy and reports go to a temp directory.
"""

import pathlib
import sys
import tempfile
from http.server import ThreadingHTTPServer

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import fakes

from warden import web

tmp = pathlib.Path(tempfile.mkdtemp(prefix="warden-ui-"))
web.RUNS_DIR = tmp / "runs"
web.POLICY_FILE = tmp / "policy.md"
web.agent.run = fakes.fake_run
web.deployment = lambda: {"deployed": False, "message": "fixture"}
port = int(sys.argv[1]) if len(sys.argv) > 1 else 8766
print(f"fixture UI on http://127.0.0.1:{port} (data in {tmp})", flush=True)
ThreadingHTTPServer(("127.0.0.1", port), web.Handler).serve_forever()
