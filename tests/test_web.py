"""Drive the web UI's HTTP API against the scripted run in fakes.py. No AWS calls."""

import json
import pathlib
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import fakes

from warden import report, web


class WebAPI(unittest.TestCase):
    def setUp(self):
        tmp = pathlib.Path(tempfile.mkdtemp())
        for name, value in {
            "RUNS_DIR": tmp / "runs",
            "POLICY_FILE": tmp / "policy.md",
            "RUNS": {},
        }.items():
            p = mock.patch.object(web, name, value)
            p.start()
            self.addCleanup(p.stop)
        p = mock.patch.object(web.agent, "run", fakes.fake_run)
        p.start()
        self.addCleanup(p.stop)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.shutdown)
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def call(self, method, path, body=None, ctype="application/json"):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(
            self.base + path, data=data, method=method, headers={"Content-Type": ctype}
        )
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            with e:
                return e.code, json.loads(e.read())

    def wait_for(self, rid, pred, timeout=5):
        end = time.time() + timeout
        while time.time() < end:
            _, run = self.call("GET", f"/api/runs/{rid}")
            if pred(run):
                return run
            time.sleep(0.05)
        self.fail(
            f"timed out; last state {run.get('status')} pending={run.get('pending')}"
        )

    def test_policy_round_trip(self):
        code, body = self.call(
            "PUT", "/api/policy", {"rules": ["  a   rule ", "", "second"]}
        )
        self.assertEqual((code, body["rules"]), (200, ["a rule", "second"]))
        self.assertEqual(
            self.call("GET", "/api/policy")[1]["rules"], ["a rule", "second"]
        )

    def test_post_without_json_content_type_refused(self):
        code, _ = self.call("PUT", "/api/policy", {"rules": ["x"]}, ctype="text/plain")
        self.assertEqual(code, 400)

    def test_bad_run_id_is_404(self):
        self.assertEqual(self.call("GET", "/api/runs/..%2f..%2fetc")[0], 404)

    def test_run_with_approvals_produces_code_computed_report(self):
        self.call("PUT", "/api/policy", {"rules": [r["text"] for r in fakes.SCRIPT]})
        code, body = self.call("POST", "/api/runs", {})
        self.assertEqual(code, 200)
        rid = body["id"]
        self.assertEqual(
            self.call("POST", "/api/runs", {})[0], 409
        )  # one run at a time

        for approve in (True, False, True):
            self.wait_for(rid, lambda r: r.get("pending"))
            self.assertEqual(
                self.call("POST", f"/api/runs/{rid}/decision", {"approve": approve})[0],
                200,
            )
        run = self.wait_for(rid, lambda r: r["status"] == "done")

        rules = {r["rule_id"]: r for r in run["report"]["rules"]}
        self.assertEqual(
            (rules["R1"]["violations"], rules["R1"]["resources_checked"]), (1, 2)
        )
        self.assertFalse(rules["R2"]["approved"])
        self.assertIsNone(rules["R2"]["violations"])
        self.assertEqual(rules["R3"]["violations"], 1)
        self.assertEqual(run["report"]["totals"]["violations"], 2)
        self.assertEqual(len(run["report"]["hooks_denied"]), 1)

        listed = self.call("GET", "/api/runs")[1]["runs"]
        self.assertEqual((listed[0]["id"], listed[0]["violations"]), (rid, 2))
        self.assertTrue((web.RUNS_DIR / f"{rid}.json").exists())

    def test_decision_without_pending_rule_refused(self):
        self.assertEqual(
            self.call(
                "POST", "/api/runs/20260101-000000-abcd/decision", {"approve": True}
            )[0],
            409,
        )


class Report(unittest.TestCase):
    def test_model_text_never_feeds_numbers(self):
        t = [
            {"kind": "text", "text": "There are 999 violations."},
            {"kind": "rules", "proposed": []},
        ]
        rep = report.build_report(t)
        self.assertEqual(rep["totals"]["violations"], 0)
        self.assertIn("999", rep["agent_summary"])


if __name__ == "__main__":
    unittest.main()
