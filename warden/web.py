"""Local web UI: edit the policy, run a check, approve rules, read reports.

    python3 -m warden.web            http://127.0.0.1:8765

Binds to 127.0.0.1 only. Runs execute on this machine with your AWS credentials,
exactly like `make run`. Reports are saved to results/runs/<id>.json.
"""

import argparse
import datetime as dt
import json
import pathlib
import re
import threading
import traceback
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import agent, config
from .report import build_report

STATIC = pathlib.Path(__file__).resolve().parent / "static"
POLICY_FILE = config.ROOT / "policy.md"
EXAMPLE_POLICY = config.ROOT / "policy.example.md"
RUNS_DIR = config.ROOT / "results" / "runs"
APPROVAL_TIMEOUT = (
    900  # seconds a proposed rule waits for a click before it is rejected
)

RUNS = {}  # run id -> live run dict (this process only)
LOCK = threading.Lock()


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


# ---------- policy ----------


def read_policy():
    path = POLICY_FILE if POLICY_FILE.exists() else EXAMPLE_POLICY
    lines = path.read_text(encoding="utf-8").splitlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("#")]


def write_policy(rules):
    clean = [" ".join(str(r).split()) for r in rules if str(r).strip()]
    if len(clean) > 50 or any(len(r) > 500 for r in clean):
        raise ValueError("at most 50 rules of at most 500 characters")
    POLICY_FILE.write_text("\n".join(clean) + "\n", encoding="utf-8")
    return clean


def deployment():
    try:
        s = config.load_state()
        return {
            "deployed": True,
            "harness_id": s["harness_id"],
            "model": s["model"],
            "region": s["region"],
        }
    except SystemExit as e:
        return {"deployed": False, "message": str(e)}


# ---------- runs ----------


def save_run(run):
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    data = {k: v for k, v in run.items() if not k.startswith("_")}
    (RUNS_DIR / f"{run['id']}.json").write_text(json.dumps(data, indent=2, default=str))


def public(run):
    out = {k: v for k, v in run.items() if not k.startswith("_") and k != "transcript"}
    out["report"] = build_report(run["transcript"])
    out["progress"] = [progress_line(e) for e in run["transcript"] if progress_line(e)]
    return out


def progress_line(e):
    k = e["kind"]
    if k == "tool_result":
        res = e["result"]
        if e["tool"] == "scan_account":
            return f"scan_account: {res.get('resources', '?')} resources"
        if e["tool"] == "propose_rule":
            return f"propose_rule: {res.get('rule_id', 'invalid')} {'approved' if res.get('approved') else 'rejected'}"
        return e["tool"]
    if k == "hook" and e.get("decision") == "deny":
        return f"hook {e.get('name')} denied: {e.get('reason')}"
    if k == "error":
        return f"error: {e.get('error')}"
    return None


def web_approver(run):
    def approve(rule):
        event = threading.Event()
        with LOCK:
            run["pending"] = {"rule": rule, "since": now()}
            run["_decision"] = None
            run["_event"] = event
        if not event.wait(APPROVAL_TIMEOUT):
            with LOCK:
                run["pending"] = None
            return False, f"no decision within {APPROVAL_TIMEOUT}s; rejected"
        with LOCK:
            ok = run["_decision"]
            run["pending"] = None
        return ok, "approved in UI" if ok else "rejected in UI"

    return approve


def start_run(policy):
    run = {
        "id": dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%S-")
        + uuid.uuid4().hex[:4],
        "started": now(),
        "finished": None,
        "status": "running",
        "policy": policy,
        "pending": None,
        "error": None,
        "transcript": [],
    }
    prompt = "Check this account against the policy.\n\nPolicy:\n" + "\n".join(
        f"- {p}" for p in policy
    )

    def work():
        try:
            agent.run(
                prompt,
                echo=False,
                approver=web_approver(run),
                transcript=run["transcript"],
            )
            run["status"] = "done"
        # The thread must record every failure on the run, or the UI spins forever.
        # SystemExit is included: load_state raises it when nothing is deployed.
        except (Exception, SystemExit) as e:  # noqa: BLE001
            run["status"] = "error"
            run["error"] = f"{type(e).__name__}: {e}"
            traceback.print_exc()
        run["finished"] = now()
        save_run(run)

    with LOCK:
        RUNS[run["id"]] = run
    threading.Thread(target=work, daemon=True).start()
    return run


def list_runs():
    items = {}
    if RUNS_DIR.exists():
        for p in RUNS_DIR.glob("*.json"):
            try:
                d = json.loads(p.read_text())
            except json.JSONDecodeError:
                continue
            items[d["id"]] = d
    with LOCK:
        for rid, r in RUNS.items():
            items[rid] = r
    out = []
    for d in items.values():
        totals = build_report(d.get("transcript", []))["totals"]
        out.append(
            {
                "id": d["id"],
                "started": d["started"],
                "status": d["status"],
                "rules": len(d.get("policy", [])),
                "violations": totals["violations"],
                "rules_evaluated": totals["rules_evaluated"],
                "error": d.get("error"),
            }
        )
    return sorted(out, key=lambda r: r["id"], reverse=True)


RUN_ID = re.compile(r"^\d{8}-\d{6}-[0-9a-f]{4}$")


def get_run(rid):
    if not RUN_ID.match(rid):
        return None
    with LOCK:
        if rid in RUNS:
            return public(RUNS[rid])
    path = RUNS_DIR / f"{rid}.json"
    if path.exists():
        return public(json.loads(path.read_text()))
    return None


def decide(rid, approve):
    with LOCK:
        run = RUNS.get(rid)
        if not run or not run.get("pending") or not run.get("_event"):
            return False
        run["_decision"] = bool(approve)
        run["_event"].set()
        return True


# ---------- HTTP ----------


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def send_json(self, obj, code=200):
        body = json.dumps(obj, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        # Requiring application/json means a cross-site page cannot post here without a CORS preflight.
        if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
            raise ValueError("Content-Type must be application/json")
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            body = (STATIC / "index.html").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/api/status":
            self.send_json(deployment())
        elif path == "/api/policy":
            self.send_json(
                {
                    "rules": read_policy(),
                    "file": POLICY_FILE.name
                    if POLICY_FILE.exists()
                    else EXAMPLE_POLICY.name,
                }
            )
        elif path == "/api/runs":
            self.send_json({"runs": list_runs()})
        elif path.startswith("/api/runs/"):
            run = get_run(path.rsplit("/", 1)[1])
            self.send_json(run or {"error": "not found"}, 200 if run else 404)
        else:
            self.send_json({"error": "not found"}, 404)

    def do_PUT(self):
        if self.path != "/api/policy":
            return self.send_json({"error": "not found"}, 404)
        try:
            self.send_json({"rules": write_policy(self.read_json().get("rules", []))})
        except (ValueError, json.JSONDecodeError) as e:
            self.send_json({"error": str(e)}, 400)

    def do_POST(self):
        try:
            body = self.read_json()
        except (ValueError, json.JSONDecodeError) as e:
            return self.send_json({"error": str(e)}, 400)
        if self.path == "/api/runs":
            policy = read_policy()
            if not policy:
                return self.send_json({"error": "the policy is empty"}, 400)
            with LOCK:
                if any(r["status"] == "running" for r in RUNS.values()):
                    return self.send_json({"error": "a check is already running"}, 409)
            return self.send_json({"id": start_run(policy)["id"]})
        parts = self.path.strip("/").split("/")
        if len(parts) == 4 and parts[:2] == ["api", "runs"] and parts[3] == "decision":
            ok = decide(parts[2], body.get("approve"))
            return self.send_json({"ok": ok}, 200 if ok else 409)
        self.send_json({"error": "not found"}, 404)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8765)
    a = ap.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", a.port), Handler)
    print(f"Policy Warden UI on http://127.0.0.1:{a.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
