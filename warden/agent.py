"""Drive one Policy Warden session: invoke the harness, run inline tool calls
locally under the auditor role, send results back, repeat until the agent stops.

    python3 -m warden.agent "Check the account against policy.example.md"
    python3 -m warden.agent --policy policy.example.md --approve ask
"""

import argparse
import json
import sys
import uuid

import boto3
from botocore.config import Config
from botocore.exceptions import EventStreamError

from . import config
from .tools import TOOL_SPECS, ToolBox, as_tool_result

MAX_TURNS = 15


def lambda_scanner(state):
    """scan_account runs in the scanner Lambda, whose execution role is the read-only
    auditor role. This process never holds account-read credentials of its own."""
    lam = boto3.client(
        "lambda", region_name=config.REGION, config=Config(read_timeout=300)
    )

    def scan(regions):
        resp = lam.invoke(
            FunctionName=state["scanner_arn"],
            Payload=json.dumps({"regions": regions or None}).encode(),
        )
        body = json.loads(resp["Payload"].read() or b"{}")
        if resp.get("FunctionError") or "error" in body or "errorMessage" in body:
            msg = (
                body.get("error")
                or body.get("errorMessage")
                or resp.get("FunctionError")
            )
            return [], [f"scanner: {msg}"]
        return body["records"], body["errors"]

    return scan


def make_approver(mode):
    def approve(rule):
        if mode == "all":
            return True, "auto-approved (--approve all)"
        if mode == "none":
            return False, "auto-rejected (--approve none)"
        print("\n--- proposed rule ---")
        print(json.dumps(rule, indent=2))
        answer = input("approve this rule? [y/N] ").strip().lower()
        return (answer == "y"), (
            "approved by operator" if answer == "y" else "rejected by operator"
        )

    return approve


def _events(stream, transcript, echo):
    """Yield stream events. botocore raises an error event (for example a model
    ValidationException) as EventStreamError; record it and end the stream."""
    try:
        yield from stream
    except EventStreamError as e:
        transcript.append({"kind": "error", "error": "stream", "detail": str(e)})
        if echo:
            print(f"\n[stream error] {e}", file=sys.stderr)


def _read_stream(stream, transcript, echo):
    """Consume one InvokeHarness stream. Returns (stop_reason, pending inline tool uses)."""
    blocks, results_seen, stop = {}, set(), None
    for event in _events(stream, transcript, echo):
        if "contentBlockStart" in event:
            start = event["contentBlockStart"].get("start", {})
            idx = event["contentBlockStart"].get("contentBlockIndex")
            if "toolUse" in start:
                blocks[idx] = {
                    "id": start["toolUse"]["toolUseId"],
                    "name": start["toolUse"]["name"],
                    "input": "",
                }
            if "toolResult" in start:
                results_seen.add(start["toolResult"]["toolUseId"])
        elif "contentBlockDelta" in event:
            d = event["contentBlockDelta"]
            delta = d.get("delta", {})
            if "text" in delta:
                transcript.append({"kind": "text", "text": delta["text"]})
                if echo:
                    print(delta["text"], end="", flush=True)
            if "toolUse" in delta and d.get("contentBlockIndex") in blocks:
                blocks[d["contentBlockIndex"]]["input"] += delta["toolUse"].get(
                    "input", ""
                )
        elif "hookEvent" in event:
            h = event["hookEvent"]
            transcript.append(
                {
                    "kind": "hook",
                    **{k: h.get(k) for k in ("name", "type", "decision", "reason")},
                }
            )
            if echo and h.get("decision") == "deny":
                print(
                    f"\n[hook {h.get('name')} denied {h.get('type')}: {h.get('reason')}]",
                    flush=True,
                )
        elif "messageStop" in event:
            stop = event["messageStop"].get("stopReason")
        else:
            for err in (
                "validationException",
                "internalServerException",
                "runtimeClientError",
            ):
                if err in event:
                    transcript.append(
                        {"kind": "error", "error": err, "detail": event[err]}
                    )
                    if echo:
                        print(f"\n[{err}] {event[err]}", file=sys.stderr)
    pending = [
        b
        for b in blocks.values()
        if b["id"] not in results_seen and b["name"] in TOOL_SPECS
    ]
    for b in blocks.values():
        transcript.append(
            {"kind": "tool_call", "tool": b["name"], "id": b["id"], "input": b["input"]}
        )
    return stop, pending


def run(prompt, approve="ask", echo=True, state=None, approver=None, transcript=None):
    """Run one session to completion. Returns the transcript (a list of dicts).

    approver overrides the --approve mode (the web UI passes one that waits for a click).
    transcript, if given, is appended to in place so a caller can watch progress.
    """
    state = state or config.load_state()
    client = boto3.client(
        "bedrock-agentcore",
        region_name=config.REGION,
        config=Config(read_timeout=600, tcp_keepalive=True),
    )
    toolbox = ToolBox(lambda_scanner(state), approver or make_approver(approve))
    session_id = f"warden-{uuid.uuid4()}"
    transcript = transcript if transcript is not None else []
    transcript.append({"kind": "prompt", "text": prompt, "session": session_id})
    messages = [{"role": "user", "content": [{"text": prompt}]}]

    for _ in range(MAX_TURNS):
        resp = client.invoke_harness(
            harnessArn=state["harness_arn"],
            runtimeSessionId=session_id,
            messages=messages,
        )
        stop, pending = _read_stream(resp["stream"], transcript, echo)
        transcript.append({"kind": "stop", "reason": stop})
        if stop != "tool_use" or not pending:
            break
        results = []
        for call in pending:
            try:
                args = json.loads(call["input"] or "{}")
            except json.JSONDecodeError:
                args = None
            payload = toolbox.call(call["name"], args)
            transcript.append(
                {
                    "kind": "tool_result",
                    "tool": call["name"],
                    "id": call["id"],
                    "result": payload,
                }
            )
            results.append(as_tool_result(call["id"], payload))
        messages = [{"role": "user", "content": results}]

    transcript.append({"kind": "rules", "proposed": toolbox.proposed})
    if echo:
        print()
    return transcript


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("prompt", nargs="?", default="")
    ap.add_argument("--policy", help="file with the policy in plain English")
    ap.add_argument("--approve", choices=["ask", "all", "none"], default="ask")
    ap.add_argument("--save", help="write the transcript as JSON to this path")
    a = ap.parse_args()
    prompt = a.prompt
    if a.policy:
        with open(a.policy, encoding="utf-8") as f:
            prompt = (prompt + "\n\nPolicy:\n" + f.read()).strip()
    if not prompt:
        ap.error("give a prompt or --policy")
    transcript = run(prompt, a.approve)
    if a.save:
        with open(a.save, "w", encoding="utf-8") as f:
            json.dump(transcript, f, indent=2, default=str)


if __name__ == "__main__":
    main()
