"""Gate Lambda for the Policy Warden harness. One function serves all three hooks.

before_invocation  user text goes through the Bedrock Guardrail (prompt attacks,
                   remediation requests). Deny stops the invocation.
before_tool_call   only the four inline tools, and only with input that passes
                   the same validation the client runs. Deny skips the call.
after_tool_call    tool results (which carry tag values anyone can write) go
                   through the Guardrail and a key-pattern check before the
                   model reads them. Deny stops the invocation.

Fails closed: the harness is configured with failureMode=deny, and any
truncated context is denied here.
"""

import json
import os
import re

import boto3

from warden import rules
from warden.tools import REGION_RE, TOOL_NAMES

GUARDRAIL_ID = os.environ["GUARDRAIL_ID"]
GUARDRAIL_VERSION = os.environ["GUARDRAIL_VERSION"]
CHUNK = 20000
KEY_RE = re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")

bedrock = boto3.client("bedrock-runtime")


def allow(reason="ok"):
    return {"decision": "allow", "reason": reason[:1024]}


def deny(reason):
    print(json.dumps({"deny": reason}))
    return {"decision": "deny", "reason": reason[:1024]}


def _truncated(value):
    return isinstance(value, dict) and value.get("truncated") is True


def guardrail_check(text):
    """Return a sorted list of what the guardrail flagged (empty if clean)."""
    for i in range(0, len(text), CHUNK):
        resp = bedrock.apply_guardrail(
            guardrailIdentifier=GUARDRAIL_ID,
            guardrailVersion=GUARDRAIL_VERSION,
            source="INPUT",
            content=[{"text": {"text": text[i : i + CHUNK]}}],
        )
        if resp["action"] == "GUARDRAIL_INTERVENED":
            flagged = []
            for a in resp.get("assessments", []):
                for f in a.get("contentPolicy", {}).get("filters", []):
                    flagged.append(f"content:{f['type']}")
                for t in a.get("topicPolicy", {}).get("topics", []):
                    flagged.append(f"topic:{t['name']}")
                for p in a.get("sensitiveInformationPolicy", {}).get("piiEntities", []):
                    flagged.append(f"pii:{p['type']}")
            return sorted(set(flagged)) or ["guardrail intervened"]
    return []


def before_invocation(ctx):
    if ctx.get("truncated"):
        return deny("request too large to check")
    texts = [
        c["text"]
        for m in ctx.get("messages", [])
        for c in m.get("content", [])
        if "text" in c
    ]
    if not texts:
        return allow("no user text (tool result follow-up)")
    flagged = guardrail_check("\n".join(texts))
    if flagged:
        return deny(
            f"request refused by guardrail ({', '.join(flagged)}). Policy Warden only reads and reports."
        )
    return allow()


def _check_tool_input(name, args):
    if name == "scan_account":
        extra = set(args) - {"regions"}
        regions = args.get("regions") or []
        if (
            extra
            or not isinstance(regions, list)
            or not all(isinstance(r, str) and re.match(REGION_RE, r) for r in regions)
        ):
            return "scan_account takes only a list of region names"
    elif name == "describe_fields":
        if args:
            return "describe_fields takes no input"
    elif name == "propose_rule":
        if set(args) != {"rule"}:
            return "propose_rule takes exactly one key, rule"
        errors = rules.validate_rule(args["rule"])
        if errors:
            return "invalid rule: " + "; ".join(errors)
    elif name == "evaluate_rules":
        ids = args.get("rule_ids")
        if (
            set(args) != {"rule_ids"}
            or not isinstance(ids, list)
            or not all(isinstance(i, str) and re.match(r"^R\d{1,3}$", i) for i in ids)
        ):
            return "evaluate_rules takes only rule_ids like R1"
    return None


def before_tool_call(ctx):
    name, ttype, args = ctx.get("toolName"), ctx.get("toolType"), ctx.get("toolInput")
    if name not in TOOL_NAMES or ttype != "inline_function":
        return deny(f"tool {name!r} ({ttype}) is not on the allowlist {TOOL_NAMES}")
    if _truncated(args):
        return deny("tool input too large to check")
    if isinstance(args, str):
        try:
            args = json.loads(args or "{}")
        except json.JSONDecodeError:
            return deny("tool input is not JSON")
    if not isinstance(args, dict):
        return deny("tool input must be an object")
    problem = _check_tool_input(name, args)
    return deny(problem) if problem else allow()


def after_tool_call(ctx):
    result = ctx.get("toolResult")
    if _truncated(result):
        return deny("tool result too large to check")
    text = result if isinstance(result, str) else json.dumps(result, default=str)
    if KEY_RE.search(text):
        return deny(
            "tool result contains an AWS access key id; withheld from the model"
        )
    # Topics describe what a user may ask for; on tool output they misfire (a rule
    # sentence like "No S3 bucket may be public" was flagged as Remediation on
    # 2026-11-20). Tool results are blocked for prompt attacks and secrets only.
    flagged = [f for f in guardrail_check(text) if not f.startswith("topic:")]
    if flagged:
        return deny(
            f"tool result flagged by guardrail ({', '.join(flagged)}); possible instructions hidden in resource data"
        )
    return allow()


HANDLERS = {
    "before_invocation": before_invocation,
    "before_tool_call": before_tool_call,
    "after_tool_call": after_tool_call,
}


def lambda_handler(event, _context):
    handler = HANDLERS.get(event.get("event"))
    if handler is None:
        return allow(f"no check for {event.get('event')}")
    return handler(event.get("context") or {})
