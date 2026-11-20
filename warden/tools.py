"""The agent's four inline tools. The harness hands each call to this process;
the gate Lambda has already allowed it (hooks/gate.py), and it runs here under
the read-only auditor role.

The only path from an English sentence to a reported number:
    propose_rule  -> validated, shown to a human, approved or rejected
    evaluate_rules -> runs approved rule ids only; all counts computed in code
"""

import json
import re

from . import rules

REGION_RE = r"^[a-z]{2}(-gov)?-[a-z]+-\d$"

CONDITION_SCHEMA = {
    "type": "object",
    "properties": {
        "field": {
            "type": "string",
            "description": "region, type, arn, attrs.<name> or tags.<key>",
        },
        "op": {"type": "string", "enum": sorted(rules.OPS)},
        "value": {
            "description": "Omit for exists/missing. Number for gt/gte/lt/lte. List for in/not_in."
        },
    },
    "required": ["field", "op"],
    "additionalProperties": False,
}

_CONDS = {
    "type": "array",
    "items": CONDITION_SCHEMA,
    "minItems": 1,
    "maxItems": rules.MAX_CONDITIONS,
}

RULE_SCHEMA = {
    "type": "object",
    "properties": {
        "text": {
            "type": "string",
            "description": "The policy sentence, verbatim, this rule was compiled from.",
        },
        "resource_type": {"type": "string", "enum": sorted(rules.RESOURCE_TYPES)},
        "require": {
            **_CONDS,
            "description": (
                "Use for 'must' / 'every ... must' sentences: the conditions a compliant resource meets. "
                "A resource violates the rule unless ALL hold. "
                "Example: 'Every EBS volume must be attached' -> require [attrs.attached eq true]."
            ),
        },
        "violation_when": {
            **_CONDS,
            "description": (
                "Use for 'no ... may' / 'must not' sentences: the conditions that make a resource a violation. "
                "A resource violates the rule when ALL hold. "
                "Example: 'No volume may exceed 100 GiB' -> violation_when [attrs.size_gib gt 100]."
            ),
        },
        "severity": {"type": "string", "enum": sorted(rules.SEVERITIES)},
    },
    "required": ["text", "resource_type"],
    "additionalProperties": False,
    "description": "Give exactly one of require or violation_when.",
}

TOOL_SPECS = {
    "scan_account": {
        "description": (
            "Take a read-only inventory of this AWS account (EC2 instances, EBS volumes, "
            "security group rules, Elastic IPs, S3 buckets, month-to-date cost per service). "
            "Returns exact counts per resource type. Call once per session before other tools."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "regions": {
                    "type": "array",
                    "items": {"type": "string", "pattern": REGION_RE},
                    "maxItems": 40,
                    "description": "Omit to scan every enabled region.",
                }
            },
            "additionalProperties": False,
        },
    },
    "describe_fields": {
        "description": (
            "List the attrs fields (with value types) and tag keys present for each resource "
            "type in the last scan. Use it to compile policy sentences into rules."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    "propose_rule": {
        "description": (
            "Submit one rule compiled from one policy sentence. A human reviews the exact rule "
            "and approves or rejects it. Only approved rules can be evaluated."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"rule": RULE_SCHEMA},
            "required": ["rule"],
            "additionalProperties": False,
        },
    },
    "evaluate_rules": {
        "description": (
            "Evaluate approved rules against the last scan. Returns, per rule, the exact number "
            "of resources checked and in violation, with evidence. Quote these numbers; "
            "do not recount."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "rule_ids": {
                    "type": "array",
                    "items": {"type": "string", "pattern": r"^R\d{1,3}$"},
                    "minItems": 1,
                    "maxItems": 50,
                }
            },
            "required": ["rule_ids"],
            "additionalProperties": False,
        },
    },
}

TOOL_NAMES = sorted(TOOL_SPECS)

# allowedTools selectors. A plain name matches built-in tools only, so the inline
# functions need the "@*/name" form; measured 2026-11-20: plain names left the model
# with no tools (0 of 2 runs called scan_account), "@*/name" 2 of 2.
ALLOWED_SELECTORS = [f"@*/{n}" for n in TOOL_NAMES]


def harness_tools():
    """The tools list for CreateHarness."""
    return [
        {
            "type": "inline_function",
            "name": name,
            "config": {
                "inlineFunction": {
                    "description": spec["description"],
                    "inputSchema": spec["inputSchema"],
                }
            },
        }
        for name, spec in TOOL_SPECS.items()
    ]


class ToolBox:
    """Client-side tool state for one session."""

    def __init__(self, scan_fn, approver):
        self.scan_fn = scan_fn  # callable(regions) -> (records, errors)
        self.approver = approver  # callable(rule) -> (bool, reason)
        self.records = None
        self.approved = {}
        self.proposed = []  # every rule the model proposed, approved or not, for the transcript

    def call(self, name, args):
        if name not in TOOL_SPECS:
            return {"error": f"unknown tool {name}"}
        if not isinstance(args, dict):
            return {"error": "tool input must be an object"}
        return getattr(self, name)(**args)

    def scan_account(self, regions=None):
        if regions and not all(
            isinstance(r, str) and re.match(REGION_RE, r) for r in regions
        ):
            return {"error": "bad region name"}
        self.records, errors = self.scan_fn(regions)
        counts = {}
        for r in self.records:
            counts[r["type"]] = counts.get(r["type"], 0) + 1
        return {"resources": len(self.records), "by_type": counts, "errors": errors}

    def describe_fields(self):
        if self.records is None:
            return {"error": "call scan_account first"}
        return rules.field_catalog(self.records)

    def propose_rule(self, rule):
        catalog = (
            rules.field_catalog(self.records) if self.records is not None else None
        )
        errors = rules.validate_rule(rule, catalog)
        if errors:
            return {"approved": False, "errors": errors}
        rule_id = f"R{len(self.proposed) + 1}"
        rule = {**rule, "id": rule_id}
        ok, reason = self.approver(rule)
        self.proposed.append({"rule": rule, "approved": ok, "reason": reason})
        if ok:
            self.approved[rule_id] = rule
        return {"rule_id": rule_id, "approved": ok, "reason": reason, "rule": rule}

    def evaluate_rules(self, rule_ids):
        if self.records is None:
            return {"error": "call scan_account first"}
        out = []
        for rid in rule_ids:
            if rid not in self.approved:
                out.append(
                    {"rule_id": rid, "error": "not an approved rule; it was not run"}
                )
                continue
            out.append(rules.evaluate(self.approved[rid], self.records))
        return {"results": out}


def as_tool_result(tool_use_id, payload):
    status = "error" if isinstance(payload, dict) and "error" in payload else "success"
    return {
        "toolResult": {
            "toolUseId": tool_use_id,
            "status": status,
            # Text, not a json block: the harness rejected json with "content_type=<json_> | unsupported type".
            "content": [{"text": json.dumps(payload, default=str)}],
        }
    }
