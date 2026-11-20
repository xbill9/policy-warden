"""A scripted stand-in for warden.agent.run, for offline UI tests only.

It makes no model or AWS call. It proposes fixed rules through the real
approver, evaluates approved ones with the real rule engine on the synthetic
RECORDS below, and appends the same transcript entries the real client does.
"""

from warden import rules

RECORDS = [
    {
        "arn": "arn:aws:ec2:us-east-1:000000000000:volume/vol-test1",
        "type": "ec2:volume",
        "region": "us-east-1",
        "attrs": {"size_gib": 1, "attached": False},
        "tags": {"Name": "<img src=x onerror=alert(1)>"},
    },
    {
        "arn": "arn:aws:ec2:us-east-1:000000000000:volume/vol-test2",
        "type": "ec2:volume",
        "region": "us-east-1",
        "attrs": {"size_gib": 20, "attached": True},
        "tags": {"owner": "a"},
    },
    {
        "arn": "arn:aws:ec2:us-east-1:000000000000:security-group/sg-test#tcp:22-22:0.0.0.0/0",
        "type": "ec2:security-group-rule",
        "region": "us-east-1",
        "attrs": {"from_port": 22, "to_port": 22, "open_to_world": True},
        "tags": {},
    },
]

SCRIPT = [
    {
        "text": "Every EBS volume must be attached to an instance.",
        "resource_type": "ec2:volume",
        "where": [{"field": "attrs.attached", "op": "eq", "value": False}],
    },
    {
        "text": "Every EBS volume must have an owner tag.",
        "resource_type": "ec2:volume",
        "where": [
            {"field": "tags.owner", "op": "missing"},
            {"field": "tags.Name", "op": "exists"},
        ],
    },
    {
        "text": "No security group rule may open port 22 to 0.0.0.0/0.",
        "resource_type": "ec2:security-group-rule",
        "where": [
            {"field": "attrs.from_port", "op": "lte", "value": 22},
            {"field": "attrs.to_port", "op": "gte", "value": 22},
            {"field": "attrs.open_to_world", "op": "eq", "value": True},
        ],
    },
]


def fake_run(
    prompt, approve="ask", echo=True, state=None, approver=None, transcript=None
):
    t = transcript if transcript is not None else []
    t.append({"kind": "prompt", "text": prompt, "session": "fake"})
    t.append(
        {
            "kind": "tool_result",
            "tool": "scan_account",
            "id": "t0",
            "result": {"resources": len(RECORDS), "by_type": {}, "errors": []},
        }
    )
    proposed, approved = [], []
    for i, r in enumerate(SCRIPT, 1):
        rule = {**r, "id": f"R{i}"}
        ok, reason = approver(rule)
        proposed.append({"rule": rule, "approved": ok, "reason": reason})
        t.append(
            {
                "kind": "tool_result",
                "tool": "propose_rule",
                "id": f"t{i}",
                "result": {
                    "rule_id": rule["id"],
                    "approved": ok,
                    "reason": reason,
                    "rule": rule,
                },
            }
        )
        if ok:
            approved.append(rule)
    t.append(
        {
            "kind": "hook",
            "name": "screen_tool_result",
            "type": "after_tool_call",
            "decision": "deny",
            "reason": "scripted denial for the UI test",
        }
    )
    t.append(
        {
            "kind": "tool_result",
            "tool": "evaluate_rules",
            "id": "t9",
            "result": {"results": [rules.evaluate(r, RECORDS) for r in approved]},
        }
    )
    t.append({"kind": "text", "text": "Scripted summary text."})
    t.append({"kind": "stop", "reason": "end_turn"})
    t.append({"kind": "rules", "proposed": proposed})
    return t
