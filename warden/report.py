"""Turn a session transcript into a report. Every number comes from evaluate_rules
results recorded in the transcript; the model's own text is kept separately as
its summary and is never parsed for figures."""


def build_report(transcript):
    proposed = next((e["proposed"] for e in transcript if e["kind"] == "rules"), None)
    if proposed is None:  # session still running: rebuild from tool results so far
        proposed = []
        for e in transcript:
            if (
                e["kind"] == "tool_result"
                and e["tool"] == "propose_rule"
                and e["result"].get("rule_id")
            ):
                proposed.append(
                    {
                        "rule": e["result"].get("rule")
                        or {"id": e["result"]["rule_id"]},
                        "approved": e["result"].get("approved"),
                        "reason": e["result"].get("reason"),
                    }
                )
    results = {}
    for e in transcript:
        if e["kind"] == "tool_result" and e["tool"] == "evaluate_rules":
            for r in e["result"].get("results", []):
                results[r.get("rule_id")] = r

    rules = []
    for p in proposed:
        rule = p["rule"]
        r = results.get(rule.get("id"))
        rules.append(
            {
                "rule_id": rule.get("id"),
                "sentence": rule.get("text"),
                "rule": rule,
                "approved": p.get("approved"),
                "reason": p.get("reason"),
                "evaluated": bool(r and "violations" in r),
                "resources_checked": r.get("resources_checked") if r else None,
                "violations": r.get("violations") if r else None,
                "evidence": r.get("evidence", []) if r else [],
                "evidence_truncated": r.get("evidence_truncated", False)
                if r
                else False,
                "violating_monthly_usd": r.get("violating_monthly_usd") if r else None,
                "error": r.get("error") if r else None,
            }
        )

    scans = [
        e["result"]
        for e in transcript
        if e["kind"] == "tool_result" and e["tool"] == "scan_account"
    ]
    evaluated = [r for r in rules if r["evaluated"]]
    return {
        "rules": rules,
        "scan": scans[-1] if scans else None,
        "totals": {
            "rules_proposed": len(rules),
            "rules_approved": sum(1 for r in rules if r["approved"]),
            "rules_evaluated": len(evaluated),
            "rules_with_violations": sum(1 for r in evaluated if r["violations"]),
            "violations": sum(r["violations"] for r in evaluated),
        },
        "hooks_denied": [
            {"name": e.get("name"), "type": e.get("type"), "reason": e.get("reason")}
            for e in transcript
            if e["kind"] == "hook" and e.get("decision") == "deny"
        ],
        "errors": [e for e in transcript if e["kind"] == "error"],
        "stop_reasons": [e["reason"] for e in transcript if e["kind"] == "stop"],
        "agent_summary": "".join(
            e["text"] for e in transcript if e["kind"] == "text"
        ).strip(),
    }
