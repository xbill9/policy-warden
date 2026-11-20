"""Rule language: validation and evaluation. Pure Python, no AWS calls.

Shared by the client (which evaluates rules) and the gate Lambda (which
validates every rule the model proposes before the client ever sees it).
The model writes rules; this module does every count, comparison and sum.
"""

import re

RESOURCE_TYPES = {
    "ec2:instance": "EC2 instances",
    "ec2:volume": "EBS volumes",
    "ec2:security-group-rule": "Inbound security group rules, one record per CIDR",
    "ec2:elastic-ip": "Elastic IP addresses",
    "s3:bucket": "S3 buckets",
    "cost:service": "Month-to-date cost per AWS service",
    "*": "Every resource type except cost:service",
}

OPS = {
    "eq",
    "ne",
    "gt",
    "gte",
    "lt",
    "lte",
    "in",
    "not_in",
    "exists",
    "missing",
    "contains",
    "matches",
}
NUMERIC_OPS = {"gt", "gte", "lt", "lte"}
NO_VALUE_OPS = {"exists", "missing"}
SEVERITIES = {"low", "medium", "high"}

FIELD_RE = re.compile(r"^(region|type|arn|(attrs|tags)\.[A-Za-z0-9_:./@+=-]{1,128})$")
RULE_KEYS = {"id", "text", "resource_type", "require", "violation_when", "severity"}
# A rule states its direction in its key, because models write both forms:
#   require         a resource violates the rule unless ALL conditions hold
#   violation_when  a resource violates the rule when ALL conditions hold
# Measured 2026-11-20 (Nova 2 Lite, one key "where" meaning violation_when): 4 of 7
# rules came back as the compliant condition, which code then counted exactly.
DIRECTIONS = ("require", "violation_when")
MAX_CONDITIONS = 8
MAX_EVIDENCE = 25


def conditions(rule):
    """(direction, conditions) of a rule, or (None, None) if it has not exactly one."""
    present = [d for d in DIRECTIONS if d in rule]
    if len(present) != 1:
        return None, None
    return present[0], rule[present[0]]


def validate_rule(rule, catalog=None):
    """Return a list of error strings. Empty list means the rule is valid.

    catalog (from field_catalog) adds a check that every attrs.* field exists for the
    resource type in the scan; the gate Lambda has no scan and checks syntax only.
    """
    if not isinstance(rule, dict):
        return ["rule must be an object"]
    errors = []
    extra = set(rule) - RULE_KEYS
    if extra:
        errors.append(f"unknown keys: {sorted(extra)}")
    if not isinstance(rule.get("text"), str) or not rule.get("text", "").strip():
        errors.append(
            "text: the English sentence the rule was compiled from is required"
        )
    if rule.get("resource_type") not in RESOURCE_TYPES:
        errors.append(f"resource_type must be one of {sorted(RESOURCE_TYPES)}")
    if rule.get("severity", "medium") not in SEVERITIES:
        errors.append(f"severity must be one of {sorted(SEVERITIES)}")
    direction, conds = conditions(rule)
    if direction is None:
        errors.append(
            "give exactly one of require (must hold) or violation_when (must not hold)"
        )
        return errors
    if not isinstance(conds, list) or not conds:
        errors.append(f"{direction}: a non-empty list of conditions is required")
        return errors
    if len(conds) > MAX_CONDITIONS:
        errors.append(f"{direction}: at most {MAX_CONDITIONS} conditions")
    for i, cond in enumerate(conds):
        errors.extend(f"{direction}[{i}]: {e}" for e in _validate_condition(cond))
    if catalog is not None and not errors:
        errors.extend(_check_fields(rule["resource_type"], conds, catalog))
    return errors


def _check_fields(resource_type, conds, catalog):
    types = (
        [t for t in catalog if t != "cost:service"]
        if resource_type == "*"
        else [resource_type]
    )
    known = set()
    for t in types:
        known.update((catalog.get(t) or {}).get("attrs", {}))
    errs = []
    for c in conds:
        if c["field"].startswith("attrs."):
            name = c["field"][len("attrs.") :]
            if name not in known:
                errs.append(
                    f"field {c['field']} does not exist for {resource_type}; known attrs: {sorted(known)}"
                )
    return errs


def _validate_condition(cond):
    if not isinstance(cond, dict):
        return ["condition must be an object"]
    errs = []
    extra = set(cond) - {"field", "op", "value"}
    if extra:
        errs.append(f"unknown keys: {sorted(extra)}")
    field, op = cond.get("field"), cond.get("op")
    if not isinstance(field, str) or not FIELD_RE.match(field):
        errs.append("field must be region, type, arn, attrs.<name> or tags.<key>")
    if op not in OPS:
        errs.append(f"op must be one of {sorted(OPS)}")
        return errs
    value = cond.get("value")
    if isinstance(field, str) and field.startswith("tags.") and op in NUMERIC_OPS:
        # Tag values are always strings, so a numeric comparison is false for every
        # resource and reports 0 violations. Measured 2026-11-20: Nova 2 Lite wrote
        # tags.Name gt 40 for "a Name tag longer than 40 characters".
        errs.append(
            f"tags are text; {op} cannot compare them. For length use matches, e.g. '^.{{41,}}$' for longer than 40"
        )
        return errs
    if op in NO_VALUE_OPS:
        if "value" in cond:
            errs.append(f"op {op} takes no value")
    elif "value" not in cond:
        errs.append(f"op {op} needs a value")
    elif op in NUMERIC_OPS and (
        isinstance(value, bool) or not isinstance(value, (int, float))
    ):
        errs.append(f"op {op} needs a number")
    elif op in {"in", "not_in"} and not isinstance(value, list):
        errs.append(f"op {op} needs a list")
    elif op == "matches":
        if not isinstance(value, str) or len(value) > 200:
            errs.append("op matches needs a regex string of at most 200 characters")
        else:
            try:
                re.compile(value)
            except re.error as e:
                errs.append(f"bad regex: {e}")
    return errs


_MISSING = object()


def _get(record, field):
    if field in ("region", "type", "arn"):
        return record.get(field, _MISSING)
    scope, _, key = field.partition(".")
    return (record.get(scope) or {}).get(key, _MISSING)


def _holds(actual, op, value):
    if op == "exists":
        return actual is not _MISSING
    if op == "missing":
        return actual is _MISSING
    if actual is _MISSING:
        return False
    if op == "eq":
        return actual == value
    if op == "ne":
        return actual != value
    if op in NUMERIC_OPS:
        if isinstance(actual, bool) or not isinstance(actual, (int, float)):
            return False
        return {
            "gt": actual > value,
            "gte": actual >= value,
            "lt": actual < value,
            "lte": actual <= value,
        }[op]
    if op == "in":
        return actual in value
    if op == "not_in":
        return actual not in value
    if op == "contains":
        return isinstance(actual, (str, list)) and value in actual
    if op == "matches":
        return isinstance(actual, str) and re.search(value, actual) is not None
    raise ValueError(op)


def _in_scope(record, resource_type):
    if resource_type == "*":
        return record["type"] != "cost:service"
    return record["type"] == resource_type


def evaluate(rule, records):
    """Apply one validated rule. Every number in the result is computed here."""
    errors = validate_rule(rule)
    if errors:
        return {"rule_id": rule.get("id"), "error": errors}
    direction, conds = conditions(rule)
    scoped = [r for r in records if _in_scope(r, rule["resource_type"])]

    def all_hold(r):
        return all(_holds(_get(r, c["field"]), c["op"], c.get("value")) for c in conds)

    if direction == "violation_when":
        hits = [r for r in scoped if all_hold(r)]
    else:
        hits = [r for r in scoped if not all_hold(r)]
    fields = [c["field"] for c in conds]
    evidence = []
    for r in hits[:MAX_EVIDENCE]:
        seen = {}
        for f in fields:
            v = _get(r, f)
            seen[f] = "<missing>" if v is _MISSING else v
        evidence.append({"arn": r["arn"], "region": r.get("region"), "values": seen})
    result = {
        "rule_id": rule.get("id"),
        "rule": rule,
        "resources_checked": len(scoped),
        "violations": len(hits),
        "evidence": evidence,
        "evidence_truncated": len(hits) > MAX_EVIDENCE,
    }
    costs = [r["attrs"].get("monthly_usd") for r in hits]
    costs = [c for c in costs if isinstance(c, (int, float))]
    if costs:
        result["violating_monthly_usd"] = round(sum(costs), 2)
    return result


def field_catalog(records):
    """Fields seen per resource type, with value types, for the model to compile against.

    Tag values are never returned here, only tag keys.
    """
    catalog = {}
    for r in records:
        entry = catalog.setdefault(
            r["type"], {"count": 0, "attrs": {}, "tag_keys": set()}
        )
        entry["count"] += 1
        for k, v in (r.get("attrs") or {}).items():
            entry["attrs"][k] = type(v).__name__
        entry["tag_keys"].update((r.get("tags") or {}).keys())
    for entry in catalog.values():
        entry["tag_keys"] = sorted(entry["tag_keys"])[:100]
    return catalog
