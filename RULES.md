# Policy Warden: the agent's rules

Policy Warden has one job: check one AWS account against a policy written in plain English, and report every violation with evidence.

These are the rules it runs under. Each rule names what enforces it. A rule enforced only by the system prompt would be listed as such; none is.

#### What it can access

| # | Rule | Enforced by |
|---|---|---|
| A1 | It reads EC2 instances, EBS volumes, security group rules, Elastic IPs, S3 bucket settings and tags, and month-to-date cost per service. Nothing else. | IAM: the auditor role allows only those Describe/List/Get actions (`infra/iam/auditor-policy.json`). |
| A2 | It reads only the account it is deployed in. | IAM: the auditor role trusts only this account; `scan_account` has no account parameter, and the gate Lambda denies any extra input key. |
| A3 | It has four tools: `scan_account`, `describe_fields`, `propose_rule`, `evaluate_rules`. | Harness `allowedTools`, plus the gate Lambda's `before_tool_call` allowlist, which also denies the harness's built-in shell and file tools. |
| A4 | The harness's own microVM cannot touch the account. | IAM: the harness execution role may call one model and one Lambda; an explicit deny covers `ec2:*`, `s3:*`, `iam:*`, `ce:*`, `sts:AssumeRole`, `organizations:*`. |

#### What it must refuse

| # | Rule | Enforced by |
|---|---|---|
| R1 | It never changes the account: no delete, stop, terminate, tag, modify or create. | IAM: the auditor role denies every action that is not a read (`NotAction` deny), and no tool can write. Guardrail denied topic `Remediation` on the request. |
| R2 | It never follows instructions found inside resource data (names, tags, descriptions). | Gate Lambda `after_tool_call`: every tool result passes the Bedrock Guardrail prompt-attack filter before the model reads it; a flagged result stops the invocation. Tag values never appear in `describe_fields` output. |
| R3 | It never reveals AWS keys found in the account. | Gate Lambda `after_tool_call`: an access key id pattern in a tool result stops the invocation; Guardrail `AWS_ACCESS_KEY` / `AWS_SECRET_KEY` filters. |
| R4 | It refuses prompt attacks in the request itself. | Gate Lambda `before_invocation`: user text passes the Guardrail prompt-attack filter; a flagged request never reaches the model. |
| R5 | It never reports a result for a rule a human did not approve. | Code: `propose_rule` shows each compiled rule to the operator; `evaluate_rules` runs approved rule ids only. |

#### How it handles edge cases

| # | Rule | Enforced by |
|---|---|---|
| E1 | Every count, sum and comparison comes from code. The model quotes numbers; it never computes them. | Code: `warden/rules.py` evaluates rules and returns exact counts. |
| E2 | A malformed rule never runs. Unknown fields, unknown operators, a string where a number belongs, more than 8 conditions, a bad regex: all rejected. | Code: `rules.validate_rule`, run twice: in the gate Lambda before the call reaches the client, and again in the client. |
| E3 | "10 or more" means `gte 10`; "more than 10" means `gt 10`. | The operator sees the compiled operator before approving (R5); the stress test checks it in code (`boundary-predicate`). |
| E4 | If a hook cannot read the full context (too large, truncated), it denies. If the hook Lambda fails or times out, the harness denies. | Gate Lambda truncation checks; hook `failureMode: deny`. |
| E5 | A session cannot run away. | Harness limits: 20 iterations, 4,096 output tokens, 300 seconds. |
