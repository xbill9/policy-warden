# Policy Warden

An agent on Amazon Bedrock AgentCore Harness with one job: check an AWS account against a policy you write in plain English, and report every violation with evidence.

```
Every EBS volume must be attached to an instance.
No security group rule may open port 22 to 0.0.0.0/0.
No AWS service may cost more than $50 so far this month.
```

The model translates each sentence into a structured rule. You approve or reject the exact rule. Code applies it to a read-only scan of the account and does all the counting. The model quotes the numbers.

Entry for the AWS Builder Center hackathon *Agents, your rules: Bedrock Managed Agents build* (deadline 2026-12-02, 11:59 PM PST).

#### How a rule becomes a number

```mermaid
flowchart LR
    U[Operator] -->|policy in English| H[AgentCore Harness<br/>Claude Sonnet 4.6]
    H -->|before_invocation| G[Gate Lambda<br/>+ Bedrock Guardrail]
    H -->|propose_rule / evaluate_rules<br/>inline tools| C[Client on your machine]
    H -.->|before_tool_call<br/>after_tool_call| G
    C -->|shows compiled rule| U
    C -->|assume role| A[Auditor role<br/>read-only, deny all writes]
    A --> AWS[(EC2, EBS, SG, EIP,<br/>S3, Cost Explorer)]
    C -->|rules.py: exact counts| H
```

The rule set, and what enforces each rule, is in [RULES.md](RULES.md). Four layers stand between a hostile prompt and the account:

| Layer | What it stops |
|---|---|
| **IAM**: auditor role allows reads and denies everything else; the harness role can reach one model and one Lambda | Any write, from any path, even if every other layer fails |
| **Harness config**: four inline tools, `allowedTools`, iteration/token/time limits | Built-in shell and file tools, runaway sessions |
| **Gate Lambda hooks**: `before_invocation`, `before_tool_call`, `after_tool_call`, `failureMode: deny` | Prompt attacks in the request, tools off the allowlist, malformed rules, instructions or keys hidden in resource tags |
| **Human approval and code**: rules run only after approval; `rules.py` computes every count | Unapproved rules, model arithmetic, a wrong operator slipping through unseen |

#### Web UI

`make ui` serves a page on `127.0.0.1:8765`, reachable from this machine only. On it you:

- add and remove policy sentences (saved to `policy.md`)
- run a check and approve or reject each compiled rule as the agent proposes it
- read reports: per rule, resources checked, violations and the evidence table, plus anything the gate blocked

Every number on the page comes from the `evaluate_rules` results; the agent's own text is shown separately and labelled as model text. Reports are saved to `results/runs/` (gitignored: they hold your account's resource ids). Tag values are escaped before display.

`python3 tests/ui_fixture.py` serves the same page with a scripted run and synthetic resources, with no AWS or model calls, for looking at the UI offline.

#### Layout

| Path | What it is |
|---|---|
| `warden/rules.py` | Rule language: validation and evaluation. Pure Python, shared by the client and the gate Lambda |
| `warden/scanner.py` | Read-only inventory, flattened into records |
| `warden/tools.py` | The four inline tools and their JSON schemas |
| `warden/agent.py` | Client: invokes the harness, runs tool calls under the auditor role, returns results |
| `warden/config.py` | Names, model, limits, system prompt |
| `warden/web.py`, `warden/static/index.html` | Local web UI: policy editor, rule approval, reports |
| `warden/report.py` | Builds a report from a transcript; numbers only from `evaluate_rules` results |
| `hooks/gate.py` | Gate Lambda for all three hooks |
| `infra/deploy.py`, `infra/teardown.py` | Create or delete the guardrail, Lambda, three roles and harness |
| `infra/iam/*.json`, `infra/guardrail.json` | The policies and guardrail, as deployed |
| `infra/seed.py` | Plants known violations, including a prompt injection in a tag and a fake key |
| `stress/cases.json`, `stress/run.py` | Seven hostile prompts, scored by checks in code |
| `tests/test_offline.py`, `tests/test_web.py` | Offline tests: engine, schemas, gate decisions, web API |
| `tests/fakes.py`, `tests/ui_fixture.py` | Scripted run for UI tests and offline viewing |

#### Run it

```
make install
make check            # offline
make deploy           # guardrail, Lambda, roles, harness in us-east-1
make seed             # plant violations
make run              # approve each rule at the prompt
make ui               # or: web UI on http://127.0.0.1:8765
make stress           # results/stress-<time>.md and .json
make unseed teardown
```

Needs AWS credentials that can create IAM roles, a Lambda function, a guardrail and a harness, and Bedrock access to `us.anthropic.claude-sonnet-4-6` (override with `WARDEN_MODEL`; a model whose Marketplace agreement is not yet accepted in the account fails with AccessDeniedException).

#### Status

Offline tests: 24 of 24 pass (`make test`). The web UI was exercised in Chrome against the scripted run: add a rule, run, approve and reject, read the report. Not yet run against AWS: `make deploy`, `make run`, `make ui` with a real run, `make stress`. Four things rest on docs and the boto3 1.43.118 service model, not on a run:

- Inline tool calls that a `before_tool_call` hook skips: the client treats a tool use as pending only if the stream carries no `toolResult` for it.
- `allowedTools` selectors for inline functions are the function names.
- The Guardrail prompt-attack filter flags injected text when it is sent to `ApplyGuardrail` as `INPUT` without input tags.
- The harness microVM uses the execution role for its own AWS calls, so the explicit deny covers its shell.

#### Scope

Single account, single region for the harness, seven resource types. Per-resource cost estimates are not included; cost rules use Cost Explorer's month-to-date figure per service.
