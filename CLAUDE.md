# Policy Warden

AgentCore Harness agent that checks one AWS account against a plain-English policy. Hackathon: Agents, your rules (due 2026-12-02 11:59 PM PST). Rule set and enforcement map: RULES.md.

## Commands

`make check` (offline lint + tests), `make deploy`, `make seed`, `make run`, `make ui` (web UI, 127.0.0.1:8765), `make stress`, `make unseed`, `make teardown`. `make help` lists all.

## Invariants

- Every count comes from `warden/rules.py`. Never let the model compute a number.
- `warden/rules.py` is shared with the gate Lambda; `infra/deploy.py` zips it. Keep it free of boto3.
- The auditor role's NotAction deny is the last line of defence. Do not widen it.
- `stress/run.py` scores by code checks on transcripts. Check the rule the model sent, not just the number it quoted.
- The web UI must escape every value it renders: tag values come from the account and anyone who can tag a resource writes them.
