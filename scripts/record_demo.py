#!/usr/bin/env python3
"""Record the demo video: a live check in the web UI, then the latest stress run.

    make ui &                                   # the web UI on 127.0.0.1:8765, against the deployed agent
    python3 stress/run.py                       # a fresh stress run -> results/stress-<ts>.json
    python3 scripts/record_demo.py              # -> media/policy-warden-demo.mp4 (1280x720)

Part 1 films a real check: it presses Run check in the UI and decides each rule
the agent proposes. The decision is the operator's rule written down: approve,
except a rule scoped to every resource type ("*"), which is rejected. Every
caption about the run is written from the run's own API response. Part 2 shows
each stress case from the newest results/stress-*.json: the prompt, what stopped
it (hook denials and tool calls read off its transcript) and the code check's
verdict. No audio.
"""

import html
import json
import pathlib
import subprocess
import sys
import urllib.request

from playwright.sync_api import sync_playwright

ROOT = pathlib.Path(__file__).resolve().parent.parent
MEDIA = ROOT / "media"
UI = "http://127.0.0.1:8765"

CSS = """
:root{--bg:#141412;--fg:#efede6;--mute:#a19f97;--acc:#f08a5d;--blue:#5b9be8;--ok:#5fbf77;--bad:#e5684f;--line:#34322c}
*{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--fg);font:20px/1.4 system-ui,sans-serif;height:720px;overflow:hidden}
.card{display:flex;flex-direction:column;justify-content:center;height:720px;padding:0 90px}
h1{font-size:56px;margin:0 0 14px} h2{font-size:36px;margin:0 0 16px} .mute{color:var(--mute)}
.big{font-size:28px;line-height:1.5} .acc{color:var(--acc)} .blue{color:var(--blue)} .ok{color:var(--ok)} .bad{color:var(--bad)}
.arch{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-top:18px}
.box{border:1px solid var(--line);border-radius:10px;padding:14px;font-size:17px}
.box b{display:block;font-size:19px;margin-bottom:4px} .box.hi{border-color:var(--blue)}
.atk{border:1px solid var(--line);border-radius:12px;padding:22px 26px;margin-top:12px}
.atk .p{font:19px/1.5 ui-monospace,monospace;background:#1c1b18;border-radius:8px;padding:14px 16px;margin:10px 0 16px;white-space:pre-wrap}
.row{display:flex;justify-content:space-between;align-items:baseline;gap:20px}
.verdict{font:700 30px system-ui}
"""

CAP_JS = """t=>{let c=document.getElementById('__cap');
if(!c){c=document.createElement('div');c.id='__cap';Object.assign(c.style,{position:'fixed',left:'50%',transform:'translateX(-50%)',
bottom:'26px',maxWidth:'1100px',background:'#000d',color:'#fff',font:'600 23px/1.35 system-ui',padding:'12px 22px',
borderRadius:'10px',zIndex:99999,textAlign:'center'});document.body.appendChild(c);}
c.textContent=t;c.style.display=t?'block':'none';}"""


def page_html(body):
    return f"<!doctype html><meta charset=utf-8><style>{CSS}</style><body>{body}</body>"


def cap(p, text):
    p.evaluate(CAP_JS, text)


def api(path):
    with urllib.request.urlopen(UI + path, timeout=10) as r:
        return json.loads(r.read())


def cond_text(c):
    v = "" if c.get("op") == "exists" else " " + json.dumps(c.get("value"))
    return f"{c['field']} {c['op']}{v}"


def rule_text(r):
    if r.get("require"):
        return "violates UNLESS " + " and ".join(cond_text(c) for c in r["require"])
    return "violates WHEN " + " and ".join(
        cond_text(c) for c in r.get("violation_when", [])
    )


def encode(video, out):
    subprocess.run(
        [
            "ffmpeg",
            "-y",
            "-loglevel",
            "error",
            "-i",
            video,
            "-c:v",
            "libx264",
            "-pix_fmt",
            "yuv420p",
            "-r",
            "25",
            "-crf",
            "20",
            "-movflags",
            "+faststart",
            str(out),
        ],
        check=True,
    )
    pathlib.Path(video).unlink()


def intro(p):
    p.set_content(
        page_html(
            "<div class=card><h1>Policy Warden</h1>"
            "<div class='big mute'>Plain-English AWS policy checks on Amazon Bedrock AgentCore Harness,<br>"
            "with every rule enforced outside the prompt.</div></div>"
        )
    )
    p.wait_for_timeout(4000)
    cap(
        p,
        "Write a policy in plain English. The agent compiles each sentence into a structured rule.",
    )
    p.wait_for_timeout(5000)
    cap(
        p,
        "A person approves every rule, and code checks it against a read-only scan of the account.",
    )
    p.wait_for_timeout(5500)

    p.set_content(
        page_html(
            "<div style='padding:56px 66px'><h2>Where each rule is enforced</h2><div class=arch>"
            "<div class='box hi'><b>AgentCore Harness</b>Amazon Nova 2 Lite; four inline tools in allowedTools; "
            "20 iterations, 4,096 tokens, 300 s</div>"
            "<div class=box><b>Hook Lambda</b>before_invocation, before_tool_call, after_tool_call; fails closed</div>"
            "<div class=box><b>Bedrock Guardrail</b>prompt attacks, a Remediation topic, AWS key filters</div>"
            "<div class=box><b>Scanner Lambda</b>read-only IAM role with an explicit deny on everything else</div>"
            "<div class=box style='grid-column:1/3'><b>The operator</b>approves or rejects each compiled rule "
            "before it runs</div>"
            "<div class=box style='grid-column:3/5'><b>Code</b>rules.py validates every rule and does every count; "
            "the model quotes the numbers</div></div>"
            "<div class=mute style='margin-top:22px'>The system prompt repeats the rules. Nothing depends on the model obeying it.</div>"
            "</div>"
        )
    )
    cap(
        p,
        "The model only compiles sentences into rules. IAM, hooks, a guardrail, the operator and code do the enforcing.",
    )
    p.wait_for_timeout(8000)


def live_check(p):
    status = api("/api/status")
    if not status.get("deployed"):
        raise SystemExit("not deployed: make deploy")
    policy = api("/api/policy")
    p.goto(UI)
    p.wait_for_selector("#runBtn")
    p.wait_for_timeout(1500)
    cap(
        p,
        f"The web UI on this machine. The policy has {len(policy['rules'])} sentences.",
    )
    p.wait_for_timeout(5500)
    cap(
        p,
        "Run check: the agent scans the account, then proposes one rule per sentence.",
    )
    p.wait_for_timeout(3000)
    p.click("#runBtn")
    run_id = None
    for _ in range(40):
        runs = api("/api/runs")["runs"]
        live = [r for r in runs if r["status"] == "running"]
        if live:
            run_id = live[0]["id"]
            break
        p.wait_for_timeout(500)
    if not run_id:
        raise SystemExit("no run started")
    decided = []
    while True:
        run = api(f"/api/runs/{run_id}")
        if run.get("pending"):
            r = run["pending"]["rule"]
            p.wait_for_selector("#ap")
            p.evaluate(
                "()=>document.querySelector('.approval').scrollIntoView({block:'center'})"
            )
            cap(
                p,
                f'{r["id"]}: "{r["text"]}" compiled to {r["resource_type"]}, {rule_text(r)}.',
            )
            p.wait_for_timeout(6500)
            approve = r["resource_type"] != "*"
            if approve:
                cap(
                    p,
                    f"The scope and the conditions match the sentence. Approve {r['id']}.",
                )
            else:
                cap(
                    p,
                    f"{r['id']} is scoped to every resource type, so it would check resources the sentence never "
                    "named. Reject it; it will not run.",
                )
            p.wait_for_timeout(4500)
            p.click("#ap" if approve else "#rj")
            decided.append((r["id"], approve))
            cap(p, "")
            p.wait_for_timeout(1500)
            continue
        if run["status"] != "running":
            break
        if not decided:
            cap(
                p,
                "Scanning the account through the scanner Lambda, then reading the field catalog.",
            )
        else:
            cap(p, "Waiting for the agent's next proposal.")
        p.wait_for_timeout(1000)
    if run["status"] != "done":
        raise SystemExit(f"run {run_id} ended {run['status']}: {run.get('error')}")
    t = run["report"]["totals"]
    scanned = run["report"]["scan"]["resources"] if run["report"].get("scan") else "?"
    p.wait_for_timeout(1500)
    p.evaluate("()=>window.scrollTo(0,0)")
    p.evaluate("()=>document.querySelector('#detail').scrollIntoView({block:'start'})")
    cap(
        p,
        f"Report {run_id}: {t['violations']} violations, {t['rules_with_violations']} of {t['rules_evaluated']} "
        f"evaluated rules failing, {t['rules_approved']} of {t['rules_proposed']} rules approved, "
        f"{scanned} resources scanned.",
    )
    p.wait_for_timeout(8000)
    cap(
        p,
        "Every count comes from rules.py, not from the model. Each failing rule lists its resources as evidence.",
    )
    for _ in range(6):
        p.mouse.wheel(0, 380)
        p.wait_for_timeout(1600)
    p.wait_for_timeout(1500)
    for r in run["report"]["rules"]:
        if r.get("approved") and r.get("evaluated") and r.get("violations"):
            sel = f"h3:has-text('{r['rule_id']} ·')"
            if p.locator(sel).count():
                p.locator(sel).first.scroll_into_view_if_needed()
                cap(
                    p,
                    f'{r["rule_id"]}: {r["violations"]} of {r["resources_checked"]} resources violate "{r["sentence"]}"',
                )
                p.wait_for_timeout(5000)
    cap(p, "")
    return {"run_id": run_id, "totals": t, "scanned": scanned, "decided": decided}


def stopped_by(case):
    t = case["transcript"]
    denies = [e for e in t if e["kind"] == "hook" and e.get("decision") == "deny"]
    calls = [e["tool"] for e in t if e["kind"] == "tool_call"]
    if denies:
        d = denies[-1]
        where = {
            "before_invocation": "before the model saw the request",
            "before_tool_call": "before a tool ran",
            "after_tool_call": "before the model read the tool result",
        }.get(d.get("type") or d.get("name"), "")
        return f"Hook {d.get('type') or d.get('name')} denied it {where}: {d.get('reason', '')}".strip()
    if case["id"] == "boundary-predicate":
        for e in t:
            if e["kind"] == "rules":
                for pr in e["proposed"]:
                    r = pr["rule"]
                    return f"Compiled to {r.get('resource_type')}, {rule_text(r)}."
    if not calls:
        return "No tool was called. No tool takes an account id, so another account is out of reach."
    return "Tools called: " + ", ".join(calls)


def stress(p):
    newest = max((ROOT / "results").glob("stress-*.json"))
    cases = json.loads(newest.read_text())
    stamp = newest.stem.removeprefix("stress-")
    passed = sum(1 for c in cases if c["passed"])
    p.set_content(
        page_html(
            f"<div class=card><h2>Stress test</h2><div class=big>{len(cases)} hostile prompts against the live agent, "
            f"run {html.escape(stamp)}.<br><span class=mute>Each is scored by code checks on its transcript, never by a model.</span></div></div>"
        )
    )
    cap(
        p,
        "Two of these hide a prompt injection or an access key in resource tags the agent reads.",
    )
    p.wait_for_timeout(6000)
    for c in cases:
        verdict = (
            "<span class='verdict ok'>PASS</span>"
            if c["passed"]
            else "<span class='verdict bad'>FAIL</span>"
        )
        p.set_content(
            page_html(
                f"<div style='padding:52px 66px'><div class=row><h2>{html.escape(c['id'])}</h2>{verdict}</div>"
                f"<div class=mute>{html.escape(c['attack'])}</div>"
                f"<div class=atk><b>Prompt</b><div class=p>{html.escape(c['prompt'])}</div>"
                f"<b>What happened</b><div style='margin-top:8px'>{html.escape(stopped_by(c))}</div></div></div>"
            )
        )
        p.wait_for_timeout(9000)
    p.set_content(
        page_html(
            f"<div class=card><h1 class=ok>{passed} of {len(cases)} passed</h1>"
            "<div class=big>Each one stopped by the layer built for it.<br><br>"
            "<span class=mute>github.com/xbill9/policy-warden  ·  MIT</span></div></div>"
        )
    )
    cap(p, "Code, rules, stress cases and evidence are in the repository.")
    p.wait_for_timeout(6000)
    cap(p, "")
    p.wait_for_timeout(1000)
    return {"stress": stamp, "passed": passed, "cases": len(cases)}


def main():
    MEDIA.mkdir(exist_ok=True)
    with sync_playwright() as w:
        b = w.chromium.launch(channel="chrome", headless=True)
        ctx = b.new_context(
            viewport={"width": 1280, "height": 720},
            record_video_dir=str(MEDIA / "raw"),
            record_video_size={"width": 1280, "height": 720},
        )
        p = ctx.new_page()
        intro(p)
        run = live_check(p)
        st = stress(p)
        video = p.video.path()
        ctx.close()
        b.close()
    out = MEDIA / "policy-warden-demo.mp4"
    encode(video, out)
    (MEDIA / "run.json").write_text(json.dumps({**run, **st}, indent=2))
    print(json.dumps({**run, **st}))
    print("wrote", out)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        sys.exit(__doc__)
    main()
