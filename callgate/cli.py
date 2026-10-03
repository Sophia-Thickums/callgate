"""callgate CLI — check tool calls from a JSONL stream, or run the self-test.

    callgate check  calls.jsonl        # one {tool, args} object per line
    callgate test                      # run the built-in suite (incl. the negative control)
    echo '{"tool":"http_post","args":{"url":"https://x","body":"sk-..."}}' | callgate -
"""
from __future__ import annotations

import json
import sys

from .rules import evaluate, ALLOW, DENY, UNKNOWN
from . import selftest


def _fmt(v) -> str:
    action = v.action if hasattr(v, "action") else v["action"]
    rule = v.rule if hasattr(v, "rule") else v["rule"]
    reason = v.reason if hasattr(v, "reason") else v["reason"]
    mark = {ALLOW: "ALLOW  ", DENY: "DENY   ", UNKNOWN: "UNKNOWN"}.get(action, action)
    return f"[{mark}] {rule:16s} {reason}"


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    cmd = argv[0]

    if cmd == "test":
        return selftest.run()

    if cmd == "check":
        if len(argv) < 2:
            print("usage: callgate check <file.jsonl>", file=sys.stderr)
            return 2
        with open(argv[1]) as f:
            lines = f.readlines()
    elif cmd == "-":
        lines = sys.stdin.readlines()
    else:
        print(f"unknown command: {cmd}", file=sys.stderr)
        return 2

    worst = ALLOW
    for n, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            print(f"line {n}: bad json ({e})", file=sys.stderr)
            continue
        v = evaluate(obj.get("tool", ""), obj.get("args", {}))
        print(f"line {n}: {_fmt(v)}")
        if v.action == DENY:
            worst = DENY
        elif v.action == UNKNOWN and worst != DENY:
            worst = UNKNOWN
    # exit code carries the verdict: 0 allow, 3 unknown, 4 deny
    return {ALLOW: 0, UNKNOWN: 3, DENY: 4}.get(worst, 0)


if __name__ == "__main__":
    raise SystemExit(main())
