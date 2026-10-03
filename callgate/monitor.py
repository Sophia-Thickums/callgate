"""callgate.monitor — the in-path wrapper and the audit trail.

Usage as a guard around any tool dispatcher:

    from callgate import monitor
    gate = monitor.Gate(log_path="callgate.jsonl", unknown_policy="block")
    result = gate.run("http_post", {"url": "...", "body": "..."}, real_tool_fn)

The gate never calls the tool when the verdict is DENY, and (by default) never calls
it on UNKNOWN either — it records the call and returns a refusal the caller can see.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import asdict

from .rules import evaluate, ALLOW, DENY, UNKNOWN


class Gate:
    def __init__(self, log_path: str = "callgate.jsonl", unknown_policy: str = "block"):
        assert unknown_policy in ("block", "allow"), "unknown_policy is block|allow"
        self.log_path = log_path
        self.unknown_policy = unknown_policy
        self.counts = {ALLOW: 0, DENY: 0, UNKNOWN: 0}

    def _log(self, record: dict):
        record["ts"] = time.time()
        with open(self.log_path, "a") as f:
            f.write(json.dumps(record) + "\n")

    def check(self, tool: str, args: dict) -> dict:
        verdict = evaluate(tool, args)
        self.counts[verdict.action] = self.counts.get(verdict.action, 0) + 1
        self._log({"tool": tool, **verdict.as_dict()})
        return verdict.as_dict()

    def run(self, tool: str, args: dict, fn):
        """Check, then either call fn(args) or refuse. Refusal is a value, not an exception."""
        verdict = self.check(tool, args)
        if verdict["action"] == DENY:
            return {"gate": "denied", "verdict": verdict}
        if verdict["action"] == UNKNOWN and self.unknown_policy == "block":
            return {"gate": "held_for_review", "verdict": verdict}
        return {"gate": "allowed", "verdict": verdict, "result": fn(**args)}
