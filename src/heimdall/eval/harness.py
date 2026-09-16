"""Evaluation harness — the training loop that makes "high detection" a number.

Loads a suite and its frozen ``expected.json`` (ground truth you confirmed by
hand), scans the vulnerable target, and matches findings to expected rows on
``(check, method, path_template)``. Prints precision / recall / F1. If the
suite defines a ``safe_target`` (e.g. VAmPI with ``vulnerable=0``), it scans
that too and reports the false-positive rate — the same target run must find
nothing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from heimdall.engine import Suite, scan, scan_suite
from heimdall.models import Finding


@dataclass
class EvalResult:
    suite: str
    tp: int
    fp: int
    fn: int
    matched: list[str]
    missed: list[dict]
    unexpected: list[str]
    safe_fp: int = 0
    safe_findings: list[str] = None  # type: ignore

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 1.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "suite": self.suite,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "safe_target_false_positives": self.safe_fp,
            "matched": self.matched,
            "missed": self.missed,
            "unexpected": self.unexpected,
            "safe_findings": self.safe_findings or [],
        }


def _key(check: str, method: str, path: str) -> str:
    return f"{check}|{method.upper()}|{path}"


def _finding_key(f: Finding) -> str:
    return _key(f.check_id, f.method, f.path_template)


def load_expected(path: Path) -> list[dict]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    # Support either a bare list or {"expected": [...]}.
    return data["expected"] if isinstance(data, dict) else data


def evaluate(suite: Suite, **scan_overrides) -> EvalResult:
    expected_path = suite.resolve(suite.expected)
    if not expected_path or not expected_path.exists():
        raise FileNotFoundError(f"expected.json not found for suite {suite.name!r}")
    expected = [row for row in load_expected(expected_path) if row.get("must_detect", True)]

    findings = scan_suite(suite, **scan_overrides)
    found_keys = {_finding_key(f) for f in findings}

    expected_keys = {_key(r["check"], r["method"], r["path"]): r for r in expected}

    matched, missed = [], []
    for k, row in expected_keys.items():
        if k in found_keys:
            matched.append(row.get("id", k))
        else:
            missed.append(row)
    unexpected = sorted(found_keys - set(expected_keys))

    tp = len(matched)
    fn = len(missed)
    fp = len(unexpected)

    result = EvalResult(
        suite=suite.name,
        tp=tp,
        fp=fp,
        fn=fn,
        matched=matched,
        missed=[{"id": r.get("id"), "check": r["check"], "endpoint": f'{r["method"]} {r["path"]}'} for r in missed],
        unexpected=unexpected,
    )

    if suite.safe_target:
        safe = scan(
            suite.safe_target,
            suite.safe_checks or suite.checks,
            openapi=(suite.openapi or "").replace(suite.target, suite.safe_target) or None,
            auth=suite.auth,
            hints=suite.hints,
            payloads_dir=suite.resolve(suite.payloads_dir),
            exclude=suite.exclude,
            **scan_overrides,
        )
        result.safe_findings = sorted(_finding_key(f) for f in safe)
        result.safe_fp = len(safe)

    return result
