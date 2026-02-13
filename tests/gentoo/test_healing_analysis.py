#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)  # type: ignore[attr-defined]
    return module


class HealingAnalysisTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        repo = Path(__file__).resolve().parents[2]
        scripts = repo / "scripts/gentoo"
        cls.analyze_mod = load_module("analyze_healing", scripts / "analyze-healing.py")
        cls.pattern_mod = load_module("detect_patterns", scripts / "detect-patterns.py")
        cls.fp_mod = load_module("false_positive_detector", scripts / "false-positive-detector.py")
        cls.sample_log = repo / "data/gentoo/healing-analysis/sample-healing.jsonl"

    def test_analyze_healing_summary(self) -> None:
        summary = self.analyze_mod.analyze(self.sample_log)
        self.assertEqual(summary["total_healing_actions"], 5)
        self.assertEqual(summary["breakdown"]["ClampSize"], 2)
        self.assertIn("dev-db/redis", summary["by_package"])

    def test_detect_patterns(self) -> None:
        summary = self.analyze_mod.analyze(self.sample_log)
        patterns = self.pattern_mod.detect_patterns(summary)
        actions = {p["healing_action"] for p in patterns}
        self.assertIn("ClampSize", actions)
        self.assertIn("TruncateWithNull", actions)

    def test_false_positive_detector(self) -> None:
        summary = self.analyze_mod.analyze(self.sample_log)
        candidates = self.fp_mod.detect_false_positives(summary, max_action_rate_per_1000=50.0, clamp_margin=0.05)
        self.assertGreaterEqual(len(candidates), 1)


if __name__ == "__main__":
    unittest.main()
