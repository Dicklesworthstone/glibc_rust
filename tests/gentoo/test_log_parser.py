#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)  # type: ignore[attr-defined]
    return module


class LogParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        repo = Path(__file__).resolve().parents[2]
        scripts = repo / "scripts/gentoo"
        cls.log_parser = load_module("log_parser", scripts / "log_parser.py")
        cls.log_stats = load_module("log_stats", scripts / "log_stats.py")
        cls.log_validator = load_module("log_validator", scripts / "log_validator.py")
        cls.fixtures = repo / "tests/gentoo/fixtures/sample_logs"

    def test_parse_valid_runtime_log(self) -> None:
        parser = self.log_parser.LogParser(strict=True)
        entries = list(parser.parse_file(self.fixtures / "valid_runtime.jsonl"))
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0].call, "malloc")
        self.assertEqual(entries[0].action, "ClampSize")
        self.assertEqual(entries[0].latency_ns, 185)

    def test_parse_valid_hook_log(self) -> None:
        parser = self.log_parser.LogParser(strict=True)
        entries = list(parser.parse_file(self.fixtures / "valid_hook.jsonl"))
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].call, "__hook_event__")
        self.assertEqual(entries[0].action, "hook_enable")

    def test_invalid_json_raises_in_strict_mode(self) -> None:
        parser = self.log_parser.LogParser(strict=True)
        with self.assertRaises(self.log_parser.ParseError):
            list(parser.parse_file(self.fixtures / "invalid_json.jsonl"))

    def test_invalid_line_collected_in_non_strict_mode(self) -> None:
        parser = self.log_parser.LogParser(strict=False)
        entries = list(parser.parse_file(self.fixtures / "invalid_missing_field.jsonl"))
        self.assertEqual(entries, [])
        self.assertEqual(len(parser.errors), 1)
        self.assertIn("missing required field", str(parser.errors[0]))

    def test_stats_and_validator(self) -> None:
        parser = self.log_parser.LogParser(strict=True)
        entries = list(parser.parse_file(self.fixtures / "valid_runtime.jsonl"))

        stats = self.log_stats.LogStats()
        stats.extend(entries)
        snapshot = stats.to_dict()
        self.assertEqual(snapshot["total_entries"], 2)
        self.assertIn("malloc", snapshot["by_call"])

        validator = self.log_validator.LogValidator()
        issues = validator.validate(entries)
        self.assertEqual(issues, [])


if __name__ == "__main__":
    unittest.main()
