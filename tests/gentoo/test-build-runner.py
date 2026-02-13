#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


def load_build_runner_module(repo_root: Path):
    script_path = repo_root / "scripts/gentoo/build-runner.py"
    spec = importlib.util.spec_from_file_location("build_runner_module", script_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)  # type: ignore[attr-defined]
    return module


class BuildRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.module = load_build_runner_module(Path(__file__).resolve().parents[2])

        data_dir = self.root / "data/gentoo"
        data_dir.mkdir(parents=True, exist_ok=True)
        (data_dir / "build-order.txt").write_text("sys-devel/binutils\nsys-devel/gcc\n", encoding="utf-8")
        (data_dir / "build-waves.json").write_text(
            json.dumps({"waves": [{"packages": ["sys-devel/binutils"]}, {"packages": ["sys-devel/gcc"]}]}),
            encoding="utf-8",
        )
        (data_dir / "dependency-graph.json").write_text(
            json.dumps({"edges": [{"from": "sys-devel/binutils", "to": "sys-devel/gcc"}]}),
            encoding="utf-8",
        )

        self.config = self.module.BuildConfig(
            image="frankenlibc/gentoo-frankenlibc:latest",
            build_order=data_dir / "build-order.txt",
            build_waves=data_dir / "build-waves.json",
            dependency_graph=data_dir / "dependency-graph.json",
            results_dir=self.root / "artifacts",
            state_file=self.root / "artifacts/state.json",
            binpkg_cache=Path("/var/cache/binpkgs"),
            distfiles_cache=Path("/var/cache/distfiles"),
            parallelism=1,
            max_retries=2,
            timeout_seconds=30,
            mode="hardened",
            resume=True,
            dry_run=False,
            stop_on_failure=False,
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _result(self, package: str, result: str, attempts: int = 1):
        return self.module.PackageResult(
            package=package,
            version="",
            result=result,
            build_time_seconds=1,
            frankenlibc_healing_actions=0,
            frankenlibc_mode="hardened",
            log_file="build.log",
            frankenlibc_log="frankenlibc.jsonl",
            binary_package="",
            exit_code=0 if result == "success" else 1,
            timestamp="2026-02-13T00:00:00Z",
            attempts=attempts,
            reason="",
        )

    def test_dependency_skip_when_parent_fails(self) -> None:
        runner = self.module.BuildRunner(self.config)

        with patch.object(
            runner,
            "_run_package_once",
            side_effect=[
                self._result("sys-devel/binutils", "failed", 1),
                self._result("sys-devel/binutils", "failed", 2),
                self._result("sys-devel/binutils", "failed", 3),
            ],
        ):
            results = runner.run()

        self.assertEqual(results["sys-devel/binutils"].result, "failed")
        self.assertEqual(results["sys-devel/gcc"].result, "skipped")
        self.assertEqual(results["sys-devel/gcc"].reason, "dependency_failed")

    def test_retry_until_success(self) -> None:
        runner = self.module.BuildRunner(self.config)

        with patch.object(
            runner,
            "_run_package_once",
            side_effect=[
                self._result("sys-devel/binutils", "transient", 1),
                self._result("sys-devel/binutils", "success", 2),
                self._result("sys-devel/gcc", "success", 1),
            ],
        ):
            results = runner.run()

        self.assertEqual(results["sys-devel/binutils"].result, "success")
        self.assertEqual(results["sys-devel/binutils"].attempts, 2)
        self.assertEqual(results["sys-devel/gcc"].result, "success")

    def test_resume_skips_existing_results(self) -> None:
        state_payload = {
            "updated_at": "2026-02-13T00:00:00Z",
            "results": {
                "sys-devel/binutils": {
                    "package": "sys-devel/binutils",
                    "version": "",
                    "result": "success",
                    "build_time_seconds": 1,
                    "frankenlibc_healing_actions": 0,
                    "frankenlibc_mode": "hardened",
                    "log_file": "build.log",
                    "frankenlibc_log": "frankenlibc.jsonl",
                    "binary_package": "",
                    "exit_code": 0,
                    "timestamp": "2026-02-13T00:00:00Z",
                    "attempts": 1,
                    "reason": "",
                }
            },
        }
        self.config.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.config.state_file.write_text(json.dumps(state_payload), encoding="utf-8")

        runner = self.module.BuildRunner(self.config)
        with patch.object(runner, "_run_package_once", return_value=self._result("sys-devel/gcc", "success", 1)) as mocked:
            results = runner.run()

        self.assertEqual(results["sys-devel/binutils"].result, "success")
        self.assertEqual(results["sys-devel/gcc"].result, "success")
        mocked.assert_called_once()


if __name__ == "__main__":
    unittest.main()
