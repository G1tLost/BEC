"""Acceptance checks for the standalone email command and package entry point."""

import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from bec import __version__
from bec.cli import main


class StandaloneCli(unittest.TestCase):
    def test_device_commands_are_rejected_without_case_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "must-not-be-created"
            for command in ("endpoint", "acquisition", "lab", "lab-fixtures"):
                for suffix in ([], ["--help"]):
                    with self.subTest(command=command, suffix=suffix):
                        with contextlib.redirect_stderr(io.StringIO()):
                            with self.assertRaises(SystemExit) as result:
                                main(["--root", str(root), command, *suffix])
                        self.assertEqual(result.exception.code, 2)
                        self.assertFalse(root.exists())

    def test_module_entrypoint_help_and_version(self):
        source_root = Path(__file__).resolve().parents[1]
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        for flag in ("--help", "--version"):
            with self.subTest(flag=flag):
                result = subprocess.run(
                    [sys.executable, "-m", "bec", flag],
                    cwd=source_root,
                    env=environment,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                if flag == "--version":
                    self.assertEqual(result.stdout.strip(), "BEC " + __version__)
                else:
                    self.assertIn("email compromise", " ".join(result.stdout.split()))
                    self.assertIn("investigate", result.stdout)
                    self.assertNotIn("endpoint", result.stdout)
                    self.assertNotIn("acquisition", result.stdout)
                    self.assertNotIn("lab-fixtures", result.stdout)


if __name__ == "__main__":
    unittest.main()
