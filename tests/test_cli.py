import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


class CliTests(unittest.TestCase):
    def run_cli(self, arguments, input_data=b""):
        return subprocess.run(
            ["python3", "cli.py", *arguments],
            cwd=ROOT,
            input=input_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_help(self):
        result = self.run_cli(["-h"])
        self.assertEqual(result.returncode, 0)
        self.assertIn(b"USAGE", result.stdout)

    def test_xor_block_subject_example(self):
        key = "576861742069732064656164206d6179206e6576657220646965"
        result = self.run_cli(["xor", "-c", "-b", key], b"You know nothing, Jon Snow\n")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(
            result.stdout,
            b"20070f2700071c6a4449060a490515164e4e12190b190011063c",
        )

    def test_aes_block_subject_example(self):
        key = "57696e74657220697320636f6d696e67"
        result = self.run_cli(["aes", "-c", "-b", key], b"All men must die\n")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"744ce22c385958348f0df26eceb62eef")

    def test_invalid_command_returns_84_and_stderr(self):
        result = self.run_cli(["rsa", "-c", "00"], b"message")
        self.assertEqual(result.returncode, 84)
        self.assertIn(b"unsupported crypto system", result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_aes_requires_block_mode_for_now(self):
        result = self.run_cli(["aes", "-c", "00" * 16], b"message")
        self.assertEqual(result.returncode, 84)
        self.assertIn(b"use -b", result.stderr)


if __name__ == "__main__":
    unittest.main()