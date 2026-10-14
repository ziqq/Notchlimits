import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent


@unittest.skipUnless(sys.platform == "darwin", "Release workflow runs on macOS")
class ReleaseRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        result = subprocess.run([
            "ruby", "-rjson", "-ryaml", "-e",
            "puts JSON.generate(YAML.safe_load(File.read(ARGV[0]), aliases: true))",
            str(ROOT / ".github/workflows/release.yml"),
        ], capture_output=True, text=True, check=True, timeout=10)
        cls.workflow = json.loads(result.stdout)
        cls.steps = cls.workflow["jobs"]["release"]["steps"]

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="notchlimits-release-tests-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.work = self.root / "checkout"
        self.work.mkdir()
        self.environment = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
        self.git("init", "--bare", "--quiet", str(self.root / "origin"))
        self.git("init", "--quiet", "--initial-branch=main")
        self.git("config", "user.name", "Synthetic regression")
        self.git("config", "user.email", "synthetic@example.invalid")
        self.git("-c", "commit.gpgsign=false", "commit", "--quiet", "--allow-empty", "-m", "main fixture")
        self.git("remote", "add", "origin", str(self.root / "origin"))
        self.git("push", "--quiet", "--set-upstream", "origin", "main")
        self.trace = self.root / "gh-calls.jsonl"
        mock = self.root / "bin"
        mock.mkdir()
        # This is an API boundary, not an alternative implementation of the gate.
        # git ancestry is checked against a real, isolated repository.
        (mock / "gh").write_text('''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys
args = sys.argv[1:]
with open(os.environ["MOCK_TRACE"], "a") as file:
    file.write(json.dumps(args) + "\\n")
if args[0] == "run":
    assert args[:3] == ["run", "watch", "123"]
    assert "--exit-status" in args
    sys.exit(1 if os.environ["MOCK_CONCLUSION"] == "failure" else 0)
if "actions/workflows/ci.yml/runs" in " ".join(args):
    for field in ["head_sha=" + os.environ["MOCK_SHA"], "branch=main", "event=push"]:
        assert field in args, "CI query does not bind the release SHA and main push"
    if os.environ["MOCK_CONCLUSION"] != "missing":
        print("123")
elif "actions/runs/123" in " ".join(args):
    print(os.environ["MOCK_CONCLUSION"])
else:
    sys.exit("Unexpected GitHub command: " + repr(args))
''')
        (mock / "gh").chmod(0o755)
        self.environment.update({
            "PATH": str(mock) + os.pathsep + os.environ["PATH"],
            "GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/tags/v1.4.1",
            "GITHUB_REF_NAME": "v1.4.1", "GITHUB_REPOSITORY": "ziqq/Notchlimits",
            "GITHUB_OUTPUT": str(self.root / "outputs"),
            "MOCK_TRACE": str(self.trace), "MOCK_CONCLUSION": "success",
        })
        guard = ROOT / "scripts/verify_release.sh"
        if guard.exists():
            (self.work / "scripts").mkdir()
            shutil.copy2(guard, self.work / "scripts/verify_release.sh")

    def git(self, *arguments):
        return subprocess.run(
            ["git", *arguments], cwd=self.work, env=self.environment,
            capture_output=True, text=True, check=True, timeout=10,
        ).stdout.strip()

    def preflight(self, *, manual=False, ref="refs/heads/main", conclusion="success", outside_main=False):
        if outside_main:
            self.git("switch", "--quiet", "--create", "outside-main")
            self.git("-c", "commit.gpgsign=false", "commit", "--quiet", "--allow-empty", "-m", "outside main")
        sha = self.git("rev-parse", "HEAD")
        self.environment.update(MOCK_SHA=sha, MOCK_CONCLUSION=conclusion, GITHUB_SHA=sha)
        if manual:
            self.environment.update(GITHUB_EVENT_NAME="workflow_dispatch", GITHUB_REF=ref,
                                    GITHUB_REF_NAME=ref.rsplit("/", 1)[-1])
        values = {
            "github.event_name": self.environment["GITHUB_EVENT_NAME"],
            "github.token": "synthetic-token", "inputs.version": "1.4.1",
        }

        def expand(text):
            return re.sub(r"\$\{\{\s*(.*?)\s*\}\}", lambda match: values[match[1]], text)

        # Execute every shell step up to importing the certificate. Old releases
        # have no guard here, so bad inputs actually reach the signing boundary.
        for step in self.steps:
            if "CERTIFICATE_BASE64" in step.get("env", {}):
                return True, "Reached signing boundary"
            if "run" not in step:
                continue
            env = dict(self.environment)
            env.update({key: expand(str(value)) for key, value in step.get("env", {}).items()})
            result = subprocess.run(
                ["bash", "-e", "-o", "pipefail"], input=expand(step["run"]),
                cwd=self.work, env=env, capture_output=True, text=True, timeout=10,
            )
            if result.returncode:
                return False, result.stdout + result.stderr
        self.fail("Release workflow has no signing boundary")

    def assert_blocked(self, **arguments):
        allowed, output = self.preflight(**arguments)
        self.assertFalse(allowed, "Unsafe release reached signing: " + output)

    def test_manual_run_from_another_branch_is_blocked(self):
        self.assert_blocked(manual=True, ref="refs/heads/work")

    def test_tag_on_a_commit_outside_main_is_blocked(self):
        self.assert_blocked(outside_main=True)

    def test_missing_main_push_ci_is_blocked(self):
        self.assert_blocked(conclusion="missing")

    def test_failed_ci_is_blocked(self):
        self.assert_blocked(conclusion="failure")

    def test_cancelled_ci_is_blocked(self):
        self.assert_blocked(conclusion="cancelled")

    def test_neutral_ci_is_blocked(self):
        self.assert_blocked(conclusion="neutral")

    def test_skipped_ci_is_blocked(self):
        self.assert_blocked(conclusion="skipped")

    def test_successful_main_manual_run_reaches_signing(self):
        allowed, output = self.preflight(manual=True)
        self.assertTrue(allowed, output)

    def test_successful_main_tag_reaches_signing(self):
        allowed, output = self.preflight()
        self.assertTrue(allowed, output)

    def test_ci_gate_precedes_signing_and_has_bounded_wait(self):
        signing = next(index for index, step in enumerate(self.steps)
                       if "CERTIFICATE_BASE64" in step.get("env", {}))
        gates = [(index, step) for index, step in enumerate(self.steps)
                 if "verify_release.sh" in step.get("run", "")]
        self.assertEqual(len(gates), 1, "Release has no CI gate before signing")
        index, gate = gates[0]
        self.assertLess(index, signing)
        self.assertGreater(gate["timeout-minutes"], 0)
        self.assertLessEqual(gate["timeout-minutes"], 20)
        permissions = self.workflow["jobs"]["release"].get("permissions", self.workflow["permissions"])
        self.assertEqual(permissions.get("actions"), "read")
        self.assertEqual(permissions.get("checks"), "read")
