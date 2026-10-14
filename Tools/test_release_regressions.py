import json
import os
from pathlib import Path
import plistlib
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
        jobs = cls.workflow["jobs"]
        cls.steps = jobs.get("preflight", {}).get("steps", []) + jobs["release"]["steps"]

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
        (self.work / "scripts").mkdir()
        for name in ["verify_release.sh", "verify_release_tag.sh"]:
            source = ROOT / "scripts" / name
            if source.exists():
                shutil.copy2(source, self.work / "scripts" / name)
        self.git("add", "scripts")
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
elif args[:2] == ["release", "create"]:
    import subprocess
    tag = args[2]
    remote = subprocess.run(["git", "ls-remote", "origin", "refs/tags/" + tag],
                            capture_output=True, text=True, check=True).stdout
    if not remote and "--verify-tag" in args:
        sys.exit(1)
    # Match gh's documented auto-creation when --verify-tag is absent.
    if not remote:
        subprocess.run(["git", "--git-dir", os.environ["MOCK_ORIGIN"], "tag", tag, "main"], check=True)
    Path(os.environ["MOCK_PUBLISHED"]).write_text(json.dumps(args))
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
            "MOCK_ORIGIN": str(self.root / "origin"),
            "MOCK_PUBLISHED": str(self.root / "published"),
        })

    def git(self, *arguments):
        return subprocess.run(
            ["git", *arguments], cwd=self.work, env=self.environment,
            capture_output=True, text=True, check=True, timeout=10,
        ).stdout.strip()

    def preflight(self, *, manual=False, ref="refs/heads/main", conclusion="success", outside_main=False,
                  tamper_guard=False, annotated=False, missing_tag=False, sha_mismatch=False,
                  version="1.4.1"):
        if outside_main:
            self.git("switch", "--quiet", "--create", "outside-main")
            if tamper_guard:
                (self.work / "scripts/verify_release.sh").write_text("#!/bin/bash\nexit 0\n")
                self.git("add", "scripts/verify_release.sh")
            self.git("-c", "commit.gpgsign=false", "commit", "--quiet", "--allow-empty", "-m", "outside main")
        sha = self.git("rev-parse", "HEAD")
        if not missing_tag:
            tag_args = ["-a", "-m", "synthetic tag"] if annotated else []
            self.git("-c", "tag.gpgsign=false", "tag", *tag_args, "v1.4.1")
            self.git("push", "--quiet", "origin", "refs/tags/v1.4.1")
        if sha_mismatch:
            self.git("-c", "commit.gpgsign=false", "commit", "--quiet", "--allow-empty", "-m", "main progressed")
            self.git("push", "--quiet", "origin", "main")
            sha = self.git("rev-parse", "HEAD")
        self.environment.update(MOCK_SHA=sha, MOCK_CONCLUSION=conclusion, GITHUB_SHA=sha)
        if manual:
            self.environment.update(GITHUB_EVENT_NAME="workflow_dispatch", GITHUB_REF=ref,
                                    GITHUB_REF_NAME=ref.rsplit("/", 1)[-1])
        self.values = {
            "github.event_name": self.environment["GITHUB_EVENT_NAME"],
            "github.token": "synthetic-token", "inputs.version": version,
            "steps.package.outputs.dmg": "synthetic.dmg",
            "steps.package.outputs.name": "synthetic.zip",
        }

        # Execute every shell step up to importing the certificate. Old releases
        # have no guard here, so bad inputs actually reach the signing boundary.
        for step in self.steps:
            if "CERTIFICATE_BASE64" in step.get("env", {}):
                return True, "Reached signing boundary"
            if "uses" in step and "actions/checkout@" in step["uses"]:
                checkout_ref = step.get("with", {}).get("ref")
                if checkout_ref:
                    checkout_ref = self.expand(checkout_ref)
                    self.git("switch", "--quiet", "--detach",
                             "origin/main" if checkout_ref == "main" else checkout_ref)
            if "run" not in step:
                continue
            result = self.run_step(step)
            if result.returncode:
                return False, result.stdout + result.stderr
            if step.get("id"):
                for line in Path(self.environment["GITHUB_OUTPUT"]).read_text().splitlines():
                    key, value = line.split("=", 1)
                    self.values[f"steps.{step['id']}.outputs.{key}"] = value
                    self.values[f"needs.preflight.outputs.{key}"] = value
        self.fail("Release workflow has no signing boundary")

    def expand(self, text):
        return re.sub(r"\$\{\{\s*(.*?)\s*\}\}", lambda match: self.values[match[1]], text)

    def run_step(self, step):
        env = dict(self.environment)
        env.update({key: self.expand(str(value)) for key, value in step.get("env", {}).items()})
        return subprocess.run(
            ["bash", "-e", "-o", "pipefail"], input=self.expand(step["run"]),
            cwd=self.work, env=env, capture_output=True, text=True, timeout=10,
        )

    def publication(self):
        step = next(step for step in self.workflow["jobs"]["release"]["steps"]
                    if "gh release create" in step.get("run", ""))
        return self.run_step(step)

    def assert_blocked(self, **arguments):
        allowed, output = self.preflight(**arguments)
        self.assertFalse(allowed, "Unsafe release reached signing: " + output)

    def test_manual_run_from_another_branch_is_blocked(self):
        self.assert_blocked(manual=True, ref="refs/heads/work")

    def test_multiline_version_cannot_inject_shell_code_into_signing_job(self):
        marker = self.root / "injected-command"
        version = f"1.4.1\nversion=1.4.1$(touch {marker})"
        allowed, output = self.preflight(manual=True, version=version)
        if allowed:
            # Exercise the workflow's real downstream shell with the poisoned
            # output. A failed bundle comparison does not undo code execution.
            bundle = self.work / "build/Notchlimits.app/Contents"
            bundle.mkdir(parents=True)
            bundle.joinpath("Info.plist").write_bytes(plistlib.dumps({
                "CFBundleShortVersionString": self.values["steps.meta.outputs.version"],
            }))
            step = next(step for step in self.workflow["jobs"]["release"]["steps"]
                        if "plutil -extract CFBundleShortVersionString" in step.get("run", ""))
            self.run_step(step)
        self.assertFalse(marker.exists(), "Release version executed a shell command in the signing job")
        self.assertFalse(allowed, "Multiline release version reached signing: " + output)

    def test_tag_on_a_commit_outside_main_is_blocked(self):
        self.assert_blocked(outside_main=True)

    def test_tag_cannot_replace_the_trusted_gate(self):
        self.assert_blocked(outside_main=True, tamper_guard=True)

    def test_missing_remote_tag_is_blocked_before_signing(self):
        self.assert_blocked(missing_tag=True)

    def test_remote_tag_must_match_event_commit(self):
        self.assert_blocked(sha_mismatch=True)

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

    def test_annotated_main_tag_reaches_signing(self):
        allowed, output = self.preflight(annotated=True)
        self.assertTrue(allowed, output)

    def test_valid_release_publishes_the_existing_tag(self):
        allowed, output = self.preflight()
        self.assertTrue(allowed, output)
        result = self.publication()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(Path(self.environment["MOCK_PUBLISHED"]).exists())

    def test_deleted_remote_tag_cannot_be_recreated_at_publication(self):
        allowed, output = self.preflight()
        self.assertTrue(allowed, output)
        self.git("push", "--quiet", "origin", ":refs/tags/v1.4.1")
        result = self.publication()
        self.assertNotEqual(result.returncode, 0, "Publication recreated a deleted tag")
        self.assertFalse(Path(self.environment["MOCK_PUBLISHED"]).exists())

    def test_moved_remote_tag_cannot_receive_old_artifacts(self):
        allowed, output = self.preflight()
        self.assertTrue(allowed, output)
        self.git("-c", "commit.gpgsign=false", "commit", "--quiet", "--allow-empty", "-m", "different artifact commit")
        self.git("-c", "tag.gpgsign=false", "tag", "--force", "v1.4.1")
        self.git("push", "--quiet", "--force", "origin", "refs/tags/v1.4.1")
        result = self.publication()
        self.assertNotEqual(result.returncode, 0, "Moved tag received artifacts from another commit")
        self.assertFalse(Path(self.environment["MOCK_PUBLISHED"]).exists())

    def test_signing_uses_environment_and_checkout_of_verified_sha(self):
        release = self.workflow["jobs"]["release"]
        self.assertEqual(release.get("environment"), "release", "Signing keys have no external environment gate")
        self.assertEqual(release.get("needs"), "preflight")
        checkout = next(step for step in release["steps"] if "actions/checkout@" in step.get("uses", ""))
        self.assertEqual(checkout["with"]["ref"], "${{ needs.preflight.outputs.sha }}")
        self.assertRegex(checkout["uses"], r"@[a-f0-9]{40}$")
        self.assertFalse(any(re.search(r"(?m)^\s*git\s+tag\s+(?!.*--(?:sort|list)\b)", step.get("run", ""))
                             for step in release["steps"]),
                         "Workflow still creates tags instead of using a protected pre-created tag")

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
        permissions = self.workflow["jobs"].get("preflight", self.workflow["jobs"]["release"]).get(
            "permissions", self.workflow["permissions"])
        self.assertEqual(permissions.get("actions"), "read")
        self.assertEqual(permissions.get("checks"), "read")
