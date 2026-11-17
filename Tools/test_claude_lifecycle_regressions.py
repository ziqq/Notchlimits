import os
import pathlib
import select
import subprocess
import sys
import tempfile
import unittest

import swift_regression
import test_auth_regressions as authentication


@unittest.skipUnless(sys.platform == "darwin", "Notchlimits runs on macOS")
class ClaudeLifecycleRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture = tempfile.TemporaryDirectory(prefix="notchlimits-claude-lifecycle-")
        cls.addClassCleanup(fixture.cleanup)
        support = (swift_regression.FIXTURES / "Authentication.swift").read_text().split("\n@main\n", 1)[0]
        hooks = {
            "func SecKeychainCopySearchList(_ result: UnsafeMutablePointer<CFArray?>) -> OSStatus {":
                "if let searchList = ClaudeLifecycleSignals.searchList { return searchList(result) }",
            "_ to: UnsafePointer<CChar>, _ flags: UInt32) -> Int32 {":
                """if flags == UInt32(RENAME_SWAP) { ClaudeLifecycleSignals.replaceExpiredLock(at: fromFD, path: from) }
    ClaudeLifecycleSignals.beforeRename(flags)
    if ClaudeLifecycleSignals.selectionRenameRefused(String(cString: from)) { return -1 }""",
        }
        for anchor, body in hooks.items():
            assert support.count(anchor) == 1
            support = support.replace(anchor, anchor + "\n    " + body)
        rename = "return Darwin.renameatx_np(fromFD, from, toFD, to, flags)"
        assert support.count(rename) == 1
        support = support.replace(rename, """let result = Darwin.renameatx_np(fromFD, from, toFD, to, flags)
    ClaudeLifecycleSignals.afterRename(flags, result)
    return result""")
        name = "Lifecycle$Claude.swift"
        cls.fixture_path = pathlib.Path(fixture.name) / name
        cls.fixture_path.write_text(support + "\n" + (swift_regression.FIXTURES / name).read_text())
        authentication.AuthenticationRegressions.setUpClass.__func__(cls)

    check_scenario = authentication.AuthenticationRegressions.check_scenario

    def test_file_logout_during_selection_validation_preserves_the_previous_route(self):
        self.check_scenario("file-pointer:logout")

    def test_file_stub_during_selection_validation_preserves_the_previous_route(self):
        self.check_scenario("file-pointer:stub")

    def test_unchanged_file_login_still_switches(self):
        self.check_scenario("file-pointer:stable")

    def test_file_login_still_switches_when_classic_keychain_revision_is_unavailable(self):
        self.check_scenario("file-pointer:unavailable")

    def test_removed_cli_route_cannot_select_the_readded_profile(self):
        self.check_scenario("cli-removed:replacement")

    def test_unfinished_profile_removal_retires_the_selected_route(self):
        self.check_scenario("cli-removed:orphan")

    def test_removing_another_profile_preserves_the_selected_route(self):
        self.check_scenario("cli-removed:previous")

    def test_refused_profile_removal_preserves_the_selected_route(self):
        self.check_scenario("cli-removed:refused")

    def test_refused_cli_retirement_preserves_the_profile_and_route(self):
        self.check_scenario("cli-removed:pointer-refused")

    def test_keychain_login_during_publication_does_not_publish_previous_limits(self):
        self.check_scenario("usage:replacement")

    def test_current_keychain_login_still_publishes_limits(self):
        self.check_scenario("usage:stable")

    def test_readable_keychain_without_classic_revision_still_publishes_limits(self):
        self.check_scenario("usage:unavailable")

    def test_audit_rollback_replacement(self):
        self.check_scenario("cli-removed:rollback-replacement")

    def test_audit_zsh_custom_dotdir(self):
        self.check_scenario("dotdir:custom")

    def test_audit_zsh_default_dotdir(self):
        self.check_scenario("dotdir:default")

    def test_audit_zsh_interactive_dotdir(self):
        self.check_scenario("dotdir:interactive")

    def test_audit_rollback_empty_bootstrap(self):
        self.check_scenario("cli-removed:rollback-empty")

    def test_preserves_native_lock_replaced_during_release(self):
        self.check_scenario("lock-syscall:release")

    def test_preserves_native_lock_replaced_during_recovery(self):
        self.check_scenario("lock-syscall:recover")

    def check_crash_with_native_replacement(self, mode, public_state="marked"):
        with tempfile.TemporaryDirectory(prefix="notchlimits-lock-crash-", dir="/private/tmp") as directory:
            root = pathlib.Path(directory)
            lock = root / "claude-lock/.storage-write.lock"
            with subprocess.Popen(
                [str(self.executable), "lock-crash-swap:" + mode, directory],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            ) as child:
                try:
                    self.assertTrue(select.select([child.stdout], [], [], 10)[0], "The swap was not reached")
                    self.assertEqual(child.stdout.readline(), b"ready-for-cli\n")
                    lock.rmdir()
                    lock.mkdir()
                    native = os.open(lock, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        original = os.fstat(native).st_ino
                        out, err = child.communicate(b"go\n", timeout=10)
                        self.assertEqual(child.returncode, 86, (out, err))
                        self.assertNotEqual(lock.stat().st_ino, original, "The fixture did not displace the native lock")
                        if public_state != "marked":
                            lock.rmdir()
                        if public_state == "occupied":
                            lock.mkdir()
                            successor = lock.stat().st_ino
                            result = swift_regression.run_fixture(self.executable, "lock-native-owner", root)
                            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                            self.assertEqual(lock.stat().st_ino, successor)
                            lock.rmdir()
                        result = swift_regression.run_fixture(self.executable, "lock-native-owner", root)
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertEqual(lock.stat().st_ino, original)
                    finally:
                        os.close(native)
                finally:
                    if child.poll() is None:
                        child.kill()
                        child.communicate()

    def test_interrupted_release_restores_native_exclusion(self):
        self.check_crash_with_native_replacement("release")

    def test_interrupted_recovery_restores_native_exclusion(self):
        self.check_crash_with_native_replacement("recover")

    def test_interrupted_release_restores_native_lock_after_placeholder_is_removed(self):
        self.check_crash_with_native_replacement("release", "absent")

    def test_interrupted_release_preserves_a_new_owner_before_restoring_the_displaced_lock(self):
        self.check_crash_with_native_replacement("release", "occupied")
