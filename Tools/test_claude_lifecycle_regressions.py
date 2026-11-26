import os
import pathlib
import select
import subprocess
import sys
import tempfile
import time
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
            "_ item: UnsafeMutablePointer<SecKeychainItem?>) -> OSStatus {":
                """if ClaudeLifecycleSignals.ownsPersistentReference(reference) {
        item.pointee = unsafeBitCast("fixture-claude-item" as CFString, to: SecKeychainItem.self)
        return errSecSuccess
    }""",
            "_ to: UnsafePointer<CChar>, _ flags: UInt32) -> Int32 {":
                """if flags == UInt32(RENAME_SWAP) {
        if !ClaudeLifecycleSignals.replaceOnRepair { ClaudeLifecycleSignals.replaceExpiredLock(at: fromFD, path: from) }
        ClaudeLifecycleSignals.replaceAtRepairDestination(parent: toFD, path: to)
    }
    ClaudeLifecycleSignals.beforeRename(flags)
    if ClaudeLifecycleSignals.selectionRenameRefused(String(cString: from)) { return -1 }""",
        }
        for anchor, body in hooks.items():
            assert support.count(anchor) == 1
            support = support.replace(anchor, anchor + "\n    " + body)
        attributes = "result?.pointee = [kSecAttrService as String: service] as NSDictionary"
        assert support.count(attributes) == 2
        support = support.replace(attributes, """result?.pointee = ClaudeLifecycleSignals.attributes(service, query: query) as NSDictionary""", 1)
        rename = "return Darwin.renameatx_np(fromFD, from, toFD, to, flags)"
        assert support.count(rename) == 1
        support = support.replace(rename, """let result = Darwin.renameatx_np(fromFD, from, toFD, to, flags)
    ClaudeLifecycleSignals.afterRename(flags, result, parent: fromFD)
    ClaudeLifecycleSignals.afterSelectionRename(String(cString: from), result: result)
    ClaudeLifecycleSignals.afterCredentialRollback(parent: fromFD, name: String(cString: from), result: result)
    ClaudeLifecycleSignals.afterFallbackIsolation(from: String(cString: from), to: String(cString: to), result: result)
    return result""")
        move = "try super.moveItem(at: srcURL, to: dstURL)"
        assert support.count(move) == 1
        support = support.replace(move, "ClaudeLifecycleSignals.beforeProfileMove(from: srcURL, to: dstURL)\n        "
                                  + move + "\n        ClaudeLifecycleSignals.afterProfileMove(from: srcURL, to: dstURL)")
        remove = "try super.removeItem(at: url)"
        assert support.count(remove) == 1
        support = support.replace(remove, remove + "\n        ClaudeLifecycleSignals.afterProfileCleanup(url)")
        delete = "Fixture.claudeEntries = entries\n        return errSecSuccess"
        assert support.count(delete) == 1
        support = support.replace(delete, "Fixture.claudeEntries = entries\n        ClaudeLifecycleSignals.afterCredentialDelete(service)\n        return errSecSuccess")
        name = "Lifecycle$Claude.swift"
        cls.fixture_path = pathlib.Path(fixture.name) / name
        cls.fixture_path.write_text(support + "\n" + (swift_regression.FIXTURES / name).read_text())
        authentication.AuthenticationRegressions.setUpClass.__func__(cls)

    check_scenario = authentication.AuthenticationRegressions.check_scenario

    def test_removal_confirmation_stays_with_original_claude_login(self):
        for backend in ("file", "keychain", "primary"):
            for login in ("replacement", "unchanged"):
                with self.subTest(backend=backend, login=login):
                    self.check_scenario(f"remove-confirmed:{backend}:{login}")

    def test_removal_rechecks_confirmed_claude_login_after_staging(self):
        self.check_scenario("remove-confirmed:keychain:staged")

    def check_cli_retirement_restart(self, phase, backend, selection, behavior="restore"):
        with tempfile.TemporaryDirectory(prefix="notchlimits-cli-retirement-", dir="/private/tmp") as directory:
            root = pathlib.Path(directory)
            cut = swift_regression.run_fixture(
                self.executable, f"cli-retirement-cut:{phase}:{backend}:{selection}", root
            )
            self.assertEqual(cut.returncode, 86, cut.stdout + cut.stderr)
            replay = swift_regression.run_fixture(
                self.executable, f"cli-retirement-replay:{phase}:{backend}:{selection}:{behavior}", root
            )
            self.assertEqual(replay.returncode, 0, replay.stdout + replay.stderr)

    def test_interrupted_pointer_retirement_restores_the_verified_route(self):
        for backend in ("file", "keychain"):
            with self.subTest(backend=backend):
                self.check_cli_retirement_restart("pointer", backend, "target")

    def test_interrupted_directory_staging_restores_the_verified_profile(self):
        for backend in ("file", "keychain"):
            for selection in ("target", "previous", "none"):
                with self.subTest(backend=backend, selection=selection):
                    self.check_cli_retirement_restart("directory", backend, selection)

    def test_interrupted_retirement_defers_while_keychain_is_denied(self):
        for phase in ("pointer", "directory"):
            with self.subTest(phase=phase):
                self.check_cli_retirement_restart(phase, "keychain", "target", "denied")

    def test_interrupted_retirement_preserves_a_new_same_path_login(self):
        for phase in ("pointer", "directory"):
            with self.subTest(phase=phase):
                self.check_cli_retirement_restart(phase, "file", "target", "replacement")
        self.check_cli_retirement_restart("directory", "file", "target", "replacement-before-discovery")

    def test_interrupted_directory_staging_keeps_newer_cli_selection(self):
        self.check_cli_retirement_restart("directory", "keychain", "target", "newer")

    def test_interrupted_removal_started_with_unreadable_keychain_restores_exact_owner(self):
        for selection in ("target", "previous", "none"):
            with self.subTest(selection=selection):
                self.check_cli_retirement_restart("opaque", "keychain", selection)

    def test_interrupted_removal_never_restores_opaque_keychain_after_same_date_write(self):
        self.check_cli_retirement_restart("opaque", "keychain", "target", "opaque-replaced")

    def test_removal_without_any_keychain_owner_proof_leaves_profile_untouched(self):
        self.check_scenario("retirement-without-proof")

    def test_interrupted_dual_store_removal_restores_the_exact_fallback(self):
        for selection, behavior in (("target", "denied"), ("previous", "restore")):
            with self.subTest(selection=selection):
                self.check_cli_retirement_restart("fallback", "both", selection, behavior)

    def test_committed_dual_store_removal_does_not_leave_usable_fallback(self):
        self.check_cli_retirement_restart("fallback-committed", "both", "target")

    def check_desktop_retirement_restart(self, phase, case="desktop-retirement"):
        with tempfile.TemporaryDirectory(prefix="notchlimits-desktop-retirement-", dir="/private/tmp") as directory:
            root = pathlib.Path(directory)
            cut = swift_regression.run_fixture(self.executable, f"{case}-cut:{phase}", root)
            self.assertEqual(cut.returncode, 86, cut.stdout + cut.stderr)
            replay = swift_regression.run_fixture(self.executable, f"{case}-replay:{phase}", root)
            self.assertEqual(replay.returncode, 0, replay.stdout + replay.stderr)

    def test_desktop_retirement_does_not_reuse_deleted_session_after_restart(self):
        self.check_desktop_retirement_restart("deleted")

    def test_desktop_retirement_keeps_session_when_restart_precedes_deletion(self):
        self.check_desktop_retirement_restart("before")

    def test_desktop_retirement_replays_main_stub_deletion_without_reusing_session(self):
        self.check_desktop_retirement_restart("deleted", case="desktop-stub")

    def test_desktop_retirement_keeps_main_session_if_stub_deletion_did_not_occur(self):
        self.check_desktop_retirement_restart("before", case="desktop-stub")

    def test_desktop_retirement_reuses_session_after_verified_rollback_rename(self):
        self.check_desktop_retirement_restart("restored", case="desktop-rollback")

    def test_interrupted_shared_primary_removal_does_not_adopt_the_alias_fallback(self):
        for phase in ("deleted", "metadata-denied"):
            with self.subTest(phase=phase):
                self.check_desktop_retirement_restart(phase, case="shared-primary")

    def test_interrupted_shared_primary_preparation_does_not_commit_removal(self):
        self.check_desktop_retirement_restart("before", case="shared-primary")

    def test_interrupted_shared_primary_removal_admits_a_fresh_file_login(self):
        self.check_desktop_retirement_restart("replacement", case="shared-primary")

    def test_replacement_shared_primary_keeps_the_retained_alias_fallback_suppressed(self):
        self.check_desktop_retirement_restart("keychain-replacement", case="shared-primary")

    def test_refused_shared_primary_retry_preserves_the_pending_receipt(self):
        for phase in ("retry-same", "retry-new"):
            with self.subTest(phase=phase):
                self.check_desktop_retirement_restart(phase, case="shared-primary")

    def test_interrupted_native_primary_removal_restores_the_exact_fallback(self):
        for phase in ("before", "opaque"):
            with self.subTest(phase=phase):
                self.check_desktop_retirement_restart(phase, case="native-primary")

    def test_committed_native_primary_removal_finishes_fallback_cleanup(self):
        self.check_desktop_retirement_restart("deleted", case="native-primary")

    def test_interrupted_native_primary_removal_preserves_a_replacement_file(self):
        self.check_desktop_retirement_restart("replacement", case="native-primary")

    def test_interrupted_native_primary_retains_the_checkpoint_without_the_original_keychain_login(self):
        for phase in ("keychain-replacement", "keychain-denied"):
            with self.subTest(phase=phase):
                self.check_desktop_retirement_restart(phase, case="native-primary")

    def test_cli_retirement_rebinds_only_the_original_rollback_file(self):
        for phase in ("selected", "locked", "copied"):
            with self.subTest(phase=phase):
                self.check_desktop_retirement_restart(phase, case="desktop-rollback")

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

    def test_zsh_login_profile_can_choose_a_different_dotdir(self):
        self.check_scenario("dotdir:login")

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
                        placeholder = lock.stat().st_ino
                        self.assertNotEqual(placeholder, original, "The fixture did not displace the native lock")
                        if public_state.startswith("late-heartbeat:"):
                            time.sleep(1.1)
                            result = swift_regression.run_fixture(
                                self.executable, "lock-" + public_state, root
                            )
                            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                            self.assertTrue(lock.is_dir(), "Recovery removed the lock after its heartbeat")
                            return
                        if public_state == "repair-race":
                            result = swift_regression.run_fixture(self.executable, "lock-repair-race", root)
                            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                            self.assertEqual(lock.stat().st_ino, placeholder)
                            return
                        if public_state != "marked":
                            lock.rmdir()
                        if public_state == "occupied":
                            lock.mkdir()
                            successor = lock.stat().st_ino
                            result = swift_regression.run_fixture(self.executable, "lock-native-owner", root)
                            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                            self.assertEqual(lock.stat().st_ino, successor)
                            lock.rmdir()
                        if public_state == "released":
                            os.close(native)
                            native = -1
                        result = swift_regression.run_fixture(self.executable, "lock-native-owner:short", root)
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        if public_state == "marked":
                            self.assertEqual(lock.stat().st_ino, placeholder)
                        else:
                            self.assertFalse(lock.exists(), "Recovery republished the displaced CLI directory")
                        if public_state == "released":
                            time.sleep(1.1)
                            result = swift_regression.run_fixture(self.executable, "lock-available", root)
                            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                            self.assertFalse(any(".retiring-" in path.name for path in lock.parent.iterdir()))
                    finally:
                        if native >= 0:
                            os.close(native)
                finally:
                    if child.poll() is None:
                        child.kill()
                        child.communicate()

    def test_interrupted_release_restores_native_exclusion(self):
        self.check_crash_with_native_replacement("release")

    def test_interrupted_recovery_restores_native_exclusion(self):
        self.check_crash_with_native_replacement("recover")

    def test_interrupted_release_defers_after_placeholder_is_removed(self):
        self.check_crash_with_native_replacement("release", "absent")

    def test_interrupted_release_preserves_a_new_owner_and_defers_after_release(self):
        self.check_crash_with_native_replacement("release", "occupied")

    def test_repair_never_displaces_a_successor_at_the_swap_boundary(self):
        self.check_crash_with_native_replacement("release", "repair-race")

    def test_repair_expires_released_directory_without_republishing_it(self):
        self.check_crash_with_native_replacement("release", "released")

    def test_late_heartbeat_prevents_recovery(self):
        for phase in ("cleanup", "swap"):
            with self.subTest(phase=phase):
                self.check_crash_with_native_replacement("release", "late-heartbeat:" + phase)
