import pathlib
import os
import subprocess
import sys
import tempfile
import unittest

from swift_regression import SOURCES, compile_fixture, run_fixture


@unittest.skipUnless(sys.platform == "darwin", "Notchlimits runs on macOS")
class AuthenticationRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="notchlimits-auth-tests-")
        cls.addClassCleanup(cls.build.cleanup)
        # The assertion is identical for both revisions; only the old save API differs.
        keychain = (SOURCES / "Providers/AuthStorage$Claude.swift").read_text()
        flags = () if "expected: Credentials" in keychain else ("-DLEGACY_CLAUDE_SAVE",)
        provider = (SOURCES / "Providers/Provider$Claude.swift").read_text()
        if "func prepareForTermination(" in provider:
            flags += ("-DCLAUDE_TERMINATION_DRAIN",)
        codex = (SOURCES / "Providers/OAuth$Codex.swift").read_text()
        if "func prepareForTermination(" in codex:
            flags += ("-DCODEX_TERMINATION_DRAIN",)
        if "completion:" in (SOURCES / "Core/AccountRemoval.swift").read_text():
            flags += ("-DCOORDINATED_CODEX_REMOVAL",)
        # Execute the exact production quit callback with synthetic AppKit only.
        # This also exercises the old callback when proving the regression.
        delegate = (SOURCES / "App/AppDelegate.swift").read_text()
        start = delegate.index("    func applicationShouldTerminate(")
        end = delegate.index("{", start) + 1
        depth = 1
        while depth:
            depth += (delegate[end] == "{") - (delegate[end] == "}")
            end += 1
        termination = pathlib.Path(cls.build.name) / "TerminationDelegate.swift"
        termination.write_text('''
import Foundation
@MainActor final class NSApplication {
    enum TerminateReply { case terminateNow, terminateLater }
    var approved: Bool?
    func reply(toApplicationShouldTerminate value: Bool) { approved = value }
}
final class NSAlert {
    var messageText = "", informativeText = ""
    enum Style { case warning }
    var alertStyle = Style.warning
    final class Button { var hasDestructiveAction = false; var keyEquivalent = "" }
    @discardableResult func addButton(withTitle: String) -> Button { Button() }
}
@MainActor final class RegressionTerminationDelegate {
    var claudeProvider: Provider$Claude? = Provider$Claude()
    var terminationPending = false
    func runModalAbovePanel(_ alert: NSAlert) {}
''' + delegate[start:end] + "\n}\n")
        # Exercise the exact menu and removal handlers with synthetic AppKit.
        start = delegate.index("    private func orphanProfiles(")
        end = delegate.index("{", start) + 1
        depth = 1
        while depth:
            depth += (delegate[end] == "{") - (delegate[end] == "}")
            end += 1
        menu_body = delegate[start:end]
        start = delegate.index("    @objc private func removeOrphanProfile(")
        end = delegate.index("{", start) + 1
        depth = 1
        while depth:
            depth += (delegate[end] == "{") - (delegate[end] == "}")
            end += 1
        removal_body = delegate[start:end].replace("@objc private", "private", 1)
        menu = pathlib.Path(cls.build.name) / "ProfileMenu.swift"
        menu.write_text('''
import Foundation
final class NSMenuItem { var representedObject: Any? }
@MainActor final class RegressionProfileMenu {
    enum ModalResponse { case alertFirstButtonReturn }
    var failure: Error?
    func runModalAbovePanel(_ alert: NSAlert) -> ModalResponse { .alertFirstButtonReturn }
    func errorAlert(_ title: String, _ error: Error) { failure = error }
    func remove(path: String) {
        let sender = NSMenuItem(); sender.representedObject = path
        removeOrphanProfile(sender)
    }
    let store: UsageStore
    init(store: UsageStore) { self.store = store }
    func profiles() -> [(label: String, url: URL)] { orphanProfiles() }
''' + menu_body + "\n" + removal_body + "\n}\n")
        cls.executable = compile_fixture(cls.build.name, "Authentication", [
            "Model/Models.swift", "Model/Account.swift", "Core/JWT.swift",
            *(["Core/StorageLock$Claude.swift"] if (SOURCES / "Core/StorageLock$Claude.swift").exists() else []),
            *(["Core/AuthStorage$Codex.swift"] if (SOURCES / "Core/AuthStorage$Codex.swift").exists() else []),
            "Core/AuthSwap$Codex.swift", "Core/AccountRemoval.swift",
            "Core/AccountSwitcher.swift", "Core/AppAccountSwitcher.swift",
            *(["Core/CLISelection$Claude.swift"] if (SOURCES / "Core/CLISelection$Claude.swift").exists() else []),
            "Core/DefaultsMigration.swift", "Core/UsageStore.swift", "Core/UsageCache.swift",
            "Providers/AuthStorage$Claude.swift", "Providers/OAuth$Claude.swift",
            "Providers/Provider$Claude.swift", "Providers/OAuth$Codex.swift",
            "Providers/Provider$Codex.swift", "Providers/Discovery$Real.swift",
        ], flags, extra_sources=[termination, menu])

    def check_scenario(self, scenario):
        # Match the canonical home URLs returned by macOS directory discovery.
        with tempfile.TemporaryDirectory(prefix="notchlimits-auth-fixture-", dir="/private/tmp") as directory:
            result = run_fixture(self.executable, scenario, pathlib.Path(directory))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_claude_canonical_main_has_one_file_owner(self):
        self.check_scenario("claude-canonical-main-discovery")

    def test_claude_canonical_main_preserves_stale_duplicate_configuration(self):
        self.check_scenario("claude-canonical-main-stale-removal")

    def test_claude_defers_fallback_refresh_until_keychain_owner_recovers(self):
        self.check_scenario("claude-owner-denied-fallback")

    def test_claude_preflight_defers_refresh_when_keychain_becomes_unavailable(self):
        self.check_scenario("claude-owner-preflight-denied")

    def test_claude_does_not_refresh_fallback_over_malformed_keychain_owner(self):
        self.check_scenario("claude-owner-malformed-fallback")

    def test_codex_symlinked_root_preserves_keyring_lifecycle(self):
        self.check_scenario("codex-root-symlink-keyring")

    def test_codex_symlinked_root_preserves_file_lifecycle(self):
        self.check_scenario("codex-root-symlink-file")

    def test_codex_readd_during_removal_gets_new_usage_generation(self):
        self.check_scenario("codex-readd-during-removal-usage")

    def test_claude_readd_during_removal_gets_new_usage_generation(self):
        self.check_scenario("claude-readd-during-removal-usage")

    def test_codex_retired_usage_401(self):
        self.check_scenario("codex-retired-usage-401")

    def test_codex_copyback_relogin(self):
        self.check_scenario("codex-copyback-relogin")

    def test_codex_removal_selection_rollback(self):
        self.check_scenario("codex-removal-selection-rollback")

    def test_codex_native_parent_removal(self):
        self.check_scenario("codex-native-parent-removal")

    def test_claude_native_parent_removal(self):
        self.check_scenario("claude-native-parent-removal")

    def test_codex_usage_region_403(self):
        self.check_scenario("codex-usage-region-403")

    def test_claude_native_hashed_owner_removal(self):
        self.check_scenario("claude-native-hashed-owner-removal")

    def test_codex_retired_usage_same_grant(self):
        self.check_scenario("codex-retired-usage-same-grant")

    def test_codex_relogin_usage_401(self):
        self.check_scenario("codex-relogin-usage-401")

    def test_codex_copyback_file_relogin(self):
        self.check_scenario("codex-copyback-file-relogin")

    def test_codex_copyback_keyring_native(self):
        self.check_scenario("codex-copyback-keyring-native")

    def test_codex_copyback_legacy_relogin(self):
        self.check_scenario("codex-copyback-legacy-relogin")

    def test_codex_removal_file_selection_rollback(self):
        self.check_scenario("codex-removal-file-selection-rollback")

    def test_codex_removal_primary_selection_rollback(self):
        self.check_scenario("codex-removal-primary-selection-rollback")

    def test_codex_removal_native_progress_rollback(self):
        self.check_scenario("codex-removal-native-progress-rollback")

    def test_claude_native_shared_owner_removal(self):
        self.check_scenario("claude-native-shared-owner-removal")

    def test_default_profile_has_its_own_identity(self):
        self.check_scenario("profile-identity")

    def test_imported_profile_names_do_not_collide(self):
        self.check_scenario("profile-collision")

    def test_legacy_active_imported_profile_keeps_its_credentials(self):
        self.check_scenario("profile-active-migration")

    def test_imported_profile_keeps_hidden_state_and_custom_name(self):
        self.check_scenario("profile-settings-migration")

    def test_profile_settings_preserve_current_values_and_user_edits(self):
        self.check_scenario("profile-settings-existing")

    def test_profile_settings_preserve_both_owners_of_legacy_collision(self):
        self.check_scenario("profile-settings-collision")

    def test_profile_settings_do_not_cascade_through_nested_prefixes(self):
        self.check_scenario("profile-settings-nested")

    def test_lost_refresh_response_is_not_retried(self):
        self.check_scenario("lost-response")

    def test_failed_save_preserves_rotated_tokens(self):
        self.check_scenario("failed-save")

    def test_explicit_temporary_response_retries_only_on_next_cycle(self):
        self.check_scenario("temporary-response")

    def test_unreadable_refresh_response_is_not_retried(self):
        self.check_scenario("unreadable-response")

    def test_concurrent_fetches_do_not_reuse_the_refresh_token(self):
        self.check_scenario("concurrent-refresh")

    def test_claude_cli_login_survives_a_stale_refresh_response(self):
        self.check_scenario("claude-login-changed")

    def test_claude_pending_save_does_not_replace_a_new_login(self):
        self.check_scenario("claude-pending-changed")

    def test_claude_preflight_does_not_replace_a_concurrent_cli_login(self):
        self.check_scenario("claude-preflight-race")

    def test_claude_save_does_not_replace_a_concurrent_cli_login(self):
        self.check_scenario("claude-save-race")

    def test_claude_defers_writes_while_cli_owns_the_storage_lock(self):
        self.check_scenario("claude-lock-busy")

    def test_claude_does_not_steal_a_stale_storage_lock(self):
        self.check_scenario("claude-lock-stale")

    def test_claude_does_not_write_or_release_another_lock_owner(self):
        self.check_scenario("claude-lock-lost")

    def test_claude_maintains_storage_lock_during_keychain_wait(self):
        self.check_scenario("claude-lock-heartbeat")

    def test_claude_profiles_use_separate_storage_locks(self):
        self.check_scenario("claude-profile-lock")

    def test_claude_does_not_renew_with_an_unsupported_cli(self):
        self.check_scenario("claude-unsupported-cli")

    def test_claude_native_login_waits_for_the_entire_refresh_cycle(self):
        self.check_scenario("claude-native-login")

    def test_claude_respects_the_native_oauth_refresh_lock(self):
        self.check_scenario("claude-oauth-busy")

    def test_claude_respects_the_legacy_oauth_lock_and_releases_partial_acquisition(self):
        self.check_scenario("claude-legacy-busy")

    def test_claude_rereads_credentials_after_acquiring_oauth_locks(self):
        self.check_scenario("claude-oauth-reread")

    def test_claude_concurrent_callers_share_one_refresh_result(self):
        self.check_scenario("claude-concurrent-refresh")

    def test_claude_does_not_save_or_release_another_oauth_lock_owner(self):
        self.check_scenario("claude-oauth-lost")

    def test_claude_adopts_cli_login_even_when_cached_token_is_unexpired(self):
        self.check_scenario("claude-cache-login")

    def test_claude_keeps_credentials_and_recovers_after_network_failure(self):
        self.check_scenario("claude-network-recovery")

    def test_claude_refresh_post_disables_automatic_http_retry(self):
        self.check_scenario("claude-refresh-no-retry")

    def test_claude_refresh_403_does_not_require_login(self):
        self.check_scenario("claude-refresh-forbidden")

    def test_claude_usage_403_does_not_rotate_credentials(self):
        self.check_scenario("claude-usage-forbidden")

    def test_claude_profiles_have_independent_oauth_locks(self):
        self.check_scenario("claude-oauth-profile")

    def test_claude_desktop_switch_also_selects_cli_by_default(self):
        self.check_scenario("claude-switch-default")

    def test_claude_desktop_only_switch_preserves_cli_selection(self):
        self.check_scenario("claude-switch-off")

    def test_claude_primary_cli_profile_does_not_set_an_explicit_config_path(self):
        self.check_scenario("claude-switch-main")

    def test_claude_shell_selection_works_without_notchlimits_or_network(self):
        for shell in ("/bin/zsh", "/bin/bash"):
            with self.subTest(shell=shell), tempfile.TemporaryDirectory(prefix="notchlimits-cli-shell-", dir="/private/tmp") as directory:
                root = pathlib.Path(directory)
                result = run_fixture(self.executable, "claude-switch-default", root)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                fake_bin = root / "bin"
                fake_bin.mkdir()
                fake_cli = fake_bin / "claude"
                fake_cli.write_text('#!/bin/sh\nprintf "%s\\n" "${CLAUDE_CONFIG_DIR-unset}" "$@"\n')
                fake_cli.chmod(0o700)
                script = root / "support/claude-cli/profile.sh"
                pointer = script.with_name("selected-profile")
                environment = {key: value for key, value in os.environ.items()
                               if key not in ("CLAUDE_CONFIG_DIR", "CLAUDE_SECURESTORAGE_CONFIG_DIR", "BASH_ENV", "ENV")}
                environment["PATH"] = str(fake_bin) + ":/usr/bin:/bin"
                command = '. "$1"; claude "argument with spaces"'
                def invoke(extra=None):
                    return subprocess.run([shell, "-f", "-c", command, "fixture", str(script)],
                                          env=environment | (extra or {}), capture_output=True, text=True, timeout=5)
                selected = pointer.read_text().rstrip("\n")
                result = invoke()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.splitlines(), [selected, "argument with spaces"])
                result = invoke({"CLAUDE_CONFIG_DIR": "/explicit/user/profile"})
                self.assertEqual(result.stdout.splitlines()[0], "/explicit/user/profile")
                pointer.write_text("\n")
                result = invoke()
                self.assertEqual(result.stdout.splitlines()[0], "unset")
                pointer.write_text("/missing/deleted/profile\n")
                result = invoke()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "", "Invalid selection silently used the main account")

    def test_claude_oauth_lock_prevents_cli_login_at_expired_storage_write_boundary(self):
        self.check_scenario("claude-write-boundary")

    def test_claude_maintains_both_oauth_heartbeats_during_http_refresh(self):
        self.check_scenario("claude-oauth-heartbeat")

    def test_claude_defers_renewal_without_noninteractive_keychain_write_permission(self):
        self.check_scenario("claude-no-write-permission")

    def test_claude_bash_integration_preserves_existing_login_and_interactive_startup(self):
        self.check_scenario("claude-switch-bash")

    def test_rotated_claude_credentials_reach_keychain_before_cli_can_refresh(self):
        self.check_scenario("claude-persist-before-unlock")

    def test_normal_quit_cannot_abandon_unsaved_claude_rotation(self):
        self.check_scenario("claude-quit-pending")

    def test_cli_selection_preserves_trailing_slash_service_identity(self):
        self.check_scenario("claude-switch-trailing-path")

    def test_cli_selection_preserves_resolved_path_service_identity(self):
        self.check_scenario("claude-switch-resolved-path")

    def test_failed_desktop_launch_restores_previous_cli_selection(self):
        self.check_scenario("claude-launch-failed")

    def test_failed_first_desktop_launch_preserves_default_cli_routing(self):
        self.check_scenario("claude-first-launch-failed")

    def test_failed_desktop_only_switch_leaves_cli_unchanged(self):
        self.check_scenario("claude-desktop-only-failed")

    def test_concurrent_account_switches_are_serialized(self):
        self.check_scenario("claude-switch-concurrent")

    def test_abandoned_notchlimits_oauth_locks_recover_without_running_claude(self):
        with tempfile.TemporaryDirectory(prefix="notchlimits-crash-recovery-", dir="/private/tmp") as directory:
            root = pathlib.Path(directory)
            crashed = run_fixture(self.executable, "claude-crash-owner", root)
            self.assertEqual(crashed.returncode, 0, crashed.stdout + crashed.stderr)
            recovered = run_fixture(self.executable, "claude-recover-owner", root)
            self.assertEqual(recovered.returncode, 0, recovered.stdout + recovered.stderr)

    def test_live_notchlimits_lock_owner_survives_stale_mtime(self):
        with tempfile.TemporaryDirectory(prefix="notchlimits-live-owner-", dir="/private/tmp") as directory:
            root = pathlib.Path(directory)
            owner = subprocess.Popen([str(self.executable), "claude-live-owner", str(root)],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                self.assertEqual(owner.stdout.readline().strip(), "READY")
                for path in (root / ".claude/.oauth_refresh.lock", root / ".claude.lock"):
                    os.utime(path, (1, 1))
                result = run_fixture(self.executable, "claude-preserve-owner", root)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            finally:
                owner.kill()
                owner.communicate(timeout=5)

    def test_abandoned_record_does_not_authorize_removing_a_replacement_lock(self):
        with tempfile.TemporaryDirectory(prefix="notchlimits-replacement-owner-", dir="/private/tmp") as directory:
            root = pathlib.Path(directory)
            crashed = run_fixture(self.executable, "claude-crash-owner", root)
            self.assertEqual(crashed.returncode, 0, crashed.stdout + crashed.stderr)
            lock = root / ".claude/.oauth_refresh.lock"
            lock.rename(lock.with_name(".previous-owner"))
            lock.mkdir()
            result = run_fixture(self.executable, "claude-preserve-owner", root)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_cli_selection_preserves_symlink_path_service_identity(self):
        self.check_scenario("claude-switch-aliased-path")

    def test_normal_quit_waits_for_inflight_claude_refresh_persistence(self):
        self.check_scenario("claude-quit-inflight")

    def test_cli_selection_rejects_service_hash_its_native_cli_cannot_reproduce(self):
        self.check_scenario("claude-switch-short-hash")

    def test_disabling_cli_switching_before_desktop_opens_preserves_cli_account(self):
        self.check_scenario("claude-switch-toggle-off")

    def test_enabling_cli_switching_before_desktop_opens_selects_cli_account(self):
        self.check_scenario("claude-switch-toggle-on")

    def test_enabling_cli_during_failed_desktop_launch_preserves_cli_account(self):
        self.check_scenario("claude-switch-toggle-on-failed")

    def test_removing_claude_profile_during_refresh_does_not_block_quit(self):
        self.check_scenario("claude-remove-inflight")

    def test_removing_claude_profile_with_pending_save_does_not_block_quit(self):
        self.check_scenario("claude-remove-pending")

    def test_failed_claude_removal_preserves_and_saves_rotated_credentials(self):
        self.check_scenario("claude-remove-denied")

    def test_readding_removed_profile_preserves_new_login_during_late_refresh(self):
        self.check_scenario("claude-remove-readd")

    def test_readded_login_does_not_join_removed_generation_result(self):
        self.check_scenario("claude-readd-inflight")

    def test_readded_expired_login_renews_once_after_removed_generation_finishes(self):
        self.check_scenario("claude-readd-expired-inflight")

    def test_save_already_resolving_a_profile_cannot_recreate_it_after_removal(self):
        self.check_scenario("claude-remove-during-save")

    def test_oauth_lock_resolution_cannot_recreate_a_removed_extra_profile(self):
        self.check_scenario("claude-remove-during-oauth-lock")

    def test_deleted_cli_profile_is_not_published_after_desktop_opens(self):
        self.check_scenario("claude-remove-staged-cli")

    def test_deleted_main_login_is_not_published_after_desktop_opens(self):
        self.check_scenario("claude-remove-staged-cli-main")

    def test_desktop_only_switch_survives_target_profile_removal(self):
        self.check_scenario("claude-remove-staged-cli-off")

    def test_failed_profile_removal_preserves_the_staged_cli_switch(self):
        self.check_scenario("claude-remove-staged-cli-denied")

    def test_removed_account_usage_cannot_overwrite_replacement_column_and_cache(self):
        self.check_scenario("claude-stale-usage-result")

    def test_native_lock_acquired_during_preparation_is_not_replaced(self):
        self.check_scenario("claude-native-publish")

    def test_crash_after_mkdir_does_not_leave_an_unrecoverable_lock(self):
        self.check_lock_preparation_crash("mkdir")

    def test_crash_during_owner_record_does_not_leave_an_unrecoverable_lock(self):
        self.check_lock_preparation_crash("record")

    def check_lock_preparation_crash(self, phase):
        with tempfile.TemporaryDirectory(prefix="notchlimits-preparation-crash-", dir="/private/tmp") as directory:
            root = pathlib.Path(directory)
            crashed = run_fixture(self.executable, "claude-crash-" + phase, root)
            self.assertEqual(crashed.returncode, 86, crashed.stdout + crashed.stderr)
            self.assertIn("FAULT:" + phase, crashed.stdout)
            recovered = run_fixture(self.executable, "claude-recover-owner", root)
            self.assertEqual(recovered.returncode, 0, recovered.stdout + recovered.stderr)

    def test_abandoned_previous_json_owner_record_remains_recoverable(self):
        with tempfile.TemporaryDirectory(prefix="notchlimits-legacy-owner-", dir="/private/tmp") as directory:
            root = pathlib.Path(directory)
            crashed = run_fixture(self.executable, "claude-crash-legacy", root)
            self.assertEqual(crashed.returncode, 0, crashed.stdout + crashed.stderr)
            recovered = run_fixture(self.executable, "claude-recover-owner", root)
            self.assertEqual(recovered.returncode, 0, recovered.stdout + recovered.stderr)

    def test_abandoned_owner_recovers_after_torn_sidecar_write(self):
        with tempfile.TemporaryDirectory(prefix="notchlimits-torn-owner-", dir="/private/tmp") as directory:
            root = pathlib.Path(directory)
            owner = subprocess.Popen([str(self.executable), "claude-live-owner", str(root)],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                self.assertEqual(owner.stdout.readline().strip(), "READY")
                for path in (root / ".claude/.oauth_refresh.lock.notchlimits-owner", root / ".claude.lock.notchlimits-owner"):
                    path.write_bytes(b'{')
            finally:
                owner.kill()
                owner.communicate(timeout=5)
            recovered = run_fixture(self.executable, "claude-recover-owner", root)
            self.assertEqual(recovered.returncode, 0, recovered.stdout + recovered.stderr)

    def test_native_rmdir_can_reap_abandoned_marked_lock_directories(self):
        with tempfile.TemporaryDirectory(prefix="notchlimits-native-reap-", dir="/private/tmp") as directory:
            root = pathlib.Path(directory)
            crashed = run_fixture(self.executable, "claude-crash-owner", root)
            self.assertEqual(crashed.returncode, 0, crashed.stdout + crashed.stderr)
            for path in (root / ".claude/.oauth_refresh.lock", root / ".claude.lock"):
                self.assertEqual(list(path.iterdir()), [], "Owner metadata made the native lock directory nonempty")
                os.utime(path, (1, 1))
                path.rmdir()
            recovered = run_fixture(self.executable, "claude-recover-owner", root)
            self.assertEqual(recovered.returncode, 0, recovered.stdout + recovered.stderr)

    def test_removal_waits_for_native_mutation_then_allows_retry(self):
        self.check_scenario("claude-remove-native-writer")

    def test_extra_profile_removal_waits_for_native_mutation(self):
        self.check_scenario("claude-remove-native-profile-writer")

    def test_removal_respects_independent_legacy_oauth_owner(self):
        self.check_scenario("claude-remove-native-legacy-writer")

    def test_removal_respects_independent_storage_owner(self):
        self.check_scenario("claude-remove-native-storage-writer")

    def test_unmapped_profile_cannot_bypass_removal_locks(self):
        self.check_scenario("claude-remove-unmapped")

    def test_recovery_preserves_native_replacement_after_marker_read(self):
        with tempfile.TemporaryDirectory(prefix="notchlimits-recovery-replacement-", dir="/private/tmp") as directory:
            root = pathlib.Path(directory)
            crashed = run_fixture(self.executable, "claude-crash-owner", root)
            self.assertEqual(crashed.returncode, 0, crashed.stdout + crashed.stderr)
            for path in (root / ".claude/.oauth_refresh.lock", root / ".claude.lock"):
                os.utime(path, (1, 1))
            result = run_fixture(self.executable, "claude-recovery-replacement", root)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_readded_profile_gets_fresh_desktop_session_and_selects_cli(self):
        self.check_scenario("claude-readded-desktop")

    def test_readded_desktop_only_profile_preserves_cli(self):
        self.check_scenario("claude-readded-desktop-off")

    def test_readded_main_profile_gets_fresh_desktop_session(self):
        self.check_scenario("claude-readded-desktop-main")

    def test_failed_deletion_preserves_desktop_session(self):
        self.check_scenario("claude-remove-desktop-denied")

    def test_pending_desktop_launch_cannot_publish_readded_cli_target(self):
        self.check_scenario("claude-readd-staged-cli")

    def test_pending_desktop_only_launch_does_not_mark_replacement_open(self):
        self.check_scenario("claude-readd-staged-cli-off")

    def test_codex_store_keyring(self):
        self.check_scenario("codex-store-keyring")

    def test_codex_store_auto(self):
        self.check_scenario("codex-store-auto")

    def test_codex_store_file(self):
        self.check_scenario("codex-store-file")

    def test_codex_store_auto_missing(self):
        self.check_scenario("codex-store-auto-missing")

    def test_codex_store_auto_denied(self):
        self.check_scenario("codex-store-auto-denied")

    def test_codex_store_keyring_denied(self):
        self.check_scenario("codex-store-keyring-denied")

    def test_codex_store_ephemeral(self):
        self.check_scenario("codex-store-ephemeral")

    def test_codex_store_invalid(self):
        self.check_scenario("codex-store-invalid")

    def test_codex_store_discovery(self):
        self.check_scenario("codex-store-discovery")

    def test_codex_store_symlink(self):
        self.check_scenario("codex-store-symlink")

    def test_codex_store_switch(self):
        self.check_scenario("codex-store-switch")

    def test_codex_store_switch_incoming_keyring(self):
        self.check_scenario("codex-store-switch-incoming-keyring")

    def test_codex_store_switch_incoming_file(self):
        self.check_scenario("codex-store-switch-incoming-file")

    def test_codex_store_renewal(self):
        self.check_scenario("codex-store-renewal")

    def test_codex_store_renewal_denied(self):
        self.check_scenario("codex-store-renewal-denied")

    def test_codex_store_remove(self):
        self.check_scenario("codex-store-remove")

    def test_codex_store_remove_denied(self):
        self.check_scenario("codex-store-remove-denied")

    def test_codex_store_root_settings(self):
        self.check_scenario("codex-store-root-settings")

    def test_codex_store_system_requirements(self):
        self.check_scenario("codex-store-system-requirements")

    def test_codex_store_managed_requirements(self):
        self.check_scenario("codex-store-managed-requirements")

    def test_codex_store_ephemeral_switch(self):
        self.check_scenario("codex-store-ephemeral-switch")

    def test_codex_store_auto_renewal(self):
        self.check_scenario("codex-store-auto-renewal")

    def test_codex_store_auto_renewal_denied(self):
        self.check_scenario("codex-store-auto-renewal-denied")

    def test_codex_store_auto_switch(self):
        self.check_scenario("codex-store-auto-switch")

    def test_codex_store_auto_fallback_switch(self):
        self.check_scenario("codex-store-auto-fallback-switch")

    def test_codex_store_ephemeral_current(self):
        self.check_scenario("codex-store-ephemeral-current")

    def test_codex_store_encrypted(self):
        self.check_scenario("codex-store-encrypted")

    def test_codex_auto_source_loss(self):
        self.check_scenario("codex-auto-source-loss")

    def test_codex_readd_pending_loss(self):
        self.check_scenario("codex-readd-pending-loss")

    def test_codex_switch_inflight(self):
        self.check_scenario("codex-switch-inflight")

    def test_claude_file_discovery(self):
        self.check_scenario("claude-file-discovery")

    def test_claude_file_removal(self):
        self.check_scenario("claude-file-removal")

    def test_codex_toml_mode(self):
        self.check_scenario("codex-toml-mode")

    def test_codex_toml_backend(self):
        self.check_scenario("codex-toml-backend")

    def test_codex_auto_source_no_fallback(self):
        self.check_scenario("codex-auto-source-no-fallback")

    def test_codex_auto_file_source(self):
        self.check_scenario("codex-auto-file-source")

    def test_codex_switch_inflight_file(self):
        self.check_scenario("codex-switch-inflight-file")

    def test_codex_switch_pending(self):
        self.check_scenario("codex-switch-pending")

    def test_codex_remove_denied_pending(self):
        self.check_scenario("codex-remove-denied-pending")

    def test_claude_file_lifecycle_main(self):
        self.check_scenario("claude-file-lifecycle-main")

    def test_claude_file_lifecycle_profile(self):
        self.check_scenario("claude-file-lifecycle-profile")

    def test_claude_file_lifecycle_off(self):
        self.check_scenario("claude-file-lifecycle-off")

    def test_claude_file_save_recovery(self):
        self.check_scenario("claude-file-save-recovery")

    def test_claude_file_lock_busy(self):
        self.check_scenario("claude-file-lock-busy")

    def test_claude_file_relogin(self):
        self.check_scenario("claude-file-relogin")

    def test_codex_toml_forms(self):
        self.check_scenario("codex-toml-forms")

    def test_codex_switch_inflight_alias(self):
        self.check_scenario("codex-switch-inflight-alias")

    def test_codex_renewal_base_alias(self):
        self.check_scenario("codex-renewal-base-alias")

    def test_claude_remove_fallback_denied_keychain(self):
        self.check_scenario("claude-remove-fallback-denied-keychain")

    def test_claude_remove_fallback_denied_file(self):
        self.check_scenario("claude-remove-fallback-denied-file")

    def test_codex_remove_fallback_denied_keychain(self):
        self.check_scenario("codex-remove-fallback-denied-keychain")

    def test_codex_remove_fallback_denied_file(self):
        self.check_scenario("codex-remove-fallback-denied-file")

    def test_codex_quit_inflight(self):
        self.check_scenario("codex-quit-inflight")

    def test_codex_quit_pending(self):
        self.check_scenario("codex-quit-pending")

    def test_codex_quit_without_claude(self):
        self.check_scenario("codex-quit-without-claude")

    def test_codex_quit_timeout(self):
        self.check_scenario("codex-quit-timeout")

    def test_codex_auto_copyback(self):
        self.check_scenario("codex-auto-copyback")

    def test_codex_auto_copyback_fallback(self):
        self.check_scenario("codex-auto-copyback-fallback")

    def test_claude_profile_cleanup_denied(self):
        self.check_scenario("claude-profile-cleanup-denied")

    def test_codex_profile_cleanup_denied(self):
        self.check_scenario("codex-profile-cleanup-denied")

    def test_claude_profile_move_denied(self):
        self.check_scenario("claude-profile-move-denied")

    def test_claude_profile_rollback_maintains_native_lock_heartbeat(self):
        self.check_scenario("claude-profile-rollback-heartbeat")

    def test_codex_profile_move_denied(self):
        self.check_scenario("codex-profile-move-denied")

    def test_codex_active_removal(self):
        self.check_scenario("codex-active-removal")

    def test_codex_primary_removal(self):
        self.check_scenario("codex-primary-removal")

    def test_codex_primary_direct_removal(self):
        self.check_scenario("codex-primary-direct-removal")

    def test_codex_removal_quit_refused(self):
        self.check_scenario("codex-removal-quit-refused")

    def test_codex_removal_sync_guard(self):
        self.check_scenario("codex-removal-sync-guard")

    def test_codex_removal_switch_barrier(self):
        self.check_scenario("codex-removal-switch-barrier")

    def test_codex_auto_renew_unavailable(self):
        self.check_scenario("codex-auto-renew-unavailable")

    def test_codex_auto_force_unavailable(self):
        self.check_scenario("codex-auto-force-unavailable")

    def test_codex_auto_renew_recovery(self):
        self.check_scenario("codex-auto-renew-recovery")

    def test_codex_canonical_base_keyring(self):
        self.check_scenario("codex-canonical-base-keyring")

    def test_codex_canonical_base_file(self):
        self.check_scenario("codex-canonical-base-file")

    def test_codex_canonical_base_direct(self):
        self.check_scenario("codex-canonical-base-direct")

    def test_codex_canonical_base_activation_is_rejected(self):
        self.check_scenario("codex-canonical-base-activate")

    def test_codex_legacy_canonical_base_alias_keeps_current_native_grant(self):
        self.check_scenario("codex-canonical-base-legacy")

    def test_codex_native_base_without_auth_is_not_an_unfinished_profile(self):
        self.check_scenario("codex-canonical-base-menu")

    def test_codex_usage_and_switch_share_a_consistent_credential_snapshot(self):
        self.check_scenario("codex-usage-switch-snapshot")

    def test_codex_save_prepare_file(self):
        self.check_scenario("codex-save-prepare-file")

    def test_codex_save_prepare_auto(self):
        self.check_scenario("codex-save-prepare-auto")

    def test_claude_rollback_collision(self):
        self.check_scenario("claude-rollback-collision")

    def test_codex_rollback_collision(self):
        self.check_scenario("codex-rollback-collision")

    def test_claude_rollback_pending_collision(self):
        self.check_scenario("claude-rollback-pending-collision")

    def test_codex_rollback_pending_collision(self):
        self.check_scenario("codex-rollback-pending-collision")

    def test_claude_rollback_replacement(self):
        self.check_scenario("claude-rollback-replacement")

    def test_codex_rollback_replacement(self):
        self.check_scenario("codex-rollback-replacement")

    def test_claude_rollback_native_owner(self):
        self.check_scenario("claude-rollback-native-owner")

    def test_claude_incomplete_respects_native_oauth_locks(self):
        self.check_scenario("claude-incomplete-native-oauth")

    def test_claude_incomplete_respects_native_storage_lock(self):
        self.check_scenario("claude-incomplete-native-storage")

    def test_claude_incomplete_respects_native_legacy_lock(self):
        self.check_scenario("claude-incomplete-native-legacy")

    def test_claude_incomplete_preserves_completed_keychain_login(self):
        self.check_scenario("claude-incomplete-completed-keychain")

    def test_claude_incomplete_preserves_completed_fallback_login(self):
        self.check_scenario("claude-incomplete-completed-file")

    def test_claude_incomplete_empty_profile_can_be_removed_and_readded(self):
        self.check_scenario("claude-incomplete-empty")

    def test_claude_incomplete_removes_native_non_login_stub_under_leases(self):
        self.check_scenario("claude-incomplete-stub")

    def test_claude_incomplete_preserves_unreadable_owner(self):
        self.check_scenario("claude-incomplete-unreadable-owner")

    def test_claude_incomplete_restores_directory_after_refused_stub_deletion(self):
        self.check_scenario("claude-incomplete-stub-refusal")

    def test_claude_incomplete_does_not_recreate_missing_profile(self):
        self.check_scenario("claude-incomplete-missing")

    def test_codex_primary_removal_preserves_selection_when_backup_keyring_refuses_delete(self):
        self.check_scenario("codex-primary-backup-keyring-refusal")

    def test_codex_selected_removal_preserves_profile_when_backup_keyring_refuses_delete(self):
        self.check_scenario("codex-selected-backup-keyring-refusal")

    def test_codex_primary_removal_preserves_selection_when_backup_file_refuses_delete(self):
        self.check_scenario("codex-primary-backup-file-refusal")

    def test_codex_keyring_target_refusal_restores_removed_primary_backup(self):
        self.check_scenario("codex-keyring-delete-restores-backup")

    def test_codex_file_target_refusal_restores_removed_primary_backup(self):
        self.check_scenario("codex-file-delete-restores-backup")

    def test_claude_incomplete_symlink_releases_physical_locks(self):
        self.check_scenario("claude-incomplete-symlink")

    def test_claude_borrowed_lease_respects_new_native_current(self):
        self.check_scenario("claude-borrowed-foreign-current")

    def test_claude_borrowed_lease_can_retry_ordinary_rollback(self):
        self.check_scenario("claude-borrowed-normal-retry")

    def test_claude_shared_directory_preserves_other_cli_owner(self):
        self.check_scenario("claude-shared-extra")

    def test_claude_shared_directory_preserves_cli_off_setting(self):
        self.check_scenario("claude-shared-extra-cli-off")

    def test_claude_shared_directory_preserves_other_fallback(self):
        self.check_scenario("claude-shared-extra-fallback")

    def test_claude_shared_directory_defers_when_metadata_is_unavailable(self):
        self.check_scenario("claude-shared-extra-metadata-denied")

    def test_claude_stale_file_owner_cannot_delete_a_new_shared_login(self):
        self.check_scenario("claude-shared-extra-file-owner")

    def test_claude_incomplete_defers_when_metadata_is_unavailable(self):
        self.check_scenario("claude-incomplete-metadata-denied")

    def test_codex_restore_rolls_back_refused_keyring_cleanup(self):
        self.check_scenario("codex-restore-backup-keyring-refusal")

    def test_codex_restore_rolls_back_refused_file_cleanup(self):
        self.check_scenario("codex-restore-backup-file-refusal")

    def test_codex_restore_rolls_back_refused_auto_cleanup(self):
        self.check_scenario("codex-restore-backup-auto-refusal")

    def test_codex_restore_refusal_preserves_native_copyback_progress(self):
        self.check_scenario("codex-restore-backup-native-progress")

    def test_codex_primary_removal_cleans_legacy_keyring_backup(self):
        self.check_scenario("codex-legacy-backup-keyring-removal")

    def test_codex_primary_removal_cleans_legacy_file_backup(self):
        self.check_scenario("codex-legacy-backup-file-removal")

    def test_codex_primary_removal_cleans_legacy_auto_backup(self):
        self.check_scenario("codex-legacy-backup-auto-removal")

    def test_codex_primary_removal_preserves_refused_legacy_backup(self):
        self.check_scenario("codex-legacy-backup-refusal")

    def test_claude_physical_trailing_path_selects_exact_cli_service(self):
        self.check_scenario("claude-physical-trailing-switch")

    def test_claude_physical_trailing_path_renews_under_native_locks(self):
        self.check_scenario("claude-physical-trailing-renewal")

    def test_claude_physical_trailing_owner_survives_shared_removal(self):
        self.check_scenario("claude-physical-trailing-shared")

    def test_claude_physical_trailing_owner_preserves_cli_off(self):
        self.check_scenario("claude-physical-trailing-shared-off")

    def test_claude_physical_trailing_owner_preserves_shared_fallback(self):
        self.check_scenario("claude-physical-trailing-shared-fallback")

    def test_codex_auto_file_fallback_rolls_back_backup_file_refusal(self):
        self.check_scenario("codex-auto-fallback-restore-file-refusal")

    def test_codex_auto_file_fallback_rolls_back_backup_keyring_refusal(self):
        self.check_scenario("codex-auto-fallback-restore-keyring-refusal")

    def test_codex_auto_file_fallback_rolls_back_selected_removal_refusal(self):
        self.check_scenario("codex-auto-fallback-selected-refusal")

    def test_codex_auto_file_fallback_rolls_back_primary_removal_refusal(self):
        self.check_scenario("codex-auto-fallback-primary-refusal")

    def test_codex_auto_fallback_rollback_preserves_later_native_copyback(self):
        self.check_scenario("codex-auto-fallback-native-progress")

    def test_codex_auto_file_fallback_restores_primary_after_keychain_recovers(self):
        self.check_scenario("codex-auto-fallback-restore-success")

    def test_codex_native_canonical_keyring_read(self):
        self.check_scenario("codex-native-canonical-keyring")

    def test_codex_native_canonical_auto_prefers_keyring(self):
        self.check_scenario("codex-native-canonical-auto")

    def test_codex_native_canonical_save_updates_existing_item(self):
        self.check_scenario("codex-native-canonical-save")

    def test_codex_native_canonical_keyring_removal(self):
        self.check_scenario("codex-native-canonical-remove")

    def test_codex_native_canonical_auto_removal(self):
        self.check_scenario("codex-native-canonical-remove-auto")

    def test_codex_native_canonical_renewal(self):
        self.check_scenario("codex-native-canonical-renew")

    def test_codex_native_canonical_switch_and_copyback(self):
        self.check_scenario("codex-native-canonical-switch")

    def test_codex_native_canonical_file_mode_control(self):
        self.check_scenario("codex-native-canonical-file")

    def test_codex_retarget_readd_same_grant_retires_request(self):
        self.check_scenario("codex-retarget-readd-same")

    def test_codex_retarget_readd_new_grant_control(self):
        self.check_scenario("codex-retarget-readd-new")

    def test_codex_retarget_preserves_inflight_rotation_at_original_owner(self):
        self.check_scenario("codex-retarget-inflight")

    def test_codex_retarget_drains_pending_rotation_to_original_owner(self):
        self.check_scenario("codex-retarget-pending")

    def test_codex_retarget_aba_retires_late_usage_401(self):
        self.check_scenario("codex-retarget-usage-aba")

    def test_claude_stub_result_cannot_hide_new_cli_login(self):
        self.check_scenario("claude-stub-login-race")

    def test_claude_stub_same_timestamp_cannot_hide_new_login(self):
        self.check_scenario("claude-stub-same-date")

    def test_claude_stub_legacy_marker_cannot_hide_valid_login(self):
        self.check_scenario("claude-stub-legacy-marker")

    def test_claude_stub_denied_owner_does_not_follow_stale_fallback(self):
        self.check_scenario("claude-stub-owner-denied")

    def test_claude_stub_malformed_owner_does_not_follow_stale_fallback(self):
        self.check_scenario("claude-stub-owner-malformed")

    def test_claude_genuine_stub_remains_hidden_control(self):
        self.check_scenario("claude-stub-genuine")

    def test_claude_stub_later_login_is_discovered_control(self):
        self.check_scenario("claude-stub-later-login")


    def test_codex_rollback_preserves_new_cli_file(self):
        self.check_scenario("codex-rollback-new-cli-file")

    def test_codex_rollback_preserves_new_cli_symlink(self):
        self.check_scenario("codex-rollback-new-cli-symlink")

    def test_codex_rollback_restores_missing_file_control(self):
        self.check_scenario("codex-rollback-missing-file-control")

    def test_codex_active_alias_skips_file_renewal(self):
        self.check_scenario("codex-active-alias-file")

    def test_codex_active_alias_skips_keyring_renewal(self):
        self.check_scenario("codex-active-alias-keyring")

    def test_codex_active_alias_skips_auto_renewal(self):
        self.check_scenario("codex-active-alias-auto")

    def test_codex_sleeping_alias_renews_control(self):
        self.check_scenario("codex-sleeping-alias-control")

    def test_codex_copyback_pins_file_owner(self):
        self.check_scenario("codex-copyback-pinned-file")

    def test_codex_copyback_pins_keyring_owner(self):
        self.check_scenario("codex-copyback-pinned-keyring")

    def test_codex_copyback_pins_auto_owner(self):
        self.check_scenario("codex-copyback-pinned-auto")

    def test_codex_copyback_stable_symlink_control(self):
        self.check_scenario("codex-copyback-stable-symlink-control")

    def test_codex_copyback_legacy_canonical_control(self):
        self.check_scenario("codex-copyback-legacy-canonical-control")

    def test_codex_copyback_legacy_symlink_preserves_both_owners(self):
        self.check_scenario("codex-copyback-legacy-symlink")

    def test_codex_refused_removal_restores_pinned_owner(self):
        self.check_scenario("codex-copyback-pinned-rollback")

    def test_codex_retarget_to_base_retains_selected_owner(self):
        self.check_scenario("codex-retarget-to-base-pinned")

    def test_claude_retired_401_preserves_new_refresh_grant(self):
        self.check_scenario("claude-retired-401-new-refresh")

    def test_claude_retired_401_preserves_same_grant_readd(self):
        self.check_scenario("claude-retired-401-same-grant")

    def test_claude_old_401_preserves_relogin_with_same_access(self):
        self.check_scenario("claude-retired-401-relogin")

    def test_claude_old_401_preserves_new_access_control(self):
        self.check_scenario("claude-retired-401-new-access-control")

    def test_claude_current_401_still_renews_control(self):
        self.check_scenario("claude-current-401-control")

    def test_codex_rollback_implicit_file_keyring(self):
        self.check_scenario("codex-rollback-implicit-file-keyring")

    def test_codex_rollback_implicit_file_auto(self):
        self.check_scenario("codex-rollback-implicit-file-auto")

    def test_codex_rollback_explicit_file_control(self):
        self.check_scenario("codex-rollback-explicit-file-control")

    def test_codex_rollback_metadata_only_control(self):
        self.check_scenario("codex-rollback-metadata-only-control")

    def test_claude_primary_shared_preserves_fallback(self):
        self.check_scenario("claude-primary-shared-preserves-fallback")

    def test_claude_primary_shared_cli_off(self):
        self.check_scenario("claude-primary-shared-cli-off")

    def test_claude_primary_shared_metadata_denied(self):
        self.check_scenario("claude-primary-shared-metadata-denied")

    def test_claude_primary_shared_stale_file_owner(self):
        self.check_scenario("claude-primary-shared-stale-file-owner")

    def test_claude_primary_shared_delete_denied_control(self):
        self.check_scenario("claude-primary-shared-delete-denied-control")

    def test_claude_primary_shared_lone_control(self):
        self.check_scenario("claude-primary-shared-lone-control")

    def test_codex_backup_alias_fence_file(self):
        self.check_scenario("codex-backup-alias-fence-file")

    def test_codex_backup_alias_fence_keyring(self):
        self.check_scenario("codex-backup-alias-fence-keyring")

    def test_codex_backup_alias_fence_auto(self):
        self.check_scenario("codex-backup-alias-fence-auto")

    def test_codex_backup_direct_fence_control(self):
        self.check_scenario("codex-backup-direct-fence-control")

    def test_codex_backup_unrelated_switch_control(self):
        self.check_scenario("codex-backup-unrelated-switch-control")

    def test_codex_backup_alias_pending_file(self):
        self.check_scenario("codex-backup-alias-pending-file")

    def test_codex_backup_alias_pending_keyring(self):
        self.check_scenario("codex-backup-alias-pending-keyring")

    def test_codex_backup_alias_primary_removal(self):
        self.check_scenario("codex-backup-alias-primary-removal")

    def test_codex_retired_temporary_same_grant(self):
        self.check_scenario("codex-retired-temporary-same-grant")

    def test_codex_current_temporary_control(self):
        self.check_scenario("codex-current-temporary-control")

    def test_codex_retired_temporary_new_grant_control(self):
        self.check_scenario("codex-retired-temporary-new-grant-control")

    def test_codex_retired_success_no_replay(self):
        self.check_scenario("codex-retired-success-no-replay")

    def test_codex_retired_lost_no_replay(self):
        self.check_scenario("codex-retired-lost-no-replay")

    def test_codex_retired_rejected_no_replay(self):
        self.check_scenario("codex-retired-rejected-no-replay")

    def test_codex_retired_success_new_grant_control(self):
        self.check_scenario("codex-retired-success-new-grant-control")

    def test_codex_firmlink_active_file(self):
        self.check_scenario("codex-firmlink-active-file")

    def test_codex_firmlink_base_file(self):
        self.check_scenario("codex-firmlink-base-file")

    def test_codex_firmlink_active_auto_fallback(self):
        self.check_scenario("codex-firmlink-active-auto-fallback")

    def test_codex_firmlink_sleeping_control(self):
        self.check_scenario("codex-firmlink-sleeping-control")

    def test_codex_firmlink_independent_keyring_control(self):
        self.check_scenario("codex-firmlink-independent-keyring-control")

    def test_codex_native_grant_copy_file(self):
        self.check_scenario("codex-native-grant-copy-file")

    def test_codex_native_grant_copy_keyring(self):
        self.check_scenario("codex-native-grant-copy-keyring")

    def test_codex_native_grant_copy_auto(self):
        self.check_scenario("codex-native-grant-copy-auto")

    def test_codex_independent_same_account_control(self):
        self.check_scenario("codex-independent-same-account-control")

    def test_codex_firmlink_backup_restore(self):
        self.check_scenario("codex-firmlink-backup-restore")

    def test_codex_firmlink_backup_pending(self):
        self.check_scenario("codex-firmlink-backup-pending")

    def test_codex_firmlink_backup_remove(self):
        self.check_scenario("codex-firmlink-backup-remove")

    def test_codex_firmlink_retired_usage(self):
        self.check_scenario("codex-firmlink-retired-usage")

    def test_codex_firmlink_current_usage_control(self):
        self.check_scenario("codex-firmlink-current-usage-control")

    def test_codex_renewal_directory_generation(self):
        self.check_scenario("codex-renewal-directory-generation")

    def test_codex_renewal_atomic_file_control(self):
        self.check_scenario("codex-renewal-atomic-file-control")

    def test_claude_new_main_file_login_after_shared_removal_is_rediscovered(self):
        self.check_scenario("claude-main-file-readd")

    def test_claude_same_grant_main_file_rewrite_after_shared_removal_is_rediscovered(self):
        self.check_scenario("claude-main-file-same-grant-readd")

    def test_claude_first_main_file_login_with_shared_hashed_owner_is_discovered(self):
        self.check_scenario("claude-main-file-first-shared")

    def test_claude_new_main_keychain_login_control(self):
        self.check_scenario("claude-main-keychain-readd-control")

    def test_claude_new_main_file_login_without_shared_owner_control(self):
        self.check_scenario("claude-main-file-unshared-control")

    def test_claude_unchanged_shared_fallback_does_not_resurrect_primary_control(self):
        self.check_scenario("claude-main-file-unchanged-shared-control")

    def test_claude_denied_preferred_owner_with_stub_fallback_keeps_polling_interval(self):
        self.check_scenario("claude-preferred-denied-stub-polling")

    def test_claude_malformed_preferred_owner_with_stub_fallback_keeps_polling_interval(self):
        self.check_scenario("claude-preferred-malformed-stub-polling")

    def test_claude_denied_preferred_owner_with_valid_fallback_control(self):
        self.check_scenario("claude-preferred-valid-fallback-control")

    def test_claude_genuine_keychain_stub_leaves_polling_control(self):
        self.check_scenario("claude-preferred-keychain-stub-control")

    def test_claude_genuine_file_only_stub_leaves_polling_control(self):
        self.check_scenario("claude-preferred-file-stub-control")

    def test_codex_firmlink_keyring_refresh_preserves_native_file_fallback(self):
        self.check_scenario("codex-firmlink-mixed-auto-cleanup")

    def test_codex_firmlink_keyring_refresh_preserves_selected_file_fallback(self):
        self.check_scenario("codex-firmlink-mixed-auto-selected")

    def test_codex_firmlink_auto_keyring_sessions_remain_independent_control(self):
        self.check_scenario("codex-firmlink-mixed-auto-keyring-control")

    def test_codex_native_rotation_file_copied_restore(self):
        self.check_scenario("codex-native-rotation-file-copied-restore")

    def test_codex_native_rotation_file_independent_control(self):
        self.check_scenario("codex-native-rotation-file-independent-control")

    def test_codex_native_rotation_keyring_copied_restore(self):
        self.check_scenario("codex-native-rotation-keyring-copied-restore")

    def test_codex_native_rotation_keyring_independent_control(self):
        self.check_scenario("codex-native-rotation-keyring-independent-control")

    def test_codex_native_rotation_auto_copied_restore(self):
        self.check_scenario("codex-native-rotation-auto-copied-restore")

    def test_codex_native_rotation_auto_independent_control(self):
        self.check_scenario("codex-native-rotation-auto-independent-control")

    def test_codex_native_rotation_copied_poll(self):
        self.check_scenario("codex-native-rotation-copied-poll")

    def test_codex_clone_copyback_retry(self):
        self.check_scenario("codex-clone-copyback-retry")

    def test_codex_clone_copyback_independent_control(self):
        self.check_scenario("codex-clone-copyback-independent-control")

    def test_codex_clone_copyback_new_backup(self):
        self.check_scenario("codex-clone-copyback-new-backup")

    def test_codex_clone_copyback_new_profile(self):
        self.check_scenario("codex-clone-copyback-new-profile")

    def test_codex_mixed_auto_activation_file(self):
        self.check_scenario("codex-mixed-auto-activation-file")

    def test_codex_mixed_auto_activation_keyring_control(self):
        self.check_scenario("codex-mixed-auto-activation-keyring-control")

    def test_codex_clone_copyback_pending_poll(self):
        self.check_scenario("codex-clone-copyback-pending-poll")

    def test_codex_clone_copyback_native_logout(self):
        self.check_scenario("codex-clone-copyback-native-logout")

    def test_codex_shared_file_remove(self):
        self.check_scenario("codex-shared-file-remove")

    def test_codex_shared_file_remove_separate_control(self):
        self.check_scenario("codex-shared-file-remove-separate-control")

    def test_codex_shared_file_copyback(self):
        self.check_scenario("codex-shared-file-copyback")

    def test_codex_shared_file_copyback_separate_control(self):
        self.check_scenario("codex-shared-file-copyback-separate-control")

    def test_codex_shared_file_renew(self):
        self.check_scenario("codex-shared-file-renew")

    def test_codex_shared_file_renew_separate_control(self):
        self.check_scenario("codex-shared-file-renew-separate-control")

    def test_codex_backup_recovery_file_restore(self):
        self.check_scenario("codex-backup-recovery-file-restore")

    def test_codex_backup_recovery_file_renew(self):
        self.check_scenario("codex-backup-recovery-file-renew")

    def test_codex_backup_recovery_file_control(self):
        self.check_scenario("codex-backup-recovery-file-control")

    def test_codex_backup_recovery_keyring_restore(self):
        self.check_scenario("codex-backup-recovery-keyring-restore")

    def test_codex_backup_recovery_keyring_renew(self):
        self.check_scenario("codex-backup-recovery-keyring-renew")

    def test_codex_backup_recovery_keyring_control(self):
        self.check_scenario("codex-backup-recovery-keyring-control")

    def test_codex_backup_recovery_readd(self):
        self.check_scenario("codex-backup-recovery-readd")

    def test_codex_usage_snapshot_file_login(self):
        self.check_scenario("codex-usage-snapshot-file-login")

    def test_codex_usage_snapshot_file_none(self):
        self.check_scenario("codex-usage-snapshot-file-none")

    def test_codex_usage_snapshot_keyring_login(self):
        self.check_scenario("codex-usage-snapshot-keyring-login")

    def test_codex_usage_snapshot_keyring_none(self):
        self.check_scenario("codex-usage-snapshot-keyring-none")

    def test_codex_usage_snapshot_auto_login(self):
        self.check_scenario("codex-usage-snapshot-auto-login")

    def test_codex_usage_snapshot_auto_none(self):
        self.check_scenario("codex-usage-snapshot-auto-none")

    def test_claude_usage_snapshot_keychain_login(self):
        self.check_scenario("claude-usage-snapshot-keychain-login")

    def test_claude_usage_snapshot_keychain_none(self):
        self.check_scenario("claude-usage-snapshot-keychain-none")

    def test_claude_usage_snapshot_file_login(self):
        self.check_scenario("claude-usage-snapshot-file-login")

    def test_claude_usage_snapshot_file_none(self):
        self.check_scenario("claude-usage-snapshot-file-none")

    def test_codex_usage_snapshot_metadata_control(self):
        self.check_scenario("codex-usage-snapshot-metadata-control")

    def test_codex_usage_snapshot_retired_401(self):
        self.check_scenario("codex-usage-snapshot-retired-401")

    def test_codex_usage_snapshot_retired_429(self):
        self.check_scenario("codex-usage-snapshot-retired-429")

    def test_codex_usage_snapshot_unreadable(self):
        self.check_scenario("codex-usage-snapshot-unreadable")

    def test_claude_usage_snapshot_metadata_control(self):
        self.check_scenario("claude-usage-snapshot-metadata-control")

    def test_claude_usage_snapshot_retired_401(self):
        self.check_scenario("claude-usage-snapshot-retired-401")

    def test_claude_usage_snapshot_retired_429(self):
        self.check_scenario("claude-usage-snapshot-retired-429")

    def test_claude_usage_snapshot_unreadable(self):
        self.check_scenario("claude-usage-snapshot-unreadable")

    def test_codex_shared_directory_file(self):
        self.check_scenario("codex-shared-directory-file")

    def test_codex_shared_directory_selected(self):
        self.check_scenario("codex-shared-directory-selected")

    def test_codex_shared_directory_keyring(self):
        self.check_scenario("codex-shared-directory-keyring")

    def test_codex_separate_directory_file_control(self):
        self.check_scenario("codex-separate-directory-file-control")

    def test_codex_separate_directory_keyring_control(self):
        self.check_scenario("codex-separate-directory-keyring-control")
