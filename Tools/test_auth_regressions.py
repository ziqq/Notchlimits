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
        keychain = (SOURCES / "Providers/ClaudeKeychain.swift").read_text()
        flags = () if "expected: Credentials" in keychain else ("-DLEGACY_CLAUDE_SAVE",)
        provider = (SOURCES / "Providers/ClaudeProvider.swift").read_text()
        if "func prepareForTermination(" in provider:
            flags += ("-DCLAUDE_TERMINATION_DRAIN",)
        cls.executable = compile_fixture(cls.build.name, "Authentication", [
            "Model/Models.swift", "Model/Account.swift", "Core/JWT.swift",
            *(["Core/ClaudeStorageLock.swift"] if (SOURCES / "Core/ClaudeStorageLock.swift").exists() else []),
            *(["Core/CodexAuthStorage.swift"] if (SOURCES / "Core/CodexAuthStorage.swift").exists() else []),
            "Core/CodexAuthSwap.swift", "Core/AccountRemoval.swift",
            "Core/AccountSwitcher.swift", "Core/AppAccountSwitcher.swift",
            *(["Core/ClaudeCLISelection.swift"] if (SOURCES / "Core/ClaudeCLISelection.swift").exists() else []),
            "Core/DefaultsMigration.swift", "Core/UsageStore.swift", "Core/UsageCache.swift",
            "Providers/ClaudeKeychain.swift", "Providers/ClaudeOAuth.swift",
            "Providers/ClaudeProvider.swift", "Providers/CodexOAuth.swift",
            "Providers/CodexProvider.swift", "Providers/RealDiscovery.swift",
        ], flags)

    def check_scenario(self, scenario):
        # Match the canonical home URLs returned by macOS directory discovery.
        with tempfile.TemporaryDirectory(prefix="notchlimits-auth-fixture-", dir="/private/tmp") as directory:
            result = run_fixture(self.executable, scenario, pathlib.Path(directory))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

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
