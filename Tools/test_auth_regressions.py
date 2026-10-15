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
        cls.executable = compile_fixture(cls.build.name, "Authentication", [
            "Model/Models.swift", "Model/Account.swift", "Core/JWT.swift",
            *(["Core/ClaudeStorageLock.swift"] if (SOURCES / "Core/ClaudeStorageLock.swift").exists() else []),
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
