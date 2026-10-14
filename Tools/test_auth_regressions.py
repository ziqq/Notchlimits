import pathlib
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
