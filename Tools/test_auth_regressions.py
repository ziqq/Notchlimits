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
