import pathlib
import sys
import tempfile
import unittest

import swift_regression
import test_auth_regressions as authentication


@unittest.skipUnless(sys.platform == "darwin", "Notchlimits runs on macOS")
class AuthenticationLifecycleRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture = tempfile.TemporaryDirectory(prefix="notchlimits-auth-lifecycle-")
        cls.addClassCleanup(fixture.cleanup)
        support = (swift_regression.FIXTURES / "Authentication.swift").read_text().split("\n@main\n", 1)[0]
        scenarios = (swift_regression.FIXTURES / "Lifecycle$Authentication.swift").read_text()
        cls.fixture_path = pathlib.Path(fixture.name) / "Lifecycle$Authentication.swift"
        cls.fixture_path.write_text(support + "\n" + scenarios)
        authentication.AuthenticationRegressions.setUpClass.__func__(cls)

    check_scenario = authentication.AuthenticationRegressions.check_scenario

    def test_native_directory_replaced_during_creation(self):
        self.check_scenario("create")

    def test_switch_file_retarget_early(self):
        self.check_scenario("switch:file:retarget:early")

    def test_switch_file_stable_early(self):
        self.check_scenario("switch:file:stable:early")

    def test_switch_file_retarget_late(self):
        self.check_scenario("switch:file:retarget:late")

    def test_switch_file_stable_late(self):
        self.check_scenario("switch:file:stable:late")

    def test_renew_file_promote(self):
        self.check_scenario("renew:file:promote")

    def test_renew_file_retarget(self):
        self.check_scenario("renew:file:retarget")

    def test_renew_file_stable(self):
        self.check_scenario("renew:file:stable")

    def test_switch_keyring_retarget_early(self):
        self.check_scenario("switch:keyring:retarget:early")

    def test_switch_keyring_stable_early(self):
        self.check_scenario("switch:keyring:stable:early")

    def test_switch_keyring_retarget_late(self):
        self.check_scenario("switch:keyring:retarget:late")

    def test_switch_keyring_stable_late(self):
        self.check_scenario("switch:keyring:stable:late")

    def test_renew_keyring_promote(self):
        self.check_scenario("renew:keyring:promote")

    def test_renew_keyring_retarget(self):
        self.check_scenario("renew:keyring:retarget")

    def test_renew_keyring_stable(self):
        self.check_scenario("renew:keyring:stable")

    def test_switch_auto_file_retarget_early(self):
        self.check_scenario("switch:auto-file:retarget:early")

    def test_switch_auto_file_stable_early(self):
        self.check_scenario("switch:auto-file:stable:early")

    def test_switch_auto_file_retarget_late(self):
        self.check_scenario("switch:auto-file:retarget:late")

    def test_switch_auto_file_stable_late(self):
        self.check_scenario("switch:auto-file:stable:late")

    def test_renew_auto_file_promote(self):
        self.check_scenario("renew:auto-file:promote")

    def test_renew_auto_file_retarget(self):
        self.check_scenario("renew:auto-file:retarget")

    def test_renew_auto_file_stable(self):
        self.check_scenario("renew:auto-file:stable")

    def test_switch_auto_retarget_early(self):
        self.check_scenario("switch:auto:retarget:early")

    def test_switch_auto_stable_early(self):
        self.check_scenario("switch:auto:stable:early")

    def test_switch_auto_retarget_late(self):
        self.check_scenario("switch:auto:retarget:late")

    def test_switch_auto_stable_late(self):
        self.check_scenario("switch:auto:stable:late")

    def test_renew_auto_promote(self):
        self.check_scenario("renew:auto:promote")

    def test_renew_auto_retarget(self):
        self.check_scenario("renew:auto:retarget")

    def test_renew_auto_stable(self):
        self.check_scenario("renew:auto:stable")

    def test_switch_file_replace_early(self):
        self.check_scenario("switch:file:replace:early")

    def test_switch_file_replace_late(self):
        self.check_scenario("switch:file:replace:late")

    def test_renew_file_replace(self):
        self.check_scenario("renew:file:replace")

    def test_switch_file_mode_early(self):
        self.check_scenario("switch:file:mode:early")

    def test_switch_file_mode_late(self):
        self.check_scenario("switch:file:mode:late")

    def test_renew_file_mode(self):
        self.check_scenario("renew:file:mode")

    def test_usage_codex_file_replace(self):
        self.check_scenario("usage:codex:file:replace")

    def test_usage_codex_file_failure(self):
        self.check_scenario("usage:codex:file:failure")

    def test_usage_codex_file_stable(self):
        self.check_scenario("usage:codex:file:stable")

    def test_usage_codex_file_metadata(self):
        self.check_scenario("usage:codex:file:metadata")

    def test_usage_codex_file_renew(self):
        self.check_scenario("usage:codex:file:renew")

    def test_usage_codex_keyring_replace(self):
        self.check_scenario("usage:codex:keyring:replace")

    def test_usage_codex_keyring_failure(self):
        self.check_scenario("usage:codex:keyring:failure")

    def test_usage_codex_keyring_stable(self):
        self.check_scenario("usage:codex:keyring:stable")

    def test_usage_codex_keyring_metadata(self):
        self.check_scenario("usage:codex:keyring:metadata")

    def test_usage_codex_keyring_renew(self):
        self.check_scenario("usage:codex:keyring:renew")

    def test_usage_codex_auto_file_replace(self):
        self.check_scenario("usage:codex:auto-file:replace")

    def test_usage_codex_auto_file_failure(self):
        self.check_scenario("usage:codex:auto-file:failure")

    def test_usage_codex_auto_file_stable(self):
        self.check_scenario("usage:codex:auto-file:stable")

    def test_usage_codex_auto_file_metadata(self):
        self.check_scenario("usage:codex:auto-file:metadata")

    def test_usage_codex_auto_file_renew(self):
        self.check_scenario("usage:codex:auto-file:renew")

    def test_usage_codex_auto_replace(self):
        self.check_scenario("usage:codex:auto:replace")

    def test_usage_codex_auto_failure(self):
        self.check_scenario("usage:codex:auto:failure")

    def test_usage_codex_auto_stable(self):
        self.check_scenario("usage:codex:auto:stable")

    def test_usage_codex_auto_metadata(self):
        self.check_scenario("usage:codex:auto:metadata")

    def test_usage_codex_auto_renew(self):
        self.check_scenario("usage:codex:auto:renew")

    def test_usage_claude_file_replace(self):
        self.check_scenario("usage:claude:file:replace")

    def test_usage_claude_file_failure(self):
        self.check_scenario("usage:claude:file:failure")

    def test_usage_claude_file_stable(self):
        self.check_scenario("usage:claude:file:stable")

    def test_usage_claude_file_metadata(self):
        self.check_scenario("usage:claude:file:metadata")

    def test_usage_claude_file_renew(self):
        self.check_scenario("usage:claude:file:renew")

    def test_usage_claude_keyring_replace(self):
        self.check_scenario("usage:claude:keyring:replace")

    def test_usage_claude_keyring_failure(self):
        self.check_scenario("usage:claude:keyring:failure")

    def test_usage_claude_keyring_stable(self):
        self.check_scenario("usage:claude:keyring:stable")

    def test_usage_claude_keyring_metadata(self):
        self.check_scenario("usage:claude:keyring:metadata")

    def test_usage_claude_keyring_renew(self):
        self.check_scenario("usage:claude:keyring:renew")

    def test_usage_codex_file_reauth(self):
        self.check_scenario("usage:codex:file:reauth")

    def test_usage_codex_keyring_reauth(self):
        self.check_scenario("usage:codex:keyring:reauth")

    def test_usage_codex_auto_file_reauth(self):
        self.check_scenario("usage:codex:auto-file:reauth")

    def test_usage_codex_auto_reauth(self):
        self.check_scenario("usage:codex:auto:reauth")

    def test_usage_claude_file_reauth(self):
        self.check_scenario("usage:claude:file:reauth")

    def test_usage_claude_keyring_reauth(self):
        self.check_scenario("usage:claude:keyring:reauth")

    def test_usage_codex_file_restart_replace(self):
        self.check_scenario("usage:codex:file:restart-replace")

    def test_usage_codex_file_restart_stable(self):
        self.check_scenario("usage:codex:file:restart-stable")

    def test_usage_codex_file_restart_renew(self):
        self.check_scenario("usage:codex:file:restart-renew")

    def test_usage_codex_keyring_restart_replace(self):
        self.check_scenario("usage:codex:keyring:restart-replace")

    def test_usage_codex_keyring_restart_stable(self):
        self.check_scenario("usage:codex:keyring:restart-stable")

    def test_usage_codex_keyring_restart_renew(self):
        self.check_scenario("usage:codex:keyring:restart-renew")

    def test_usage_codex_auto_file_restart_replace(self):
        self.check_scenario("usage:codex:auto-file:restart-replace")

    def test_usage_codex_auto_file_restart_stable(self):
        self.check_scenario("usage:codex:auto-file:restart-stable")

    def test_usage_codex_auto_file_restart_renew(self):
        self.check_scenario("usage:codex:auto-file:restart-renew")

    def test_usage_codex_auto_restart_replace(self):
        self.check_scenario("usage:codex:auto:restart-replace")

    def test_usage_codex_auto_restart_stable(self):
        self.check_scenario("usage:codex:auto:restart-stable")

    def test_usage_codex_auto_restart_renew(self):
        self.check_scenario("usage:codex:auto:restart-renew")

    def test_usage_claude_file_restart_replace(self):
        self.check_scenario("usage:claude:file:restart-replace")

    def test_usage_claude_file_restart_stable(self):
        self.check_scenario("usage:claude:file:restart-stable")

    def test_usage_claude_file_restart_renew(self):
        self.check_scenario("usage:claude:file:restart-renew")

    def test_usage_claude_keyring_restart_replace(self):
        self.check_scenario("usage:claude:keyring:restart-replace")

    def test_usage_claude_keyring_restart_stable(self):
        self.check_scenario("usage:claude:keyring:restart-stable")

    def test_usage_claude_keyring_restart_renew(self):
        self.check_scenario("usage:claude:keyring:restart-renew")
