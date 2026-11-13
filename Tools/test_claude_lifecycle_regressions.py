import pathlib
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
                "if ClaudeLifecycleSignals.selectionRenameRefused(String(cString: from)) { return -1 }",
        }
        for anchor, body in hooks.items():
            assert support.count(anchor) == 1
            support = support.replace(anchor, anchor + "\n    " + body)
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
