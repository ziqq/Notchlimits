import pathlib
import sys
import tempfile
import unittest

import swift_regression
import test_auth_regressions as authentication


@unittest.skipUnless(sys.platform == "darwin", "Notchlimits runs on macOS")
class CodexOwnershipRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture = tempfile.TemporaryDirectory(prefix="notchlimits-codex-ownership-")
        cls.addClassCleanup(fixture.cleanup)
        support = (swift_regression.FIXTURES / "Authentication.swift").read_text().split("\n@main\n", 1)[0]
        scenarios = (swift_regression.FIXTURES / "Ownership$Codex.swift").read_text()
        cls.fixture_path = pathlib.Path(fixture.name) / "Ownership$Codex.swift"
        cls.fixture_path.write_text(support + "\n" + scenarios)
        authentication.AuthenticationRegressions.setUpClass.__func__(cls)

    check_scenario = authentication.AuthenticationRegressions.check_scenario

    def test_post_file_promote(self):
        self.check_scenario("post:file:promote")

    def test_post_file_retarget(self):
        self.check_scenario("post:file:retarget")

    def test_post_file_mode(self):
        self.check_scenario("post:file:mode")

    def test_post_file_source_login(self):
        self.check_scenario("post:file:source-login")

    def test_post_file_source_owner(self):
        self.check_scenario("post:file:source-owner")

    def test_post_file_stable(self):
        self.check_scenario("post:file:stable")

    def test_switch_file_retarget(self):
        self.check_scenario("switch:file:retarget")

    def test_switch_file_stable(self):
        self.check_scenario("switch:file:stable")

    def test_storage_file_retarget(self):
        self.check_scenario("storage:file:retarget")

    def test_storage_file_stable(self):
        self.check_scenario("storage:file:stable")

    def test_post_keyring_promote(self):
        self.check_scenario("post:keyring:promote")

    def test_post_keyring_retarget(self):
        self.check_scenario("post:keyring:retarget")

    def test_post_keyring_mode(self):
        self.check_scenario("post:keyring:mode")

    def test_post_keyring_source_login(self):
        self.check_scenario("post:keyring:source-login")

    def test_post_keyring_source_owner(self):
        self.check_scenario("post:keyring:source-owner")

    def test_post_keyring_stable(self):
        self.check_scenario("post:keyring:stable")

    def test_switch_keyring_retarget(self):
        self.check_scenario("switch:keyring:retarget")

    def test_switch_keyring_stable(self):
        self.check_scenario("switch:keyring:stable")

    def test_storage_keyring_retarget(self):
        self.check_scenario("storage:keyring:retarget")

    def test_storage_keyring_stable(self):
        self.check_scenario("storage:keyring:stable")

    def test_post_auto_file_promote(self):
        self.check_scenario("post:auto-file:promote")

    def test_post_auto_file_retarget(self):
        self.check_scenario("post:auto-file:retarget")

    def test_post_auto_file_mode(self):
        self.check_scenario("post:auto-file:mode")

    def test_post_auto_file_source_login(self):
        self.check_scenario("post:auto-file:source-login")

    def test_post_auto_file_source_owner(self):
        self.check_scenario("post:auto-file:source-owner")

    def test_post_auto_file_stable(self):
        self.check_scenario("post:auto-file:stable")

    def test_switch_auto_file_retarget(self):
        self.check_scenario("switch:auto-file:retarget")

    def test_switch_auto_file_stable(self):
        self.check_scenario("switch:auto-file:stable")

    def test_storage_auto_file_retarget(self):
        self.check_scenario("storage:auto-file:retarget")

    def test_storage_auto_file_stable(self):
        self.check_scenario("storage:auto-file:stable")

    def test_post_auto_promote(self):
        self.check_scenario("post:auto:promote")

    def test_post_auto_retarget(self):
        self.check_scenario("post:auto:retarget")

    def test_post_auto_mode(self):
        self.check_scenario("post:auto:mode")

    def test_post_auto_source_login(self):
        self.check_scenario("post:auto:source-login")

    def test_post_auto_source_owner(self):
        self.check_scenario("post:auto:source-owner")

    def test_post_auto_stable(self):
        self.check_scenario("post:auto:stable")

    def test_switch_auto_retarget(self):
        self.check_scenario("switch:auto:retarget")

    def test_switch_auto_stable(self):
        self.check_scenario("switch:auto:stable")

    def test_storage_auto_retarget(self):
        self.check_scenario("storage:auto:retarget")

    def test_storage_auto_stable(self):
        self.check_scenario("storage:auto:stable")

    def test_remove_keyring_root(self):
        self.check_scenario("remove:keyring:root")

    def test_remove_keyring_leaf(self):
        self.check_scenario("remove:keyring:leaf")

    def test_remove_keyring_stable(self):
        self.check_scenario("remove:keyring:stable")

    def test_remove_keyring_root_rollback(self):
        self.check_scenario("remove:keyring:root-rollback")

    def test_remove_keyring_move_root(self):
        self.check_scenario("remove:keyring:move-root")

    def test_remove_keyring_move_owner(self):
        self.check_scenario("remove:keyring:move-owner")

    def test_remove_auto_root(self):
        self.check_scenario("remove:auto:root")

    def test_remove_auto_leaf(self):
        self.check_scenario("remove:auto:leaf")

    def test_remove_auto_stable(self):
        self.check_scenario("remove:auto:stable")

    def test_remove_auto_root_rollback(self):
        self.check_scenario("remove:auto:root-rollback")

    def test_remove_auto_move_root(self):
        self.check_scenario("remove:auto:move-root")

    def test_remove_auto_move_owner(self):
        self.check_scenario("remove:auto:move-owner")
