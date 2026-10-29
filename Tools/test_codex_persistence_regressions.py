import pathlib
import sys
import tempfile
import unittest

import swift_regression
import test_auth_regressions as authentication


@unittest.skipUnless(sys.platform == "darwin", "Notchlimits runs on macOS")
class CodexPersistenceRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture = tempfile.TemporaryDirectory(prefix="notchlimits-codex-persistence-")
        cls.addClassCleanup(fixture.cleanup)
        # Reuse exactly the same OS boundaries as the existing lifecycle suite.
        # Keep new process/error scenarios out of its large Swift entry point.
        support = (swift_regression.FIXTURES / "Authentication.swift").read_text().split("\n@main\n", 1)[0]
        scenarios = (swift_regression.FIXTURES / "Persistence$Codex.swift").read_text()
        cls.fixture_path = pathlib.Path(fixture.name) / "Persistence$Codex.swift"
        cls.fixture_path.write_text(support + "\n" + scenarios)
        authentication.AuthenticationRegressions.setUpClass.__func__(cls)

    check_scenario = authentication.AuthenticationRegressions.check_scenario

    def test_codex_source_parent_file(self):
        self.check_scenario("codex-source-parent-file")

    def test_codex_source_self_file(self):
        self.check_scenario("codex-source-self-file")

    def test_codex_source_parent_keyring(self):
        self.check_scenario("codex-source-parent-keyring")

    def test_codex_source_parent_auto_file(self):
        self.check_scenario("codex-source-parent-auto-file")

    def test_codex_source_parent_auto_keyring(self):
        self.check_scenario("codex-source-parent-auto-keyring")

    def test_codex_source_self_no_execute(self):
        self.check_scenario("codex-source-self-no-execute")

    def test_codex_copy_no_execute_file(self):
        self.check_scenario("codex-copy-no-execute-file")

    def test_codex_copy_no_access_file(self):
        self.check_scenario("codex-copy-no-access-file")

    def test_codex_copy_no_execute_keyring(self):
        self.check_scenario("codex-copy-no-execute-keyring")

    def test_codex_copy_no_execute_auto_file(self):
        self.check_scenario("codex-copy-no-execute-auto-file")

    def test_codex_copy_no_execute_auto_keyring(self):
        self.check_scenario("codex-copy-no-execute-auto-keyring")

    def test_codex_source_removed_file(self):
        self.check_scenario("codex-source-removed-file")

    def test_codex_source_replaced_keyring_same(self):
        self.check_scenario("codex-source-replaced-keyring-same")

    def test_codex_source_replaced_keyring_new(self):
        self.check_scenario("codex-source-replaced-keyring-new")

    def test_codex_quarantine_lost_file(self):
        self.check_scenario("codex-quarantine-lost-file")

    def test_codex_quarantine_lost_keyring(self):
        self.check_scenario("codex-quarantine-lost-keyring")

    def test_codex_quarantine_lost_auto(self):
        self.check_scenario("codex-quarantine-lost-auto")

    def test_codex_quarantine_temporary_file(self):
        self.check_scenario("codex-quarantine-temporary-file")

    def test_codex_quarantine_temporary_auto(self):
        self.check_scenario("codex-quarantine-temporary-auto")

    def test_codex_quarantine_new_login(self):
        self.check_scenario("codex-quarantine-new-login")

    def test_codex_quarantine_rejected_file(self):
        self.check_scenario("codex-quarantine-rejected-file")

    def test_codex_quarantine_rejected_keyring(self):
        self.check_scenario("codex-quarantine-rejected-keyring")

    def test_codex_quarantine_unreadable_file(self):
        self.check_scenario("codex-quarantine-unreadable-file")

    def test_codex_quarantine_unreadable_auto(self):
        self.check_scenario("codex-quarantine-unreadable-auto")

    def test_codex_quarantine_fresh_access(self):
        self.check_scenario("codex-quarantine-fresh-access")

    def test_codex_quarantine_metadata(self):
        self.check_scenario("codex-quarantine-metadata")

    def test_codex_quarantine_rotated_old_copy(self):
        self.check_scenario("codex-quarantine-rotated-old-copy")

    def test_codex_quarantine_rotated_current(self):
        self.check_scenario("codex-quarantine-rotated-current")

    def test_codex_quarantine_nonrotating(self):
        self.check_scenario("codex-quarantine-nonrotating")

    def test_codex_quarantine_write_refused(self):
        self.check_scenario("codex-quarantine-write-refused")

    def test_codex_quarantine_flush_temporary(self):
        self.check_scenario("codex-quarantine-flush-temporary")

    def test_codex_quarantine_flush_success(self):
        self.check_scenario("codex-quarantine-flush-success")

    def test_codex_auth_file_missing(self):
        self.check_scenario("codex-auth-file-missing")

    def test_codex_file_rollback_pending(self):
        self.check_scenario("codex-file-rollback-pending")

    def test_codex_file_rollback_inflight(self):
        self.check_scenario("codex-file-rollback-inflight")
