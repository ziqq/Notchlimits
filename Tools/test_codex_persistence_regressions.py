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

    def test_codex_copy_bootstrap_keyring(self):
        self.check_scenario("codex-copy-bootstrap-keyring")

    def test_codex_copy_bootstrap_auto(self):
        self.check_scenario("codex-copy-bootstrap-auto")

    def test_codex_copy_bootstrap_keyring_new_login(self):
        self.check_scenario("codex-copy-bootstrap-keyring-new-login")

    def test_codex_copy_bootstrap_auto_new_login(self):
        self.check_scenario("codex-copy-bootstrap-auto-new-login")

    def test_codex_copy_bootstrap_keyring_retarget(self):
        self.check_scenario("codex-copy-bootstrap-keyring-retarget")

    def test_codex_copy_bootstrap_auto_retarget(self):
        self.check_scenario("codex-copy-bootstrap-auto-retarget")

    def test_codex_copy_bootstrap_file(self):
        self.check_scenario("codex-copy-bootstrap-file")

    def test_codex_copy_bootstrap_keyring_readded(self):
        self.check_scenario("codex-copy-bootstrap-keyring-readded")

    def test_codex_copy_bootstrap_auto_readded(self):
        self.check_scenario("codex-copy-bootstrap-auto-readded")

    def test_codex_copy_bootstrap_keyring_pending(self):
        self.check_scenario("codex-copy-bootstrap-keyring-pending")

    def test_codex_copy_bootstrap_auto_pending(self):
        self.check_scenario("codex-copy-bootstrap-auto-pending")

    def test_codex_copy_native_bootstrap_keyring(self):
        self.check_scenario("codex-copy-native-bootstrap-keyring")

    def test_codex_copy_native_bootstrap_auto(self):
        self.check_scenario("codex-copy-native-bootstrap-auto")

    def test_codex_copy_primary_bootstrap_keyring(self):
        self.check_scenario("codex-copy-primary-bootstrap-keyring")

    def test_codex_copy_primary_bootstrap_auto(self):
        self.check_scenario("codex-copy-primary-bootstrap-auto")

    def test_codex_copy_source_replaced_keyring(self):
        self.check_scenario("codex-copy-source-replaced-keyring")

    def test_codex_copy_source_replaced_auto(self):
        self.check_scenario("codex-copy-source-replaced-auto")

    def test_codex_copy_source_replaced_keyring_denied(self):
        self.check_scenario("codex-copy-source-replaced-keyring-denied")

    def test_codex_copy_source_replaced_auto_denied(self):
        self.check_scenario("codex-copy-source-replaced-auto-denied")

    def test_codex_native_grant_fresh_replaced_file(self):
        self.check_scenario("codex-native-grant-fresh-replaced-file")

    def test_codex_native_grant_fresh_replaced_auto_file(self):
        self.check_scenario("codex-native-grant-fresh-replaced-auto-file")

    def test_codex_native_grant_fresh_stable_file(self):
        self.check_scenario("codex-native-grant-fresh-stable-file")

    def test_codex_native_grant_fresh_replaced_keyring(self):
        self.check_scenario("codex-native-grant-fresh-replaced-keyring")

    def test_codex_native_grant_fresh_independent_file(self):
        self.check_scenario("codex-native-grant-fresh-independent-file")

    def test_codex_native_grant_fresh_independent_auto_file(self):
        self.check_scenario("codex-native-grant-fresh-independent-auto-file")

    def test_codex_native_grant_fresh_late_routing_file(self):
        self.check_scenario("codex-native-grant-fresh-late-routing-file")

    def test_codex_native_grant_fresh_late_routing_keyring(self):
        self.check_scenario("codex-native-grant-fresh-late-routing-keyring")

    def test_codex_native_grant_fresh_late_same_routing_file(self):
        self.check_scenario("codex-native-grant-fresh-late-same-routing-file")

    def test_codex_native_grant_fresh_late_same_routing_keyring(self):
        self.check_scenario("codex-native-grant-fresh-late-same-routing-keyring")

    def test_codex_native_grant_expired_replaced_file(self):
        self.check_scenario("codex-native-grant-expired-replaced-file")

    def test_codex_native_grant_expired_replaced_auto_file(self):
        self.check_scenario("codex-native-grant-expired-replaced-auto-file")

    def test_codex_native_grant_expired_stable_file(self):
        self.check_scenario("codex-native-grant-expired-stable-file")

    def test_codex_native_grant_expired_replaced_keyring(self):
        self.check_scenario("codex-native-grant-expired-replaced-keyring")

    def test_codex_native_grant_expired_independent_file(self):
        self.check_scenario("codex-native-grant-expired-independent-file")

    def test_codex_native_grant_expired_independent_auto_file(self):
        self.check_scenario("codex-native-grant-expired-independent-auto-file")

    def test_codex_native_grant_expired_late_routing_file(self):
        self.check_scenario("codex-native-grant-expired-late-routing-file")

    def test_codex_native_grant_expired_late_routing_keyring(self):
        self.check_scenario("codex-native-grant-expired-late-routing-keyring")

    def test_codex_native_grant_expired_late_same_routing_file(self):
        self.check_scenario("codex-native-grant-expired-late-same-routing-file")

    def test_codex_native_grant_expired_late_same_routing_keyring(self):
        self.check_scenario("codex-native-grant-expired-late-same-routing-keyring")

    def test_codex_native_grant_restart_file_unobserved(self):
        self.check_scenario("codex-native-grant-restart-file-unobserved")

    def test_codex_native_grant_restart_file_retired(self):
        self.check_scenario("codex-native-grant-restart-file-retired")

    def test_codex_native_grant_observe_file(self):
        self.check_scenario("codex-native-grant-observe-file")

    def test_codex_native_grant_selected_file(self):
        self.check_scenario("codex-native-grant-selected-file")

    def test_codex_native_grant_sync_file(self):
        self.check_scenario("codex-native-grant-sync-file")

    def test_codex_native_grant_handoff_file(self):
        self.check_scenario("codex-native-grant-handoff-file")

    def test_codex_native_grant_rollback_file(self):
        self.check_scenario("codex-native-grant-rollback-file")

    def test_codex_native_grant_restart_keyring_unobserved(self):
        self.check_scenario("codex-native-grant-restart-keyring-unobserved")

    def test_codex_native_grant_restart_keyring_retired(self):
        self.check_scenario("codex-native-grant-restart-keyring-retired")

    def test_codex_native_grant_observe_keyring(self):
        self.check_scenario("codex-native-grant-observe-keyring")

    def test_codex_native_grant_selected_keyring(self):
        self.check_scenario("codex-native-grant-selected-keyring")

    def test_codex_native_grant_sync_keyring(self):
        self.check_scenario("codex-native-grant-sync-keyring")

    def test_codex_native_grant_handoff_keyring(self):
        self.check_scenario("codex-native-grant-handoff-keyring")

    def test_codex_native_grant_rollback_keyring(self):
        self.check_scenario("codex-native-grant-rollback-keyring")

    def test_codex_native_grant_path_retarget(self):
        self.check_scenario("codex-native-grant-path-retarget")

    def test_codex_native_grant_path_stable(self):
        self.check_scenario("codex-native-grant-path-stable")

    def test_codex_native_grant_alias_file(self):
        self.check_scenario("codex-native-grant-alias-file")

    def test_codex_native_grant_alias_keyring(self):
        self.check_scenario("codex-native-grant-alias-keyring")
