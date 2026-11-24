from itertools import product
import pathlib
import sys
import tempfile
import unittest

import swift_regression
import test_auth_regressions as authentication


@unittest.skipUnless(sys.platform == "darwin", "Notchlimits runs on macOS")
class CodexRestorationRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture = tempfile.TemporaryDirectory(prefix="notchlimits-codex-restoration-")
        cls.addClassCleanup(fixture.cleanup)
        support = (swift_regression.FIXTURES / "Authentication.swift").read_text().split("\n@main\n", 1)[0]
        boundaries = {
            "guard let data = Fixture.codexKeychain[key] else { return errSecItemNotFound }":
                """if RestorationSignals.keychainDenied || key == RestorationSignals.unavailableKey { return errSecInteractionNotAllowed }
        guard let data = Fixture.codexKeychain[key] else { return errSecItemNotFound }""",
            "func SecItemDelete(_ query: CFDictionary) -> OSStatus {":
                """func SecItemDelete(_ query: CFDictionary) -> OSStatus {
    if (query as NSDictionary)[kSecAttrService as String] as? String == "Codex Auth",
       let key = (query as NSDictionary)[kSecAttrAccount as String] as? String {
        RestorationSignals.beforeDelete?(key)
    }""",
            "let exists = super.fileExists(atPath: configPath(path))":
                "let exists = super.fileExists(atPath: configPath(path))\n        RestorationSignals.io?(path)",
            "try super.removeItem(at: url)":
                "try RestorationSignals.remove?(url)\n        try super.removeItem(at: url)\n        RestorationSignals.afterFileRemoval?(url)",
            "if Fixture.failCodexFileWrite && URL(fileURLWithPath: path).lastPathComponent.hasPrefix":
                "RestorationSignals.attributes?(path)\n        if Fixture.failCodexFileWrite && URL(fileURLWithPath: path).lastPathComponent.hasPrefix",
        }
        deletion = "        Fixture.codexKeychain[key] = nil\n        return errSecSuccess"
        boundaries[deletion] = deletion.replace(
            "return errSecSuccess", "RestorationSignals.afterDelete?(key)\n        return errSecSuccess",
        )
        keychain_add = """func SecItemAdd(_ attributes: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {
    if (attributes as NSDictionary)[kSecAttrService as String] as? String == "Codex Auth" {
        let key = (attributes as NSDictionary)[kSecAttrAccount as String] as! String
        guard !Fixture.denyCodexWrite && key != Fixture.denyCodexWriteAccount else { return errSecAuthFailed }"""
        boundaries[keychain_add] = (
            keychain_add + "\n        guard Fixture.codexKeychain[key] == nil else { return errSecDuplicateItem }"
        )
        move = "            Fixture.codexKeychain[destination] = Fixture.codexKeychain.removeValue(forKey: key)"
        boundaries[move] = "            RestorationSignals.beforeMove?(key, destination)\n" + move + "\n            RestorationSignals.afterMove?(key, destination)"
        database = "        try Data().write(to: path, options: .withoutOverwriting)\n        codexDatabase = path"
        boundaries[database] = ("        if !Foundation.FileManager.default.fileExists(atPath: path.path) {\n"
                                "            try Data().write(to: path, options: .withoutOverwriting)\n"
                                "        }\n        codexDatabase = path")
        for before, after in boundaries.items():
            assert support.count(before) == 1, before
            support = support.replace(before, after)
        assignment = "Fixture.codexKeychain[key] = (attributes as NSDictionary)[kSecValueData as String] as? Data"
        assert support.count(assignment) == 2
        support = support.replace(assignment, "RestorationSignals.beforeWrite?(key)\n        " + assignment + "\n        RestorationSignals.didWrite(key)")
        cls.fixture_path = pathlib.Path(fixture.name) / "Restoration$Codex.swift"
        cls.fixture_path.write_text(support + "\n" + (swift_regression.FIXTURES / "Restoration$Codex.swift").read_text())
        authentication.AuthenticationRegressions.setUpClass.__func__(cls)

    check_scenario = authentication.AuthenticationRegressions.check_scenario


def scenario_test(scenario):
    def test(self):
        self.check_scenario(scenario)
    return test


modes = ("file", "keyring", "auto-file", "auto")
changes = ("login", "owner", "identical", "mode", "retarget", "stable", "metadata")
scenarios = []
for mode in modes:
    for phase in ("config", "delete"):
        for change in changes:
            scenarios.append(f"cleanup:{mode}:{phase}:{change}")
    for change in (*changes, "rotation"):
        scenarios.append(f"rollback:{mode}:operation:{change}")
for change in (*changes, "rotation"):
    scenarios.append(f"rollback:file:prepare:{change}")
for mode in modes:
    for change in ("login", "stable", "metadata"):
        scenarios.append(f"compensate:{mode}:before:{change}")
for change in ("login", "stable", "metadata"):
    scenarios.append(f"compensate:file:prepare:{change}")
for direction in ("select", "return"):
    for change in ("foreign", "stable"):
        scenarios.append(f"routing:{direction}:{change}")
scenarios.extend(("compensation-logins:both", "compensation-logins:backup-only"))
scenarios.extend(("compensation-logins:both:file", "compensation-logins:backup-only:file"))
for operation in ("restore", "remove"):
    for mode in ("keyring", "auto"):
        for phase in ("stable", "empty", "unlink", "denied", "foreign", "foreign-denied"):
            scenarios.append(f"migration:{operation}:{mode}:{phase}")
    scenarios.extend((f"migration:{operation}:file:stable", f"migration:{operation}:auto:config-only"))
scenarios.append("compensation-logins:both:denied")
scenarios.append("compensation-logins:both:locked")
for outcome in ("unchanged", "logged-out", "cleanup-refused", "aliased-root", "replaced", "replaced-alias",
                "replaced-managed-same", "replaced-managed-distinct", "relocated-owner", "relocated-managed",
                "relocated-primary", "relocated-primary-removed-alias", "relocated-primary-removed-alias-switch",
                "relocated-primary-removed-alias-self", "relocated-primary-removed-alias-during-read",
                "relocated-primary-removed-alias-during-delete", "relocated-primary-removed-alias-during-delete-reoccupied",
                "relocated-primary-removed-alias-during-delete-reoccupied-same",
                "relocated-primary-removed-alias-during-delete-final-read",
                "relocated-primary-removed-alias-during-delete-reoccupied-same-denied-until-retry",
                "relocated-primary-removed-alias-during-delete-denied-until-retry",
                "relocated-primary-removed-alias-during-delete-replacement-at-delete",
                "relocated-primary-removed-alias-unrelated-removal",
                "non-directory"):
    scenarios.append(f"unreadable-original:{outcome}")
assert len(scenarios) == len(set(scenarios)) == 173
for scenario in scenarios:
    setattr(CodexRestorationRegressions, "test_" + scenario.replace(":", "_").replace("-", "_"), scenario_test(scenario))


def restart_test(cut, *conditions):
    def test(self):
        with tempfile.TemporaryDirectory(prefix="notchlimits-codex-restart-", dir="/private/tmp") as directory:
            root = pathlib.Path(directory)
            scenario = "unreadable-original:relocated-primary-removed-alias-during-delete-restart-" + cut
            before = swift_regression.run_fixture(self.executable, scenario, root)
            self.assertEqual(before.returncode, 86, before.stdout + before.stderr)
            faults = (*conditions, "denied") if "-denied-" in cut else conditions
            after = swift_regression.run_fixture(self.executable, ":".join(("restart-child", *faults)), root)
            self.assertEqual(after.returncode, 0, after.stdout + after.stderr)
            if "cycle" in conditions:
                reopened = swift_regression.run_fixture(self.executable, "restart-after-cycle", root)
                self.assertEqual(reopened.returncode, 0, reopened.stdout + reopened.stderr)
    return test


restart_cases = list(product(("admission", "move", "delete"), ("unchanged", "rewrite", "replace"),
                             ("available", "denied"), ("stable", "retarget")))
for keychain in ("available", "denied"):
    restart_cases += [("move", "rewrite", keychain, "stage"), ("move", "rewrite", keychain, "source"),
                      ("move", "replace", keychain, "source"), ("delete", "rewrite", keychain, "source")]
for case in restart_cases:
    cut = "-".join(case)
    setattr(CodexRestorationRegressions, "test_restart_" + cut.replace("-", "_"), restart_test(cut))


interruptions = (("ephemeral",), ("file",), ("directory-denied",),
                 ("ephemeral", "directory-denied", "denied"), ("file", "directory-denied", "denied"))
restart_recovery_cases = [
    (f"{cut}-replace-available-{route}", faults)
    for cut, route, faults in product(("admission", "move", "delete"), ("stable", "retarget"), interruptions)
]
restart_recovery_cases += [
    ("admission-unchanged-available-stable", (condition,))
    for condition in ("empty-stage", "empty-config-removed", "keep-stage", "symlink-config")
]
restart_recovery_cases += [
    (f"{cut}-unchanged-available-retarget", faults)
    for cut, faults in product(("admission", "move", "delete"),
                               (("parent-replaced",), ("parent-replaced", "ephemeral", "denied")))
]
for cut, faults in restart_recovery_cases:
    name = "_".join((cut, *faults)).replace("-", "_")
    setattr(CodexRestorationRegressions, "test_replay_" + name, restart_test(cut, *faults))


mixed_store_cases = [
    (f"{phase}-replace-fileowner-available-retarget", faults)
    for phase, faults in product(("admission", "delete"),
                                 (("file-owner-mixed",), ("file-owner-auto", "deny-first")))
]
mixed_store_cases += [
    (f"{phase}-rewrite-available-stable", faults)
    for phase, faults in product(("admission", "move", "delete"),
                                 (("active-file-readd",), ("active-file-readd", "deny-first"),
                                  ("active-file-readd", "inactive-denied")))
]
mixed_store_cases += [
    ("delete-replace-fileowner-available-retarget", ("file-owner-distinct",)),
    ("delete-replace-fileowner-available-retarget", ("file-owner-empty", "deny-first")),
    ("delete-rewrite-available-stable", ("active-file-readd-empty-keychain", "deny-first")),
    ("admission-rewrite-available-stable", ("active-file-readd", "remove-file-login")),
    ("delete-replace-fileowner-available-retarget", ("file-owner-distinct", "remove-keyring-login")),
]
for cut, faults in mixed_store_cases:
    name = "_".join((cut, *faults)).replace("-", "_")
    setattr(CodexRestorationRegressions, "test_mixed_store_" + name, restart_test(cut, *faults))


mixed_store_lifecycle_cases = (
    ("delete-replace-fileowner-available-retarget", "audit-renew"),
    ("delete-replace-fileowner-available-retarget", "audit-renew-auto"),
    ("delete-replace-fileowner-available-retarget", "audit-renew-same"),
    ("delete-replace-fileowner-managedowner-available-retarget", "audit-managed-remove"),
    ("delete-replace-fileowner-managedowner-available-retarget", "audit-managed-remove-denied"),
    ("delete-replace-fileowner-managedowner-available-retarget", "audit-managed-remove-relogin"),
    ("delete-replace-fileowner-available-retarget", "audit-private-remove"),
    ("delete-replace-fileowner-available-stable", "audit-switch"),
    ("admission-rewrite-available-stable", "audit-stale-switch"),
    ("admission-rewrite-available-stable", "audit-stale-remove"),
    ("admission-rewrite-available-stable", "audit-stable-switch"),
)
for cut, condition in mixed_store_lifecycle_cases:
    name = condition.removeprefix("audit-").replace("-", "_")
    setattr(CodexRestorationRegressions, "test_mixed_store_lifecycle_" + name, restart_test(cut, condition))
for mode in ("audit-renew", "audit-renew-auto"):
    name = mode.removeprefix("audit-").replace("-", "_")
    setattr(CodexRestorationRegressions, "test_mixed_store_lifecycle_cycle_" + name,
            restart_test("delete-replace-fileowner-available-retarget", mode, "cycle"))
CodexRestorationRegressions.test_mixed_store_lifecycle_stale_switch_after_file_cycle = restart_test(
    "admission-rewrite-available-stable", "audit-stale-switch", "file-cycle")


def mixed_backup_cycle(mode):
    def test(self):
        with tempfile.TemporaryDirectory(prefix="notchlimits-codex-backup-cycle-", dir="/private/tmp") as directory:
            root = pathlib.Path(directory)
            for scenario in (f"backup-cycle:{mode}", "restart-after-cycle"):
                result = swift_regression.run_fixture(self.executable, scenario, root)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
    return test


for mode in ("file", "keyring", "auto"):
    setattr(CodexRestorationRegressions, "test_mixed_store_lifecycle_backup_cycle_" + mode, mixed_backup_cycle(mode))


def interrupted_primary_return(mode, cut, *conditions):
    def test(self):
        with tempfile.TemporaryDirectory(prefix="notchlimits-audit-backup-crash-", dir="/private/tmp") as directory:
            root = pathlib.Path(directory)
            before = swift_regression.run_fixture(self.executable, f"audit-backup:{mode}:{cut}", root)
            self.assertEqual(before.returncode, 86, before.stdout + before.stderr)
            after = swift_regression.run_fixture(self.executable, ":".join(("audit-backup-restart", *conditions)), root)
            self.assertEqual(after.returncode, 0, after.stdout + after.stderr)
    return test

for mode in ("auto", "keyring"):
    for cut, conditions in (
        ("cut-after-delete", ()),
        ("cut-after-delete", ("retry",)),
        ("cut-after-delete", ("denied", "native-relogin")),
        ("cut-before-delete", ("before-delete", "denied")),
        ("cut-during-removal", ("removal", "denied")),
    ):
        name = "_".join((mode, cut, *conditions)).replace("-", "_")
        setattr(CodexRestorationRegressions, "test_audit_backup_" + name, interrupted_primary_return(mode, cut, *conditions))
CodexRestorationRegressions.test_audit_backup_before_publication = interrupted_primary_return(
    "keyring", "cut-before-publication", "before-publication")
CodexRestorationRegressions.test_audit_backup_after_publication = interrupted_primary_return(
    "keyring", "cut-after-publication", "before-delete", "denied")
CodexRestorationRegressions.test_audit_backup_file_cut_after_delete = interrupted_primary_return(
    "file", "cut-after-delete", "denied")
CodexRestorationRegressions.test_audit_backup_parent_replaced = interrupted_primary_return(
    "keyring", "cut-after-delete", "parent-replaced")
CodexRestorationRegressions.test_audit_backup_primary_signed_out = scenario_test("audit-backup:keyring:signed-out-primary")
for action in ("switch", "remove"):
    for condition in ("denied", "available", "opaque-replaced", "opaque-unchanged"):
        name = condition.replace("-", "_")
        setattr(CodexRestorationRegressions, f"test_audit_stale_{action}_{name}", scenario_test(f"audit-stale-keychain:{action}:{condition}"))

CodexRestorationRegressions.test_audit_rollback_absent_native = scenario_test("audit-rollback:absent")
CodexRestorationRegressions.test_audit_rollback_present_native = scenario_test("audit-rollback:present")

def audit_combined(mode, cut, *conditions):
    def test(self):
        with tempfile.TemporaryDirectory(prefix="notchlimits-audit-combined-", dir="/private/tmp") as directory:
            root = pathlib.Path(directory)
            before = swift_regression.run_fixture(self.executable, f"audit-backup:{mode}:{cut}", root)
            self.assertEqual(before.returncode, 86, before.stdout + before.stderr)
            after = swift_regression.run_fixture(self.executable, ":".join(("audit-combined", *conditions)), root)
            self.assertEqual(after.returncode, 0, after.stdout + after.stderr)
    return test

combined = (
    ("keyring", "cut-rollback-native", "denied"),
    ("auto", "cut-rollback-native", "denied"),
    ("keyring", "cut-rollback-removal", "denied"),
    ("keyring", "cut-rollback-native", "denied", "relogin"),
    ("keyring", "cut-before-publication", "denied", "ephemeral"),
    ("keyring", "cut-before-publication", "denied", "file-mode"),
    ("keyring", "cut-before-publication", "denied"),
    ("keyring", "cut-before-delete", "denied", "stash-relogin"),
    ("auto", "cut-before-delete", "denied", "stash-relogin"),
    ("keyring", "cut-after-publication", "denied", "rotation"),
    ("keyring", "cut-before-delete", "denied", "rotation"),
    ("keyring", "cut-before-delete", "denied", "rotation", "shared-copy"),
    ("keyring", "cut-before-delete", "denied", "access-only"),
    ("keyring", "cut-before-delete", "denied", "duplicate-file"),
    ("keyring", "cut-before-delete", "denied", "same-workspace"),
    ("keyring", "cut-before-delete", "usage"),
)
for mode, cut, *conditions in combined:
    name = "_".join((mode, cut, *conditions)).replace("-", "_")
    setattr(CodexRestorationRegressions, "test_combined_" + name, audit_combined(mode, cut, *conditions))
