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
                """if RestorationSignals.keychainDenied || key == RestorationSignals.unavailableKey
            || RestorationSignals.denyRead?(key) == true { return errSecInteractionNotAllowed }
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
        boundaries[move] = (
            "            RestorationSignals.beforeMove?(key, destination)\n" + move
            + "\n            if RestorationSignals.followsDeleteDenial && Fixture.denyCodexDeleteAccount == key {\n"
            + "                Fixture.denyCodexDeleteAccount = destination\n            }\n"
            + "            RestorationSignals.afterMove?(key, destination)"
        )
        for before, after in boundaries.items():
            assert support.count(before) == 1, before
            support = support.replace(before, after)
        assignment = "Fixture.codexKeychain[key] = (attributes as NSDictionary)[kSecValueData as String] as? Data"
        assert support.count(assignment) == 2
        support = support.replace(assignment, "RestorationSignals.beforeWrite?(key)\n        " + assignment + "\n        RestorationSignals.didWrite(key)")
        cls.fixture_path = pathlib.Path(fixture.name) / "Restoration$Codex.swift"
        cls.fixture_path.write_text(swift_regression.instrument_codex_file_transfer(support) + "\n"
                                    + (swift_regression.FIXTURES / "Restoration$Codex.swift").read_text())
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
    ("keyring", "cut-rollback-native", "denied", "selected-rotation"),
    ("keyring", "cut-rollback-removal", "denied", "selected-rotation"),
    ("keyring", "cut-before-publication", "denied", "selected-rotation"),
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

def extra_audit_restart(mode, denial, operation):
    def test(self):
        with tempfile.TemporaryDirectory(prefix="notchlimits-extra-audit-", dir="/private/tmp") as directory:
            root = pathlib.Path(directory)
            before = swift_regression.run_fixture(self.executable, f"audit-backup:{mode}:cut-before-delete", root)
            self.assertEqual(before.returncode, 86, before.stdout + before.stderr)
            after = swift_regression.run_fixture(self.executable, f"extra-audit-restart:{denial}:{operation}", root)
            self.assertEqual(after.returncode, 0, after.stdout + after.stderr)
    return test

for mode, change in product(("file", "keyring"), ("rotation", "same-workspace", "different-workspace")):
    name = "_".join((mode, change)).replace("-", "_")
    setattr(CodexRestorationRegressions, "test_extra_copyback_" + name,
            scenario_test(f"extra-audit-copyback:{mode}:{change}"))

for denial, operation in product(("denied", "available"), ("usage", "switch")):
    setattr(CodexRestorationRegressions, "test_extra_restart_" + denial + "_" + operation,
            extra_audit_restart("keyring", denial, operation))

for operation in ("retry", "relogin", "remove", "remove-alternate"):
    setattr(CodexRestorationRegressions, "test_extra_restart_denied_" + operation.replace("-", "_"),
            extra_audit_restart("keyring", "denied", operation))

for operation in ("retry", "relogin"):
    setattr(CodexRestorationRegressions, "test_extra_restart_auto_denied_" + operation,
            extra_audit_restart("auto", "denied", operation))

for mode in ("file", "keyring"):
    setattr(CodexRestorationRegressions, "test_extra_legacy_login_" + mode,
            scenario_test("extra-audit-legacy-login:" + mode))

def extra_audit_failed_switch(self):
    with tempfile.TemporaryDirectory(prefix="notchlimits-codex-failed-switch-", dir="/private/tmp") as directory:
        root = pathlib.Path(directory)
        for scenario in ("extra-audit-copyback:keyring:failed-switch", "restart-after-cycle"):
            result = swift_regression.run_fixture(self.executable, scenario, root)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

CodexRestorationRegressions.test_extra_relogin_retry_survives_restart = extra_audit_failed_switch

def extra_audit_copy_restart(mode, change):
    def test(self):
        with tempfile.TemporaryDirectory(prefix="notchlimits-extra-copy-audit-", dir="/private/tmp") as directory:
            root = pathlib.Path(directory)
            before = swift_regression.run_fixture(self.executable, f"extra-audit-copy-seed:{mode}:{change}", root)
            self.assertEqual(before.returncode, 0, before.stdout + before.stderr)
            after = swift_regression.run_fixture(self.executable, "extra-audit-copy-restart", root)
            self.assertEqual(after.returncode, 0, after.stdout + after.stderr)
    return test

for mode, change in product(("file", "keyring"), ("rotation", "same-workspace")):
    name = "_".join((mode, change)).replace("-", "_")
    setattr(CodexRestorationRegressions, "test_extra_primary_copy_" + name, extra_audit_copy_restart(mode, change))

for mode, operation in product(("keyring", "auto"), ("rotate-primary", "relogin-primary", "access-only-primary")):
    name = "test_extra_restart_" + mode + "_deferred_" + operation.replace("-", "_")
    setattr(CodexRestorationRegressions, name, extra_audit_restart(mode, "denied", operation))

def retained_return(mode, operation):
    def test(self):
        with tempfile.TemporaryDirectory(prefix="notchlimits-retained-audit-", dir="/private/tmp") as directory:
            root = pathlib.Path(directory)
            before = swift_regression.run_fixture(self.executable, f"audit-backup:{mode}:cut-before-delete", root)
            self.assertEqual(before.returncode, 86, before.stdout + before.stderr)
            after = swift_regression.run_fixture(self.executable, f"retained-audit-return:{operation}", root)
            print(after.stdout.strip(), flush=True)
            self.assertEqual(after.returncode, 0, after.stdout + after.stderr)
    return test

for mode, operation in product(("file", "keyring"), ("single", "duplicate")):
    setattr(CodexRestorationRegressions, f"test_retained_audit_legacy_{mode}_{operation}",
            scenario_test(f"retained-audit-legacy-copies:{mode}:{operation}"))
for mode, operation in product(("keyring", "auto"), (
    "delete-race", "retry-delete-race", "read-before-delete", "auto-fallback", "file-fallback",
    "rotate-then-relogin", "rotate-then-relogin-denied", "relogin-without-rotation",
)):
    setattr(CodexRestorationRegressions, f"test_retained_audit_{mode}_" + operation.replace("-", "_"),
            retained_return(mode, operation))

for mode, operation in product(("keyring", "auto"), ("restore-directory", "stable-directory")):
    setattr(CodexRestorationRegressions, f"test_retained_audit_{mode}_" + operation.replace("-", "_"),
            retained_return(mode, operation))

def retained_stage_restart(mode, occupied):
    def test(self):
        with tempfile.TemporaryDirectory(prefix="notchlimits-returned-stage-", dir="/private/tmp") as directory:
            root = pathlib.Path(directory)
            cut = swift_regression.run_fixture(self.executable, f"audit-backup:{mode}:cut-before-delete", root)
            self.assertEqual(cut.returncode, 86, cut.stdout + cut.stderr)
            phase = "stage-crash-occupied" if occupied else "stage-crash"
            second_cut = swift_regression.run_fixture(self.executable, f"retained-audit-return:{phase}", root)
            self.assertEqual(second_cut.returncode, 86, second_cut.stdout + second_cut.stderr)
            replay = swift_regression.run_fixture(self.executable, "retained-audit-stage-restart", root)
            self.assertEqual(replay.returncode, 0, replay.stdout + replay.stderr)
    return test

for mode, occupied in product(("keyring", "auto"), (False, True)):
    name = f"test_retained_audit_stage_{mode}_" + ("occupied" if occupied else "empty_source")
    setattr(CodexRestorationRegressions, name, retained_stage_restart(mode, occupied))

for mode, action, phase in product(
    ("keyring", "auto"), ("return", "remove"),
    ("earlier", "late", "after-move", "after-move-denied", "after-move-denied-native"),
):
    setattr(CodexRestorationRegressions, f"test_final_audit_live_{mode}_{action}_" + phase.replace("-", "_"),
            scenario_test(f"audit-live-cleanup:{mode}:{action}:{phase}"))
for option in ("mixed", "single-backend", "denied", "replace-retained", "replace-retained-denied"):
    setattr(CodexRestorationRegressions, "test_final_audit_import_" + option.replace("-", "_"),
            scenario_test("audit-mixed-import:" + option))
for mode, phase in product(("keyring", "auto"), ("denied", "allowed")):
    setattr(CodexRestorationRegressions, f"test_final_audit_primary_removal_{mode}_{phase}",
            retained_return(mode, "remove-new-primary-" + phase))

def audit_mixed_import_cut(phase, resumed="audit-mixed-import-restart"):
    def test(self):
        with tempfile.TemporaryDirectory(prefix="notchlimits-import-cut-", dir="/private/tmp") as directory:
            root = pathlib.Path(directory)
            cut = swift_regression.run_fixture(self.executable, "audit-mixed-import:" + phase, root)
            self.assertEqual(cut.returncode, 86, cut.stdout + cut.stderr)
            restart = swift_regression.run_fixture(self.executable, resumed, root)
            self.assertEqual(restart.returncode, 0, restart.stdout + restart.stderr)
    return test

CodexRestorationRegressions.test_final_audit_import_restart = audit_mixed_import_cut("cut")
CodexRestorationRegressions.test_final_audit_import_occupied_restart = audit_mixed_import_cut(
    "replace-retained-cut", "audit-mixed-import-restart:occupied",
)
CodexRestorationRegressions.test_final_audit_import_file_denied_restart = audit_mixed_import_cut(
    "replace-retained-cut-file", "audit-mixed-import-restart:file-denied",
)
CodexRestorationRegressions.test_final_audit_import_occupied_denied_restart = audit_mixed_import_cut(
    "replace-retained-cut", "audit-mixed-import-restart:keyring-denied",
)
CodexRestorationRegressions.test_final_audit_import_ephemeral_restart = audit_mixed_import_cut(
    "replace-retained-cut-ephemeral", "audit-mixed-import-restart:ephemeral",
)

def audit_independent_staged_removal(mode):
    def test(self):
        with tempfile.TemporaryDirectory(prefix="notchlimits-staged-removal-", dir="/private/tmp") as directory:
            root = pathlib.Path(directory)
            for scenario, code in (
                (f"audit-backup:{mode}:cut-before-delete", 86),
                ("retained-audit-return:stage-crash-occupied", 86),
                ("audit-independent-staged-removal", 0),
            ):
                result = swift_regression.run_fixture(self.executable, scenario, root)
                self.assertEqual(result.returncode, code, result.stdout + result.stderr)
    return test

for mode in ("keyring", "auto"):
    setattr(CodexRestorationRegressions, f"test_final_audit_independent_stage_{mode}",
            audit_independent_staged_removal(mode))

def audit_live_takeover_restart(mode, action):
    def test(self):
        with tempfile.TemporaryDirectory(prefix="notchlimits-live-takeover-", dir="/private/tmp") as directory:
            root = pathlib.Path(directory)
            first = f"audit-live-cleanup:{mode}:{action}:after-move-denied-native-restart"
            cut = swift_regression.run_fixture(self.executable, first, root)
            self.assertEqual(cut.returncode, 86, cut.stdout + cut.stderr)
            restart = swift_regression.run_fixture(self.executable, "audit-live-restart-after-takeover", root)
            self.assertEqual(restart.returncode, 0, restart.stdout + restart.stderr)
    return test

for mode, action in product(("keyring", "auto"), ("return", "remove")):
    name = f"test_final_audit_live_{mode}_{action}_after_move_denied_native_restart"
    setattr(CodexRestorationRegressions, name, audit_live_takeover_restart(mode, action))

CodexRestorationRegressions.test_file_transfer_keeps_late_source = scenario_test("audit-mixed-import:replace-source")

for occupancy in ("vacant", "occupied"):
    phase = "replace-source-cut" if occupancy == "vacant" else "replace-source-cut-occupied"
    setattr(CodexRestorationRegressions, f"test_file_transfer_restart_{occupancy}",
            audit_mixed_import_cut(phase, "audit-file-transfer-restart:" + occupancy))

for mode, action in product(("file", "keyring", "auto"), ("return", "remove")):
    setattr(CodexRestorationRegressions, f"test_file_transfer_{mode}_{action}",
            scenario_test(f"audit-file-return:{mode}:{action}"))

for mode in ("keyring", "auto"):
    setattr(CodexRestorationRegressions, f"test_file_transfer_publication_{mode}",
            scenario_test("audit-file-publication:" + mode))


def audit_paired_return(mode, phase):
    def test(self):
        with tempfile.TemporaryDirectory(prefix="notchlimits-paired-return-", dir="/private/tmp") as directory:
            root = pathlib.Path(directory)
            cut = swift_regression.run_fixture(self.executable, f"audit-paired-return:{mode}:{phase}", root)
            self.assertEqual(cut.returncode, 86, cut.stdout + cut.stderr)
            restart = swift_regression.run_fixture(self.executable, "audit-paired-return-restart:" + phase, root)
            self.assertEqual(restart.returncode, 0, restart.stdout + restart.stderr)
    return test


for mode in ("keyring", "auto"):
    setattr(CodexRestorationRegressions, f"test_paired_return_{mode}_restart_and_remove", audit_paired_return(mode, "ready"))
    setattr(CodexRestorationRegressions, f"test_paired_return_{mode}_denied_restart", audit_paired_return(mode, "denied"))
    for phase in ("late-denied", "file-only", "keyring-only"):
        setattr(CodexRestorationRegressions, f"test_paired_return_{mode}_{phase.replace('-', '_')}_restart",
                audit_paired_return(mode, phase))
    setattr(CodexRestorationRegressions, f"test_paired_return_{mode}_live_rollback",
            scenario_test("audit-paired-return:" + mode + ":live"))


def audit_published_fallback_restart(mode, remove_new_file=False):
    def test(self):
        with tempfile.TemporaryDirectory(prefix="notchlimits-published-fallback-", dir="/private/tmp") as directory:
            root = pathlib.Path(directory)
            cut = swift_regression.run_fixture(self.executable, f"audit-file-publication:{mode}:cut", root)
            self.assertEqual(cut.returncode, 86, cut.stdout + cut.stderr)
            scenario = "audit-file-publication-restart" + (":remove-file" if remove_new_file else "")
            restart = swift_regression.run_fixture(self.executable, scenario, root)
            self.assertEqual(restart.returncode, 0, restart.stdout + restart.stderr)
    return test


for mode in ("keyring", "auto"):
    setattr(CodexRestorationRegressions, f"test_file_transfer_publication_{mode}_restart", audit_published_fallback_restart(mode))
    setattr(CodexRestorationRegressions, f"test_file_transfer_publication_{mode}_restart_remove_file",
            audit_published_fallback_restart(mode, remove_new_file=True))
