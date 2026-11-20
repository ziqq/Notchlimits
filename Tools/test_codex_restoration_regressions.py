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
                "try RestorationSignals.remove?(url)\n        try super.removeItem(at: url)",
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
        support = support.replace(assignment, assignment + "\n        RestorationSignals.didWrite(key)")
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


def restart_test(cut):
    def test(self):
        with tempfile.TemporaryDirectory(prefix="notchlimits-codex-restart-", dir="/private/tmp") as directory:
            root = pathlib.Path(directory)
            scenario = "unreadable-original:relocated-primary-removed-alias-during-delete-restart-" + cut
            before = swift_regression.run_fixture(self.executable, scenario, root)
            self.assertEqual(before.returncode, 86, before.stdout + before.stderr)
            mode = "denied" if "-denied-" in cut else "available"
            after = swift_regression.run_fixture(self.executable, "restart-child:" + mode, root)
            self.assertEqual(after.returncode, 0, after.stdout + after.stderr)
    return test


restart_cases = list(product(("admission", "move", "delete"), ("unchanged", "rewrite", "replace"),
                             ("available", "denied"), ("stable", "retarget")))
for keychain in ("available", "denied"):
    restart_cases += [("move", "rewrite", keychain, "stage"), ("move", "rewrite", keychain, "source"),
                      ("move", "replace", keychain, "source"), ("delete", "rewrite", keychain, "source")]
for case in restart_cases:
    cut = "-".join(case)
    setattr(CodexRestorationRegressions, "test_restart_" + cut.replace("-", "_"), restart_test(cut))
