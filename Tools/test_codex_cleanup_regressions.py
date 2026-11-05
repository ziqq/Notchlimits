import pathlib
import tempfile
import unittest
import sys

import swift_regression
import test_auth_regressions as authentication


@unittest.skipUnless(sys.platform == "darwin", "Notchlimits runs on macOS")
class CodexCleanupRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture = tempfile.TemporaryDirectory(prefix="notchlimits-codex-cleanup-")
        cls.addClassCleanup(fixture.cleanup)
        support = (swift_regression.FIXTURES / "Authentication.swift").read_text().split("\n@main\n", 1)[0]
        boundaries = {
            "try super.removeItem(at: url)":
                "try super.removeItem(at: url)\n        CleanupSignals.removed?(url)",
            "let exists = super.fileExists(atPath: configPath(path))":
                "let exists = super.fileExists(atPath: configPath(path))\n        CleanupSignals.io?(path)",
            "        Fixture.codexKeychain[key] = nil\n        return errSecSuccess":
                "        Fixture.codexKeychain[key] = nil\n        BackupSignals.deleted?(key)\n        return errSecSuccess",
        }
        boundaries["func SecItemCopyMatching(_ query: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {"] = """func SecItemCopyMatching(_ query: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {
    if (query as NSDictionary)[kSecAttrService as String] as? String == "Codex Auth",
       (query as NSDictionary)[kSecReturnData as String] as? Bool == true,
       let key = (query as NSDictionary)[kSecAttrAccount as String] as? String { BackupSignals.nativeRead?(key) }"""
        for before, after in boundaries.items():
            assert support.count(before) == 1, before
            support = support.replace(before, after)
        cleanup = (swift_regression.FIXTURES / "Cleanup$Authentication.swift").read_text().replace(
            "@main enum Cleanup$Authentication", "enum Cleanup$Authentication", 1)
        cls.fixture_path = pathlib.Path(fixture.name) / "Cleanup$Codex.swift"
        cls.fixture_path.write_text(support + "\n" + cleanup + "\n" +
                                    (swift_regression.FIXTURES / "Cleanup$Codex.swift").read_text())
        authentication.AuthenticationRegressions.setUpClass.__func__(cls)

    check_scenario = authentication.AuthenticationRegressions.check_scenario


def scenario_test(scenario):
    def test(self):
        self.check_scenario(scenario)
    return test


scenarios = ["orphan:auto:allowed", "orphan:auto:denied", "orphan:keyring:denied",
             "stash:auto:allowed", "stash:auto:denied", "stash:keyring:denied"]
for mode in ("file", "auto-file", "keyring", "auto"):
    for change in ("stable", "native", "backup"):
        for operation in ("restore", "remove"):
            scenarios.append(f"{operation}:{mode}:{change}")
    scenarios += [f"publication:{mode}", f"destination:{mode}"]
for mode in ("keyring", "auto"):
    for change in ("stable", "native", "backup"):
        for operation in ("restore", "remove"):
            scenarios.append(f"{operation}:{mode}:{change}:keychain")
    for operation in ("restore", "remove"):
        scenarios.append(f"{operation}:{mode}:native:completed")
scenarios += ["empty:keyring", "empty:auto"]
assert len(scenarios) == len(set(scenarios)) == 56
for scenario in scenarios:
    setattr(CodexCleanupRegressions, "test_" + scenario.replace(":", "_").replace("-", "_"), scenario_test(scenario))
