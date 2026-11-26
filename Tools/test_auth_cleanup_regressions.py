import pathlib
import sys
import tempfile
import unittest

import swift_regression
import test_auth_regressions as authentication


@unittest.skipUnless(sys.platform == "darwin", "Notchlimits runs on macOS")
class AuthenticationCleanupRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture = tempfile.TemporaryDirectory(prefix="notchlimits-auth-cleanup-")
        cls.addClassCleanup(fixture.cleanup)
        support = (swift_regression.FIXTURES / "Authentication.swift").read_text().split("\n@main\n", 1)[0]
        boundaries = {
            "func SecItemCopyMatching(_ query: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {":
                """func SecItemCopyMatching(_ query: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {
    if (query as NSDictionary)[kSecAttrService as String] as? String == "Codex Auth",
       (query as NSDictionary)[kSecReturnData as String] as? Bool == true,
       let key = (query as NSDictionary)[kSecAttrAccount as String] as? String { CleanupSignals.read?(key) }""",
            "let exists = super.fileExists(atPath: configPath(path))":
                "let exists = super.fileExists(atPath: configPath(path))\n        CleanupSignals.io?(path)",
            "try super.setAttributes(attributes, ofItemAtPath: path)":
                "try super.setAttributes(attributes, ofItemAtPath: path)\n        CleanupSignals.attributes?(path)",
            "try super.moveItem(at: srcURL, to: dstURL)":
                "try super.moveItem(at: srcURL, to: dstURL)\n        CleanupSignals.moved?(srcURL, dstURL)",
            "try super.removeItem(at: url)":
                "try super.removeItem(at: url)\n        CleanupSignals.removed?(url)",
            "var entries = try super.contentsOfDirectory(at: url, includingPropertiesForKeys: keys, options: mask)":
                "var entries = try super.contentsOfDirectory(at: url, includingPropertiesForKeys: keys, options: mask)\n        CleanupSignals.listed?(url)",
        }
        for before, after in boundaries.items():
            assert support.count(before) == 1, before
            support = support.replace(before, after)
        assignment = "Fixture.codexKeychain[key] = (attributes as NSDictionary)[kSecValueData as String] as? Data"
        assert support.count(assignment) == 2
        support = support.replace(assignment, assignment + "\n        CleanupSignals.written?(key)")
        cls.fixture_path = pathlib.Path(fixture.name) / "Cleanup$Authentication.swift"
        cls.fixture_path.write_text(support + "\n" + (swift_regression.FIXTURES / "Cleanup$Authentication.swift").read_text())
        authentication.AuthenticationRegressions.setUpClass.__func__(cls)

    check_scenario = authentication.AuthenticationRegressions.check_scenario


def scenario_test(scenario):
    def test(self):
        self.check_scenario(scenario)
    return test


scenarios = []
for mode in ("file", "auto-file", "keyring", "auto"):
    for change in ("login", "stable", "metadata"):
        scenarios.append(f"remove:{mode}:before:{change}")
    scenarios.append(f"remove:{mode}:after:login")
    for change in ("login", "owner", "identical", "retarget", "stable", "metadata"):
        scenarios.append(f"backup:{mode}:{change}")
for mode in ("auto-file", "keyring", "auto"):
    for change in ("login", "stable"):
        scenarios.append(f"remove:{mode}:unlink:{change}")
for target in ("source", "copy"):
    for mode in ("keyring", "auto"):
        for phase in ("scan", "exists"):
            for change in ("login", "stable", "metadata"):
                scenarios.append(f"cleanup:{target}:{mode}:{phase}:{change}")
for operation in ("preflight", "save"):
    for change in ("login", "storage", "oauth", "stable"):
        scenarios.append(f"claude:{operation}:{change}")
for kind in ("data", "plain", "separate"):
    scenarios.append(f"claudeAlias:{kind}")
assert len(scenarios) == len(set(scenarios)) == 81
for scenario in scenarios:
    setattr(AuthenticationCleanupRegressions, "test_" + scenario.replace(":", "_").replace("-", "_"), scenario_test(scenario))
