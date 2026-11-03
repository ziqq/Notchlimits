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
assert len(scenarios) == len(set(scenarios)) == 111
for scenario in scenarios:
    setattr(CodexRestorationRegressions, "test_" + scenario.replace(":", "_").replace("-", "_"), scenario_test(scenario))
