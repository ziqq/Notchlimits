import pathlib
import sys
import tempfile
import unittest

import swift_regression
import test_auth_regressions as authentication


@unittest.skipUnless(sys.platform == "darwin", "Notchlimits runs on macOS")
class CodexRecoveryRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture = tempfile.TemporaryDirectory(prefix="notchlimits-recovery-tests-")
        cls.addClassCleanup(fixture.cleanup)
        support = (swift_regression.FIXTURES / "Authentication.swift").read_text().split("\n@main\n", 1)[0]
        boundaries = {
            "        Fixture.codexKeychain[key] = nil\n        return errSecSuccess":
                "        Fixture.codexKeychain[key] = nil\n        RecoverySignals.deleted?(key)\n        return errSecSuccess",
            "        try super.removeItem(at: url)":
                "        try super.removeItem(at: url)\n        RecoverySignals.cleaned?(url)",
            "        try super.createDirectory(at: url, withIntermediateDirectories: createIntermediates, attributes: attributes)":
                "        try super.createDirectory(at: url, withIntermediateDirectories: createIntermediates, attributes: attributes)\n        RecoverySignals.created?(url)",
            "        guard !Fixture.denyCodexWrite && key != Fixture.denyCodexWriteAccount else { return errSecAuthFailed }\n        Fixture.codexKeychain[key] = (attributes as NSDictionary)[kSecValueData as String] as? Data\n    }":
                "        guard !Fixture.denyCodexWrite && key != Fixture.denyCodexWriteAccount else { return errSecAuthFailed }\n        guard Fixture.codexKeychain[key] == nil else { return errSecDuplicateItem }\n        Fixture.codexKeychain[key] = (attributes as NSDictionary)[kSecValueData as String] as? Data\n    }",
        }
        for before, after in boundaries.items():
            assert support.count(before) == 1, before
            support = support.replace(before, after)
        cleanup = (swift_regression.FIXTURES / "Cleanup$Authentication.swift").read_text().replace(
            "@main enum Cleanup$Authentication", "enum Cleanup$Authentication", 1)
        cls.fixture_path = pathlib.Path(fixture.name) / "Recovery$Codex.swift"
        cls.fixture_path.write_text(support + "\n" + cleanup + "\n" +
                                    (swift_regression.FIXTURES / "Recovery$Codex.swift").read_text())
        authentication.AuthenticationRegressions.setUpClass.__func__(cls)

    check_scenario = authentication.AuthenticationRegressions.check_scenario


def scenario_test(scenario):
    def test(self):
        self.check_scenario(scenario)
    return test


scenarios = []
for mode in ("keyring", "auto"):
    for replacement in ("stable", "file", "keyring", "auto-file", "auto"):
        scenarios.append(f"{mode}:{replacement}:deleted:none:idle")
    for replacement in ("file", "keyring"):
        for readd in ("file", "keyring"):
            scenarios.append(f"{mode}:{replacement}:deleted:{readd}:idle")
        scenarios.append(f"{mode}:{replacement}:cleanup:none:idle")
        for readd in ("none", "file"):
            scenarios.append(f"{mode}:{replacement}:deleted:{readd}:pending")
    for replacement in ("stable", "file", "keyring"):
        scenarios.append(f"{mode}:{replacement}:opaque:none:idle")
    scenarios.append(f"{mode}:keyring:deleted:file:idle:prepare")
assert len(scenarios) == len(set(scenarios)) == 38
for scenario in scenarios:
    setattr(CodexRecoveryRegressions, "test_" + scenario.replace(":", "_").replace("-", "_"),
            scenario_test(scenario))
