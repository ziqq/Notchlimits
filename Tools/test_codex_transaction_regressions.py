import pathlib
import sys
import tempfile
import unittest

import swift_regression
import test_auth_regressions as authentication


@unittest.skipUnless(sys.platform == "darwin", "Notchlimits runs on macOS")
class CodexTransactionRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture = tempfile.TemporaryDirectory(prefix="notchlimits-codex-transactions-")
        cls.addClassCleanup(fixture.cleanup)
        support = (swift_regression.FIXTURES / "Authentication.swift").read_text().split("\n@main\n", 1)[0]
        # Add callbacks only to the existing OS fakes. Production and previous
        # assertions remain unchanged when comparing the exact same fixture.
        boundaries = {
            "let exists = super.fileExists(atPath: configPath(path))":
                "let exists = super.fileExists(atPath: configPath(path))\n        TransactionSignals.io?(path)",
            "if Fixture.failCodexFileWrite && URL(fileURLWithPath: path).lastPathComponent.hasPrefix":
                "TransactionSignals.attributes?(path)\n        if Fixture.failCodexFileWrite && URL(fileURLWithPath: path).lastPathComponent.hasPrefix",
            "try super.removeItem(at: url)":
                "try super.removeItem(at: url)\n        TransactionSignals.removed?(url)",
        }
        for before, after in boundaries.items():
            assert support.count(before) == 1, before
            support = support.replace(before, after)
        cls.fixture_path = pathlib.Path(fixture.name) / "Transactions$Codex.swift"
        cls.fixture_path.write_text(support + "\n" + (swift_regression.FIXTURES / "Transactions$Codex.swift").read_text())
        authentication.AuthenticationRegressions.setUpClass.__func__(cls)

    check_scenario = authentication.AuthenticationRegressions.check_scenario


def scenario_test(scenario):
    def test(self):
        self.check_scenario(scenario)
    return test


modes = ("file", "keyring", "auto-file", "auto")
changes = ("login", "owner", "identical", "mode", "stable", "metadata")
scenarios = []
for mode in modes:
    for change in (*changes, "retarget"):
        scenarios.append(f"publish:{mode}:file:config:{change}")
        scenarios.append(f"publish:file:{mode}:prepare:{change}")
    for phase in ("backup", "backup-write"):
        for change in changes:
            scenarios.append(f"copyback:{mode}:{phase}:{change}")
    for phase in ("backup", "delete"):
        for change in ("owner", "identical", "mode", "stable", "metadata"):
            scenarios.append(f"primary:{mode}:{phase}:{change}")
for change in changes:
    scenarios.append(f"copyback:file:profile-write:{change}")
for mode in modes:
    for change in ("login", "owner", "identical", "stable", "metadata"):
        scenarios.append(f"rollback:{mode}:{change}")
assert len(scenarios) == len(set(scenarios)) == 170
for scenario in scenarios:
    setattr(CodexTransactionRegressions, "test_" + scenario.replace(":", "_").replace("-", "_"), scenario_test(scenario))
