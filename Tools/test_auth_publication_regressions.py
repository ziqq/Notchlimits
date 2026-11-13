import pathlib
import sys
import tempfile
import unittest

import swift_regression
import test_auth_regressions as authentication


@unittest.skipUnless(sys.platform == "darwin", "Notchlimits runs on macOS")
class AuthenticationPublicationRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture = tempfile.TemporaryDirectory(prefix="notchlimits-auth-publication-")
        cls.addClassCleanup(fixture.cleanup)
        support = (swift_regression.FIXTURES / "Authentication.swift").read_text().split("\n@main\n", 1)[0]
        boundaries = {
            "if Fixture.failCodexFileWrite && URL(fileURLWithPath: path).lastPathComponent.hasPrefix":
                "PublicationSignals.attributes?(path, false)\n        if Fixture.failCodexFileWrite && URL(fileURLWithPath: path).lastPathComponent.hasPrefix",
            "try super.setAttributes(attributes, ofItemAtPath: path)":
                "try super.setAttributes(attributes, ofItemAtPath: path)\n        PublicationSignals.attributes?(path, true)",
            "try super.createDirectory(at: url, withIntermediateDirectories: createIntermediates, attributes: attributes)":
                "try super.createDirectory(at: url, withIntermediateDirectories: createIntermediates, attributes: attributes)\n        PublicationSignals.created?(url)",
        }
        for before, after in boundaries.items():
            assert support.count(before) == 1, before
            support = support.replace(before, after)
        cls.fixture_path = pathlib.Path(fixture.name) / "Publication$Authentication.swift"
        cls.fixture_path.write_text(support + "\n" + (swift_regression.FIXTURES / "Publication$Authentication.swift").read_text())
        authentication.AuthenticationRegressions.setUpClass.__func__(cls)

    check_scenario = authentication.AuthenticationRegressions.check_scenario


def scenario_test(scenario):
    def test(self):
        self.check_scenario(scenario)
    return test


changes = ("login", "rotation", "owner", "identical", "retarget", "mode", "metadata", "stable")
scenarios = []
for target in ("source", "copy"):
    for mode in ("file", "auto-file"):
        for phase in ("before", "after"):
            for change in changes:
                scenarios.append(f"renew:{target}:{mode}:{phase}:{change}")
for mode in ("keyring", "auto"):
    for phase in ("before", "after"):
        for change in (*changes, "unreadable"):
            scenarios.append(f"remove:{mode}:{phase}:{change}")
for operation in ("preflight", "save"):
    for phase in ("before", "after"):
        for change in ("login", "storage", "oauth", "owner", "identical", "retarget", "metadata", "stable"):
            scenarios.append(f"claude:{operation}:{phase}:{change}")
assert len(scenarios) == len(set(scenarios)) == 132
for scenario in scenarios:
    setattr(AuthenticationPublicationRegressions, "test_" + scenario.replace(":", "_").replace("-", "_"), scenario_test(scenario))
