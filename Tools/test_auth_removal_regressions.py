import pathlib
import tempfile
import unittest
import sys

import swift_regression
import test_auth_regressions as authentication


@unittest.skipUnless(sys.platform == "darwin", "Notchlimits runs on macOS")
class AuthenticationRemovalRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture = tempfile.TemporaryDirectory(prefix="notchlimits-removal-tests-")
        cls.addClassCleanup(fixture.cleanup)
        root = swift_regression.ROOT
        support = (root / "Tests/Regressions/Authentication.swift").read_text().split("\n@main\n", 1)[0]
        replacements={
        '        Fixture.codexKeychain[key] = nil\n        return errSecSuccess':'        Fixture.codexKeychain[key] = nil\n        AuditSignals.deleted?(key)\n        return errSecSuccess',
        '        guard let data = Fixture.codexKeychain[key] else { return errSecItemNotFound }':'        if AuditSignals.blockedKey == key { return errSecNotAvailable }\n        if (query as NSDictionary)[kSecReturnData as String] as? Bool == true { AuditSignals.read?(key) }\n        guard let data = Fixture.codexKeychain[key] else { return errSecItemNotFound }',
        'let exists = super.fileExists(atPath: configPath(path))':'let exists = super.fileExists(atPath: configPath(path))\n        CleanupSignals.io?(path)',
        '        try super.removeItem(at: url)':'        try super.removeItem(at: url)\n        CleanupSignals.removed?(url)',
        '        Fixture.codexKeychain[key] = (attributes as NSDictionary)[kSecValueData as String] as? Data':'        Fixture.codexKeychain[key] = (attributes as NSDictionary)[kSecValueData as String] as? Data\n        CleanupSignals.written?(key)',
        }
        for before, after in replacements.items():
            assert support.count(before) in (1, 2), before
            support = support.replace(before, after)
        cleanup = (swift_regression.FIXTURES / "Cleanup$Authentication.swift").read_text().replace(
            "@main enum Cleanup$Authentication", "enum Cleanup$Authentication", 1)
        cls.fixture_path = pathlib.Path(fixture.name) / "Removal$Authentication.swift"
        cls.fixture_path.write_text(support + "\n" + cleanup + "\n" +
                                    (swift_regression.FIXTURES / "Removal$Authentication.swift").read_text())
        authentication.AuthenticationRegressions.setUpClass.__func__(cls)

    check_scenario = authentication.AuthenticationRegressions.check_scenario


def scenario_test(scenario):
    def test(self):
        self.check_scenario(scenario)
    return test


scenarios=['claude:stable:ok','claude:takeover:ok','claude:stable:denied','claude:takeover:denied','metadata:keyring:stable','metadata:keyring:fail','metadata:auto:stable','metadata:auto:fail','unlink:file:stable','unlink:file:fail','unlink:auto-file:fail','unlink:keyring:fail','unlink:auto:fail','shared:source:early','shared:source:late','shared:copy:early','shared:copy:late','shared:source:read','shared:copy:read','metadata:keyring:readd','metadata:auto:readd']
for scenario in scenarios:
    setattr(AuthenticationRemovalRegressions, "test_" + scenario.replace(":", "_").replace("-", "_"), scenario_test(scenario))
