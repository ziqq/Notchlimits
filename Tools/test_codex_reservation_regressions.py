import sys
import tempfile
import unittest
from pathlib import Path

import swift_regression
import test_auth_regressions as authentication


@unittest.skipUnless(sys.platform == "darwin", "Notchlimits runs on macOS")
class CodexReservationRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture = tempfile.TemporaryDirectory(prefix="notchlimits-reservation-tests-")
        cls.addClassCleanup(fixture.cleanup)
        support = (swift_regression.FIXTURES / "Authentication.swift").read_text().split("\n@main\n", 1)[0]
        boundaries = {
            '        try super.moveItem(at: srcURL, to: dstURL)':
                '        try super.moveItem(at: srcURL, to: dstURL)\n        if dstURL.lastPathComponent.hasPrefix(".removed-") { RecoverySignals.staged?() }',

            '    Fixture.interactionAllowed = state\n    return errSecSuccess':
                '    Fixture.interactionAllowed = state\n    if !state { RecoverySignals.gated?() }\n    return errSecSuccess',
            'func SecItemUpdate(_ query: CFDictionary, _ attributes: CFDictionary) -> OSStatus {\n    Fixture.lock.lock()':
                'func SecItemUpdate(_ query: CFDictionary, _ attributes: CFDictionary) -> OSStatus {\n    if (attributes as NSDictionary)[kSecAttrAccount as String] != nil { RecoverySignals.renaming?() }\n    Fixture.lock.lock()',
            '        guard let data = Fixture.codexKeychain[key] else { return errSecItemNotFound }':
                '        guard let data = Fixture.codexKeychain[key] else {\n'
                '            if (query as NSDictionary)[kSecReturnAttributes as String] as? Bool == true { RecoverySignals.absenceRead?(key) }\n'
                '            return errSecItemNotFound\n'
                '        }',
            '        try super.createDirectory(at: url, withIntermediateDirectories: createIntermediates, attributes: attributes)':
                '        try super.createDirectory(at: url, withIntermediateDirectories: createIntermediates, attributes: attributes)\n        RecoverySignals.created?(url)',
            '        Fixture.codexKeychain[key] = nil\n        return errSecSuccess':
                '        Fixture.codexKeychain[key] = nil\n        RecoverySignals.deleted?(key)\n        return errSecSuccess',
            '        guard !Fixture.denyCodexWrite && key != Fixture.denyCodexWriteAccount else { return errSecAuthFailed }\n        Fixture.codexKeychain[key] = (attributes as NSDictionary)[kSecValueData as String] as? Data\n    }':
                '        guard !Fixture.denyCodexWrite && key != Fixture.denyCodexWriteAccount else { return errSecAuthFailed }\n        guard Fixture.codexKeychain[key] == nil else { return errSecDuplicateItem }\n        Fixture.codexKeychain[key] = (attributes as NSDictionary)[kSecValueData as String] as? Data\n    }',
        }
        for before, after in boundaries.items():
            assert support.count(before) == 1, before
            support = support.replace(before, after)
        cleanup = (swift_regression.FIXTURES / "Cleanup$Authentication.swift").read_text().replace(
            "@main enum Cleanup$Authentication", "enum Cleanup$Authentication", 1)
        cls.fixture_path = Path(fixture.name) / "Reservation$Codex.swift"
        cls.fixture_path.write_text(support + "\n" + cleanup + "\n" +
                                    (swift_regression.FIXTURES / "Reservation$Codex.swift").read_text())
        authentication.AuthenticationRegressions.setUpClass.__func__(cls)

    check_scenario = authentication.AuthenticationRegressions.check_scenario


def scenario_test(scenario):
    def test(self):
        self.check_scenario(scenario)
    return test


scenarios = []
for mode in ("keyring", "auto", "auto-file"):
    for phase in ("created", "gate"):
        for replacement in ("stable", "file", "keyring", "auto-file", "auto"):
            scenarios.append(f"{mode}:{replacement}:{phase}")
    for replacement in ("keyring", "auto"):
        phase = "absence" if mode == "auto-file" else "rename"
        scenarios.append(f"{mode}:{replacement}:{phase}")
for replacement in ("stable", "file", "keyring", "auto-file", "auto"):
    scenarios.append(f"auto-file:{replacement}:staged")
assert len(scenarios) == len(set(scenarios)) == 41
for scenario in scenarios:
    setattr(CodexReservationRegressions, "test_" + scenario.replace(":", "_").replace("-", "_"),
            scenario_test(scenario))
