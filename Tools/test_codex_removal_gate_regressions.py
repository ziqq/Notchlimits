import sys
import tempfile
import unittest
from pathlib import Path

import swift_regression
import test_auth_regressions as authentication


@unittest.skipUnless(sys.platform == "darwin", "Notchlimits runs on macOS")
class CodexRemovalGateRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        folder = tempfile.TemporaryDirectory(prefix="notchlimits-removal-gate-tests-")
        cls.addClassCleanup(folder.cleanup)
        support = (swift_regression.FIXTURES / "Authentication.swift").read_text().split("\n@main\n", 1)[0]
        # Inject external logins from the Keychain and filesystem shims. The
        # removal transaction, discovery and storage selection are production.
        boundaries = {
            "            var attributes: [String: Any] = [kSecAttrService as String: \"Codex Auth\", kSecAttrAccount as String: key]":
                "            RemovalSignals.present?(key)\n"
                "            var attributes: [String: Any] = [kSecAttrService as String: \"Codex Auth\", kSecAttrAccount as String: key]",
            "        guard !Fixture.denyCodexDelete else { return errSecAuthFailed }\n"
            "        let key = (query as NSDictionary)[kSecAttrAccount as String] as! String":
                "        let key = (query as NSDictionary)[kSecAttrAccount as String] as! String\n"
                "        RemovalSignals.attempting?(key)\n"
                "        guard !Fixture.denyCodexDelete else { return errSecAuthFailed }",
            "            Fixture.codexSecretReads += 1":
                "            Fixture.codexSecretReads += 1\n            RemovalSignals.reading?(key)",
            "        try super.moveItem(at: srcURL, to: dstURL)":
                "        try super.moveItem(at: srcURL, to: dstURL)\n"
                "        if dstURL.lastPathComponent.hasPrefix(\".removed-\") { RemovalSignals.staged = true }",
            "    Fixture.interactionAllowed = state\n    return errSecSuccess":
                "    Fixture.interactionAllowed = state\n"
                "    if !state { let event = RemovalSignals.gate; RemovalSignals.gate = nil; event?() }\n"
                "    return errSecSuccess",
            "        try super.createDirectory(at: url, withIntermediateDirectories: createIntermediates, attributes: attributes)":
                "        try super.createDirectory(at: url, withIntermediateDirectories: createIntermediates, attributes: attributes)\n"
                "        RemovalSignals.created?(url)",
            "        guard let data = Fixture.codexKeychain[key] else { return errSecItemNotFound }":
                "        guard let data = Fixture.codexKeychain[key] else {\n"
                "            if (query as NSDictionary)[kSecReturnAttributes as String] as? Bool == true { RemovalSignals.missing?(key) }\n"
                "            return errSecItemNotFound\n"
                "        }",
            "        Fixture.codexKeychain[key] = nil\n        return errSecSuccess":
                "        RemovalSignals.deleted?(key, Fixture.codexKeychain[key])\n"
                "        Fixture.codexKeychain[key] = nil\n        return errSecSuccess",
            "        Fixture.codexKeychain[key] = (attributes as NSDictionary)[kSecValueData as String] as? Data\n    }":
                "        guard Fixture.codexKeychain[key] == nil else { return errSecDuplicateItem }\n"
                "        Fixture.codexKeychain[key] = (attributes as NSDictionary)[kSecValueData as String] as? Data\n    }",
        }
        for before, after in boundaries.items():
            assert support.count(before) == 1, before
            support = support.replace(before, after)
        cleanup = (swift_regression.FIXTURES / "Cleanup$Authentication.swift").read_text().replace(
            "@main enum Cleanup$Authentication", "enum Cleanup$Authentication", 1)
        cls.fixture_path = Path(folder.name) / "RemovalGate$Codex.swift"
        cls.fixture_path.write_text(support + "\n" + cleanup + "\n" +
                                    (swift_regression.FIXTURES / "RemovalGate$Codex.swift").read_text())
        authentication.AuthenticationRegressions.setUpClass.__func__(cls)

    check_scenario = authentication.AuthenticationRegressions.check_scenario


def scenario_test(scenario):
    def test(self):
        self.check_scenario(scenario)
    return test


scenarios = []
for mode in ("auto", "keyring"):
    for visibility in ("readable", "opaque"):
        for phase in ("source-gate", "delete-gate", "rollback-gate", "finish"):
            if phase == "source-gate" and visibility == "opaque":
                continue
            replacements = ("stable", "replacement", "keyring") if phase == "finish" else ("stable", "replacement")
            for replacement in replacements:
                scenarios.append(f"{mode}:{visibility}:{phase}:{replacement}")
for mode in ("auto", "keyring"):
    scenarios.append(f"{mode}:opaque:source-gate:stable")
    scenarios.append(f"{mode}:opaque:post-reservation:stable")
    for phase in ("source-gate", "post-reservation", "delete-gate", "rollback-gate"):
        scenarios.append(f"{mode}:opaque:{phase}:same-second")
for mode in ("auto", "keyring"):
    for phase, visibility in (("delete-late", "opaque"), ("post-file", "opaque"),
                              ("finish-last-read", "opaque"), ("finish-last-read", "readable")):
        scenarios.extend(f"{mode}:{visibility}:{phase}:{state}" for state in ("stable", "replacement"))
    scenarios.append(f"{mode}:readable:delete-late:replacement")
    scenarios.append(f"{mode}:opaque:post-file:also-readded")
for visibility in ("readable", "opaque"):
    scenarios.extend(f"auto:{visibility}:rollback-late:{state}" for state in ("stable", "replacement"))
assert len(scenarios) == len(set(scenarios)) == 68
for scenario in scenarios:
    setattr(CodexRemovalGateRegressions, "test_" + scenario.replace(":", "_").replace("-", "_"),
            scenario_test(scenario))
