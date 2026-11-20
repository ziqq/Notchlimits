import pathlib
import sys
import tempfile
import unittest

from swift_regression import FIXTURES, compile_fixture, run_fixture


@unittest.skipUnless(sys.platform == "darwin", "Notchlimits runs on macOS")
class AuthenticationSwitchingRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build = tempfile.TemporaryDirectory(prefix="notchlimits-auth-switching-")
        cls.addClassCleanup(build.cleanup)
        support = (FIXTURES / "Authentication.swift").read_text().split("\n@main\n", 1)[0]
        # Exercise production DesktopApp with AppKit's process boundaries replaced.
        start = support.index("\nenum DesktopApp {")
        end = support.index("\nprotocol AccountDiscovery", start)
        support = support[:start] + support[end:]
        home = "override var homeDirectoryForCurrentUser: URL { Fixture.root }"
        assert support.count(home) == 1
        support = support.replace(home, home + '''

    override func url(for directory: SearchPathDirectory, in domain: SearchPathDomainMask,
                      appropriateFor url: URL?, create shouldCreate: Bool) throws -> URL {
        guard directory == .applicationSupportDirectory, domain == .userDomainMask else {
            return try super.url(for: directory, in: domain, appropriateFor: url, create: shouldCreate)
        }
        let support = Fixture.root.appendingPathComponent("Application Support")
        if shouldCreate { try createDirectory(at: support, withIntermediateDirectories: true) }
        return support
    }
''')
        fixture = pathlib.Path(build.name) / "Switching$Authentication.swift"
        fixture.write_text(support + "\n" + (FIXTURES / fixture.name).read_text())
        cls.executable = compile_fixture(build.name, "AuthenticationSwitching", [
            "Model/Models.swift", "Model/Account.swift", "Core/JWT.swift",
            "Core/AccountSwitcher.swift", "Core/AppAccountSwitcher.swift", "Core/DesktopApp.swift",
            "Core/CLISelection$Claude.swift", "Core/StorageLock$Claude.swift",
            "Core/AccountRemoval.swift", "Core/AuthStorage$Codex.swift", "Core/AuthSwap$Codex.swift",
            "Providers/AuthStorage$Claude.swift", "Providers/Discovery$Real.swift",
            "Providers/OAuth$Claude.swift", "Providers/OAuth$Codex.swift",
            "Providers/Provider$Claude.swift", "Providers/Provider$Codex.swift",
        ], flags=("-DVALIDATED_USAGE", "-DCLAUDE_PRIMARY_OWNER"), fixture_path=fixture)

    def check_scenario(self, scenario):
        with tempfile.TemporaryDirectory(prefix="notchlimits-switch-", dir="/private/tmp") as directory:
            result = run_fixture(self.executable, scenario, pathlib.Path(directory))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_claude_unsupported_shell_preserves_desktop(self):
        self.check_scenario("claude-shell")

    def test_claude_unwritable_startup_preserves_desktop(self):
        self.check_scenario("claude-startup")

    def test_claude_toggle_off_during_stop(self):
        self.check_scenario("claude-toggle-off")

    def test_claude_toggle_on_during_stop(self):
        self.check_scenario("claude-toggle-on")

    def test_claude_missing_desktop_preserves_shell(self):
        self.check_scenario("claude-missing-desktop")

    def test_codex_refuses_owner_replaced_during_stop(self):
        self.check_scenario("codex-replaced-owner")

    def test_codex_refuses_primary_backup_replaced_during_stop(self):
        self.check_scenario("codex-replaced-backup")

    def test_codex_refuses_primary_backup_logged_out_during_stop(self):
        self.check_scenario("codex-logged-out-backup")

    def test_codex_switches_stable_owner(self):
        self.check_scenario("codex-stable-owner")

    def test_codex_restores_stashed_primary_with_missing_native_home(self):
        self.check_scenario("codex-missing-primary")
