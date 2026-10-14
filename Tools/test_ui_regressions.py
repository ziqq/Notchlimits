import pathlib
import sys
import tempfile
import unittest

from swift_regression import ROOT, compile_fixture, run_fixture


@unittest.skipUnless(sys.platform == "darwin", "Notchlimits runs on macOS")
class TimeLabelRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="notchlimits-ui-tests-")
        cls.addClassCleanup(cls.build.cleanup)
        cls.executable = compile_fixture(cls.build.name, "TimeLabels", [
            "Model/Models.swift", "UI/Theme.swift", "UI/ColumnView.swift",
        ])

    def check_scenario(self, scenario):
        with tempfile.TemporaryDirectory(prefix="notchlimits-ui-fixture-") as directory:
            result = run_fixture(
                self.executable, scenario, pathlib.Path(directory),
                ROOT / "Resources/en.lproj/Localizable.strings",
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_reset_countdown_updates_without_new_usage_data(self):
        self.check_scenario("reset")

    def test_stale_age_updates_without_new_usage_data(self):
        self.check_scenario("age")
