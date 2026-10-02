import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parent.parent
GENERATOR = ROOT / "Tools" / "make-strings.py"


class StringsGeneratorTests(unittest.TestCase):
    def test_generation_preserves_every_committed_translation(self):
        expected = {
            path.relative_to(ROOT): path.read_bytes()
            for path in (ROOT / "Resources").glob("*.lproj/Localizable.strings")
        }
        self.assertEqual(len(expected), 14)
        with tempfile.TemporaryDirectory() as directory:
            generated = pathlib.Path(directory)
            subprocess.run(["python3", str(GENERATOR)], cwd=generated, check=True,
                           capture_output=True)
            actual = {
                path.relative_to(generated): path.read_bytes()
                for path in (generated / "Resources").glob("*.lproj/Localizable.strings")
            }
            self.assertEqual(actual.keys(), expected.keys())
            for path, content in expected.items():
                with self.subTest(language=path.parent.name):
                    self.assertEqual(actual[path], content)
            subprocess.run(["python3", str(GENERATOR)], cwd=generated, check=True,
                           capture_output=True)
            for path, content in actual.items():
                self.assertEqual((generated / path).read_bytes(), content)


if __name__ == "__main__":
    unittest.main()
