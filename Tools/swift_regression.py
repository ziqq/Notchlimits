"""Compile regression fixtures together with the production Swift sources."""
from pathlib import Path
import platform
import subprocess


ROOT = Path(__file__).resolve().parent.parent
SOURCES = ROOT / "Sources" / "Notchlimits"
FIXTURES = ROOT / "Tests" / "Regressions"


def compile_fixture(directory, name, sources, flags=()):
    executable = Path(directory) / name
    dependencies = []
    if any("import TOMLDecoder" in (SOURCES / source).read_text() for source in sources):
        result = subprocess.run(
            ["swift", "build", "--package-path", str(ROOT), "--target", "TOMLDecoder"],
            capture_output=True, text=True, timeout=240,
        )
        if result.returncode:
            raise RuntimeError(f"TOMLDecoder did not build:\n{result.stdout}\n{result.stderr}")
        binary_path = subprocess.run(
            ["swift", "build", "--package-path", str(ROOT), "--show-bin-path"],
            capture_output=True, text=True, check=True, timeout=30,
        ).stdout.strip()
        build = Path(binary_path)
        dependencies = ["-I", str(build / "Modules"), *map(str, (build / "TOMLDecoder.build").glob("*.o"))]
    command = [
        "swiftc", "-swift-version", "5", "-parse-as-library",
        "-target", f"{platform.machine()}-apple-macosx13.0",
        "-module-cache-path", str(Path(directory) / "module-cache"),
        *flags,
        *dependencies,
        *(str(SOURCES / source) for source in sources),
        str(FIXTURES / f"{name}.swift"), "-o", str(executable),
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise RuntimeError(f"{name} fixture did not compile:\n{result.stderr}")
    return executable


def run_fixture(executable, scenario, directory, *arguments):
    return subprocess.run(
        [str(executable), scenario, str(directory), *(str(arg) for arg in arguments)],
        capture_output=True, text=True, timeout=20,
    )
