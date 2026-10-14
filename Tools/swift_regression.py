"""Compile regression fixtures together with the production Swift sources."""
from pathlib import Path
import platform
import subprocess


ROOT = Path(__file__).resolve().parent.parent
SOURCES = ROOT / "Sources" / "Notchlimits"
FIXTURES = ROOT / "Tests" / "Regressions"


def compile_fixture(directory, name, sources, flags=()):
    executable = Path(directory) / name
    command = [
        "swiftc", "-swift-version", "5", "-parse-as-library",
        "-target", f"{platform.machine()}-apple-macosx13.0",
        "-module-cache-path", str(Path(directory) / "module-cache"),
        *flags,
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
