"""Compile regression fixtures together with the production Swift sources."""
from pathlib import Path
import platform
import subprocess


ROOT = Path(__file__).resolve().parent.parent
SOURCES = ROOT / "Sources" / "Notchlimits"
FIXTURES = ROOT / "Tests" / "Regressions"


def instrument_codex_file_transfer(support):
    signature = """func renameatx_np(_ fromFD: Int32, _ from: UnsafePointer<CChar>, _ toFD: Int32,
                  _ to: UnsafePointer<CChar>, _ flags: UInt32) -> Int32 {"""
    assert support.count(signature) == 1
    hook = "\n    if let result = stageCodexAuth(fromFD, from, toFD, to, flags) { return result }"
    return support.replace(signature, signature + hook) + "\n" + (FIXTURES / "FileMutation$Codex.swift").read_text()


def compile_fixture(directory, name, sources, flags=(), extra_sources=(), fixture_path=None):
    executable = Path(directory) / name
    dependencies = []
    if any("import TOMLDecoder" in (SOURCES / source).read_text() for source in sources):
        build_command = ["swift", "build", "--package-path", str(ROOT)]
        result = subprocess.run(
            [*build_command, "--target", "TOMLDecoder"],
            capture_output=True, text=True, timeout=240,
        )
        if result.returncode:
            raise RuntimeError(f"TOMLDecoder did not build:\n{result.stdout}\n{result.stderr}")
        binary_path = subprocess.run(
            [*build_command, "--show-bin-path"],
            capture_output=True, text=True, check=True, timeout=30,
        ).stdout.strip()
        build = Path(binary_path)
        product = build / "TOMLDecoder.o"
        if (build / "TOMLDecoder.swiftmodule").is_dir() and product.is_file():
            dependencies = ["-I", str(build), str(product)]
        else:
            dependencies = ["-I", str(build / "Modules"), *map(str, (build / "TOMLDecoder.build").glob("*.o"))]
    command = [
        "swiftc", "-swift-version", "5", "-parse-as-library",
        "-target", f"{platform.machine()}-apple-macosx13.0",
        "-module-cache-path", str(Path(directory) / "module-cache"),
        *flags,
        *dependencies,
        *(str(SOURCES / source) for source in sources),
        *map(str, extra_sources),
        str(fixture_path or FIXTURES / f"{name}.swift"), "-o", str(executable),
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=600)
    if result.returncode:
        raise RuntimeError(f"{name} fixture did not compile:\n{result.stderr}")
    return executable


def run_fixture(executable, scenario, directory, *arguments):
    return subprocess.run(
        [str(executable), scenario, str(directory), *(str(arg) for arg in arguments)],
        capture_output=True, text=True, timeout=20,
    )
