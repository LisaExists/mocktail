#!/usr/bin/env python3
"""End-to-end synthetic APK -> extracted ARM64 ELF -> Dynarmic guest call test."""
from __future__ import annotations

import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 5:
        print(
            "usage: a64_apk_probe_integration.py PROBE ROOT_ELF DEP_ELF WRAPPER",
            file=sys.stderr,
        )
        return 2

    probe = Path(sys.argv[1]).resolve()
    root_elf = Path(sys.argv[2]).resolve()
    dependency_elf = Path(sys.argv[3]).resolve()
    wrapper = Path(sys.argv[4]).resolve()

    for path in (probe, root_elf, dependency_elf, wrapper):
        if not path.is_file():
            print(f"required probe fixture does not exist: {path}", file=sys.stderr)
            return 2

    # This APK deliberately contains actual cross-compiled AArch64 ELF fixtures,
    # not fabricated ELF headers. The root's DT_NEEDED edge resolves against the
    # dependency extracted from the same APK just as packaged native libraries do.
    with tempfile.TemporaryDirectory(prefix="mocktail-a64-apk-integration-") as temp:
        apk_path = Path(temp) / "synthetic-arm64-client.apk"
        with zipfile.ZipFile(apk_path, "w", compression=zipfile.ZIP_DEFLATED) as apk:
            apk.write(root_elf, f"lib/arm64-v8a/{root_elf.name}")
            apk.write(dependency_elf, f"lib/arm64-v8a/{dependency_elf.name}")

        command = [
            sys.executable,
            str(wrapper),
            "--probe",
            str(probe),
            "--root",
            root_elf.name,
            "--call",
            "guest_exported_entry",
            "--arg0",
            "41",
            "--budget",
            "10000",
            str(apk_path),
        ]
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = completed.stdout + completed.stderr
        if completed.returncode != 0:
            print(output, file=sys.stderr, end="" if output.endswith("\n") else "\n")
            print(
                f"APK probe returned exit status {completed.returncode}",
                file=sys.stderr,
            )
            return 1
        expected = ("Prepared 2 ARM64 library/libraries", "X0=0x2a", "42")
        missing = [fragment for fragment in expected if fragment not in output]
        if missing:
            print(output, file=sys.stderr, end="" if output.endswith("\n") else "\n")
            print(f"APK probe output missing expected markers: {missing}", file=sys.stderr)
            return 1

        print("[PASS] synthetic APK was extracted and both AArch64 modules were loaded")
        print("[PASS] guest_exported_entry executed through Dynarmic and returned 42")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
