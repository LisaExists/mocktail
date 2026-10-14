#!/usr/bin/env python3
"""Inspect Android APK native ABIs before attempting cross-architecture work.

Diagnostic only: this tool does not install, patch, re-sign, or execute an APK.
It uses only Python's standard library.
"""
from __future__ import annotations

import argparse
import os
import platform
import shutil
import struct
import sys
import zipfile
from pathlib import PurePosixPath
from typing import Iterable

ELF_MACHINES = {
    3: "x86",
    40: "ARM (32-bit)",
    62: "x86_64",
    183: "AArch64",
    243: "RISC-V",
}
ABI_TO_MACHINE = {
    "armeabi": 40,
    "armeabi-v7a": 40,
    "arm64-v8a": 183,
    "x86": 3,
    "x86_64": 62,
    "riscv64": 243,
}
TOOLS = (
    "qemu-aarch64",
    "qemu-aarch64-static",
    "adb",
    "apksigner",
    "aapt",
    "apkanalyzer",
    "llvm-readelf",
    "readelf",
    "llvm-objdump",
    "objdump",
)


def read_elf_machine(data: bytes) -> tuple[str, int | None, str | None]:
    """Return (ELF class, e_machine, error) for an ELF byte buffer."""
    if len(data) < 20 or data[:4] != b"\x7fELF":
        return "not ELF", None, "missing or truncated ELF header"
    elf_class = {1: "ELF32", 2: "ELF64"}.get(data[4], f"unknown class {data[4]}")
    if data[5] == 1:
        endian = "<"
    elif data[5] == 2:
        endian = ">"
    else:
        return elf_class, None, f"unknown ELF byte order {data[5]}"
    try:
        machine = struct.unpack_from(endian + "H", data, 18)[0]
    except struct.error:
        return elf_class, None, "truncated ELF machine field"
    return elf_class, machine, None


def host_arch() -> str:
    machine = platform.machine().lower()
    if machine in {"amd64", "x86_64"}:
        return "x86_64"
    if machine in {"aarch64", "arm64"}:
        return "AArch64"
    return machine or "unknown"


def print_host_summary() -> None:
    print("Host")
    print(f"  OS:           {platform.system()} {platform.release()}")
    print(f"  Architecture: {host_arch()}")
    print("  Tools:")
    for name in TOOLS:
        path = shutil.which(name)
        print(f"    {name:<20} {path if path else 'not found'}")
    print()


def inspect_apk(apk_path: str) -> bool:
    path = os.path.abspath(os.path.expanduser(apk_path))
    print(f"APK: {path}")
    if not os.path.isfile(path):
        print("  ERROR: file does not exist")
        print()
        return False
    if not zipfile.is_zipfile(path):
        print("  ERROR: not a ZIP/APK archive")
        print()
        return False

    try:
        with zipfile.ZipFile(path) as apk:
            names = apk.namelist()
            names_set = set(names)
            native_paths = sorted(
                n for n in names
                if n.startswith("lib/")
                and n.lower().endswith(".so")
                and len(PurePosixPath(n).parts) >= 3
            )
            print(f"  Size:         {os.path.getsize(path):,} bytes")
            print(f"  Entries:      {len(names):,}")
            print(f"  Manifest:     {'present' if 'AndroidManifest.xml' in names_set else 'not found'}")
            dex_count = sum(1 for n in names if n.endswith(".dex") and "/" not in n)
            print(f"  DEX files:    {dex_count}")

            if not native_paths:
                nested_apks = sorted(
                    n for n in names if n.lower().endswith(".apk") and not n.startswith("/")
                )
                if nested_apks:
                    print("  Native code:  this appears to be an APK set/bundle; inspect its contained APK files separately.")
                    for name in nested_apks:
                        print(f"    nested APK: {name}")
                else:
                    print("  Native code:  no lib/<abi>/*.so entries found")
                    print("  ABI result:   cannot infer native ABI from this APK alone")
            else:
                abis: dict[str, list[str]] = {}
                mismatches: list[str] = []
                for member in native_paths:
                    parts = PurePosixPath(member).parts
                    abi = parts[1]
                    abis.setdefault(abi, []).append(member)
                    expected = ABI_TO_MACHINE.get(abi)
                    with apk.open(member) as stream:
                        header = stream.read(64)
                    elf_class, machine, error = read_elf_machine(header)
                    machine_name = (
                        ELF_MACHINES.get(machine, f"unknown e_machine={machine}")
                        if machine is not None else "unknown"
                    )
                    if error:
                        status = f"INVALID ({error})"
                        mismatches.append(f"{member}: {error}")
                    elif expected is not None and machine != expected:
                        status = (
                            f"MISMATCH: directory expects "
                            f"{ELF_MACHINES.get(expected, expected)}, ELF says {machine_name}"
                        )
                        mismatches.append(f"{member}: {status}")
                    else:
                        status = f"{elf_class}, {machine_name}"
                    print(f"  ELF:          {member}")
                    print(f"                {status}")

                print("  ABI summary:")
                for abi, members in sorted(abis.items()):
                    expected = ABI_TO_MACHINE.get(abi)
                    note = f" (expected {ELF_MACHINES.get(expected, expected)})" if expected else " (unknown ABI label)"
                    print(f"    {abi:<16} {len(members):>3} native library/libraries{note}")
                host = host_arch()
                if host == "x86_64":
                    if "x86_64" in abis:
                        print("  Host fit:      APK includes x86_64 native libraries; architecture alone may not block loading.")
                    elif "arm64-v8a" in abis:
                        print("  Host fit:      ARM64-only native payload on x86_64 host; guest instruction translation and ABI bridging are required.")
                    else:
                        print("  Host fit:      no x86_64 native payload detected; inspect ABI list above.")
                elif host == "AArch64":
                    print("  Host fit:      AArch64 host; ARM64 native libraries may match the machine architecture.")
                else:
                    print("  Host fit:      host architecture needs manual compatibility review.")
                if mismatches:
                    print("  ELF warnings:")
                    for message in mismatches:
                        print(f"    - {message}")

            signing_meta = [
                n for n in names
                if n.startswith("META-INF/")
                and n.upper().endswith((".RSA", ".DSA", ".EC", ".SF"))
            ]
            print(f"  META-INF v1 signing files: {len(signing_meta)} (this does not determine APK v2/v3/v4 signing status)")
            print("  Note: static inspection only; it does not validate APK signing or whether an app will run.")
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        print(f"  ERROR: failed to inspect archive: {exc}")
        print()
        return False
    print()
    return True


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "apk",
        nargs="*",
        help="one or more APK files to inspect (including split APKs individually)",
    )
    args = parser.parse_args(argv)
    print_host_summary()
    if not args.apk:
        print("No APK supplied. Example: python tools/arm64-x86-preflight.py ~/Downloads/Delta.apk")
        return 0
    results = [inspect_apk(item) for item in args.apk]
    return 0 if all(results) else 2


if __name__ == "__main__":
    sys.exit(main())
