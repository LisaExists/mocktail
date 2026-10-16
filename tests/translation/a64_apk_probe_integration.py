#!/usr/bin/env python3
"""Exercise APK -> extracted AArch64 ELF -> Dynarmic, including Android APS2 ELF."""
from __future__ import annotations

import io
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


def run_probe(command: list[str], expected: tuple[str, ...], label: str) -> bool:
    try:
        completed = subprocess.run(
            command, check=False, capture_output=True, text=True, timeout=30
        )
    except subprocess.TimeoutExpired:
        print(f"[FAIL] {label}: guest probe exceeded the 30-second test limit", file=sys.stderr)
        return False
    output = completed.stdout + completed.stderr
    if completed.returncode != 0:
        print(output, file=sys.stderr, end="" if output.endswith("\n") else "\n")
        print(f"[FAIL] {label}: probe returned {completed.returncode}", file=sys.stderr)
        return False
    missing = [fragment for fragment in expected if fragment not in output]
    if missing:
        print(output, file=sys.stderr, end="" if output.endswith("\n") else "\n")
        print(f"[FAIL] {label}: output missing markers {missing}", file=sys.stderr)
        return False
    print(f"[PASS] {label}")
    return True


def main() -> int:
    if len(sys.argv) not in (5, 6, 7):
        print(
            "usage: a64_apk_probe_integration.py PROBE ROOT_ELF DEP_ELF WRAPPER "
            "[ANDROID_STYLE_ELF [ANDROID_JNI_ELF]]",
            file=sys.stderr,
        )
        return 2

    probe = Path(sys.argv[1]).resolve()
    root_elf = Path(sys.argv[2]).resolve()
    dependency_elf = Path(sys.argv[3]).resolve()
    wrapper = Path(sys.argv[4]).resolve()
    android_style_elf = Path(sys.argv[5]).resolve() if len(sys.argv) >= 6 else None
    android_jni_elf = Path(sys.argv[6]).resolve() if len(sys.argv) >= 7 else None

    inputs = [probe, root_elf, dependency_elf, wrapper]
    if android_style_elf is not None:
        inputs.append(android_style_elf)
    if android_jni_elf is not None:
        inputs.append(android_jni_elf)
    for path in inputs:
        if not path.is_file():
            print(f"required probe fixture does not exist: {path}", file=sys.stderr)
            return 2

    ok = True
    with tempfile.TemporaryDirectory(prefix="mocktail-a64-apk-integration-") as temp:
        temp_dir = Path(temp)
        # These are genuine linker-produced AArch64 ELFs. The root's DT_NEEDED
        # edge resolves to the second library extracted from the same APK.
        apk_path = temp_dir / "synthetic-arm64-client.apk"
        with zipfile.ZipFile(apk_path, "w", compression=zipfile.ZIP_DEFLATED) as apk:
            apk.write(root_elf, f"lib/arm64-v8a/{root_elf.name}")
            apk.write(dependency_elf, f"lib/arm64-v8a/{dependency_elf.name}")

        command = [
            sys.executable, str(wrapper),
            "--probe", str(probe),
            "--root", root_elf.name,
            "--call", "guest_exported_entry",
            "--arg0", "41",
            "--budget", "10000",
            str(apk_path),
        ]
        # Keep the command vector assembled from separate argv elements. This
        # integration intentionally does not involve a shell.
        ok &= run_probe(
            command,
            ("Prepared 2 ARM64 library/libraries", "X0=0x2a", "42"),
            "synthetic APK extracted both real AArch64 libraries and ran the dependency-linked guest function",
        )

        # Also use the delivery format produced by bundletool: an .apks archive
        # that contains nested split APKs. Put the root and dependency in
        # different splits to verify the extracted closure is linked end-to-end.
        def make_split(entries: list[tuple[str, Path]]) -> bytes:
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as split:
                for member, source in entries:
                    split.write(source, member)
            return stream.getvalue()

        split_set = temp_dir / "synthetic-arm64-client.apks"
        with zipfile.ZipFile(split_set, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            bundle.writestr(
                "splits/base-master.apk",
                make_split([(f"lib/arm64-v8a/{root_elf.name}", root_elf)]),
            )
            bundle.writestr(
                "splits/config.arm64_v8a.apk",
                make_split([(f"lib/arm64-v8a/{dependency_elf.name}", dependency_elf)]),
            )

        apks_command = [
            sys.executable, str(wrapper),
            "--probe", str(probe),
            "--root", root_elf.name,
            "--call", "guest_exported_entry",
            "--arg0", "41",
            "--budget", "10000",
            str(split_set),
        ]
        ok &= run_probe(
            apks_command,
            ("Prepared 2 ARM64 library/libraries", "X0=0x2a", "42"),
            "APKS split set extracted root/dependency libraries and executed through Dynarmic",
        )

        if android_style_elf is not None:
            android_apk = temp_dir / "synthetic-android-linker.apk"
            with zipfile.ZipFile(
                android_apk, "w", compression=zipfile.ZIP_DEFLATED
            ) as apk:
                apk.write(
                    android_style_elf,
                    f"lib/arm64-v8a/{android_style_elf.name}",
                )
            android_command = [
                sys.executable, str(wrapper),
                "--probe", str(probe),
                "--root", android_style_elf.name,
                "--call", "guest_android_abi_smoke",
                "--arg0", "1",
                "--budget", "10000",
                str(android_apk),
            ]
            ok &= run_probe(
                android_command,
                ("Prepared 1 ARM64 library/libraries", "X0=0x2a", "42"),
                "Android-targeted APS2/RELR ELF extracted from an APK and executed on x86-64",
            )

        if android_jni_elf is not None:
            jni_apk = temp_dir / "synthetic-android-jni.apk"
            with zipfile.ZipFile(
                jni_apk, "w", compression=zipfile.ZIP_DEFLATED
            ) as apk:
                apk.write(android_jni_elf, f"lib/arm64-v8a/{android_jni_elf.name}")
            jni_command = [
                sys.executable, str(wrapper),
                "--probe", str(probe),
                "--root", android_jni_elf.name,
                "--jni-onload",
                "--java-class", "com/mocktail/Smoke",
                "--budget", "10000",
                str(jni_apk),
            ]
            ok &= run_probe(
                jni_command,
                (
                    "Prepared 1 ARM64 library/libraries",
                    "JNI_OnLoad returned X0=0x10006",
                    "Registered native methods: 1",
                    "com/mocktail/Smoke.nativeSum(II)I",
                ),
                "Android JNI_OnLoad executed from an APK and registered a guest native method",
            )

            native_command = [
                sys.executable, str(wrapper),
                "--probe", str(probe),
                "--root", android_jni_elf.name,
                "--call-native", "com/mocktail/Smoke", "nativeSum", "(II)I",
                "--arg0", "20", "--arg1", "22",
                "--budget", "10000",
                str(jni_apk),
            ]
            ok &= run_probe(
                native_command,
                (
                    "JNI_OnLoad returned X0=0x10006",
                    "Guest JNI native com/mocktail/Smoke.nativeSum(II)I returned X0=0x2a (42)",
                ),
                "registered JNI native invoked from an APK with AArch64 ABI arguments",
            )

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
