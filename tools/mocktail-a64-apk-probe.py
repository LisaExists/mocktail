#!/usr/bin/env python3
"""Extract ARM64 native libraries from APK(s) and feed them to the experimental Mocktail guest probe.

This is a native-library/runtime probe, not a full Android application launcher.
It does not emulate Android framework services, Activity lifecycle, graphics
surface ownership, or the complete Bionic system image.
"""
from __future__ import annotations

import argparse
import os
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROBE = REPO_ROOT / "build-arm-translation" / "mocktail_a64_guest_probe"
MAX_LIBRARY_SIZE = 512 * 1024 * 1024
MAX_TOTAL_LIBRARY_SIZE = 2 * 1024 * 1024 * 1024
MAX_LIBRARY_COUNT = 256


def is_aarch64_elf(data: bytes) -> bool:
    """Return whether bytes start with a little-endian ELF64 EM_AARCH64 header."""
    return (
        len(data) >= 20
        and data[:4] == b"\x7fELF"
        and data[4] == 2  # ELFCLASS64
        and data[5] == 1  # ELFDATA2LSB
        and struct.unpack_from("<H", data, 18)[0] == 183  # EM_AARCH64
    )


def _add_library(
    libraries: dict[str, tuple[bytes, str]],
    name: str,
    data: bytes,
    source: str,
    *,
    require_aarch64: bool,
) -> None:
    if not name.endswith(".so"):
        return
    if len(data) > MAX_LIBRARY_SIZE:
        raise ValueError(f"{source}: {name} exceeds the 512 MiB size limit")
    if not is_aarch64_elf(data):
        if require_aarch64:
            raise ValueError(
                f"{source}: {name} is under an arm64-v8a path but is not a "
                "little-endian ELF64 AArch64 image"
            )
        return
    previous = libraries.get(name)
    if previous:
        if previous[0] != data:
            raise ValueError(
                f"multiple different ARM64 libraries have basename {name!r} "
                f"({previous[1]} and {source}); the prototype linker requires "
                "unambiguous module names"
            )
        return
    if len(libraries) >= MAX_LIBRARY_COUNT:
        raise ValueError(
            f"more than {MAX_LIBRARY_COUNT} distinct libraries were found; "
            "trim the supplied APK/system library set"
        )
    total_size = sum(len(item[0]) for item in libraries.values()) + len(data)
    if total_size > MAX_TOTAL_LIBRARY_SIZE:
        raise ValueError("combined ARM64 library payload exceeds the 2 GiB limit")
    libraries[name] = (data, source)


def collect_apk_libraries(
    apk_paths: Iterable[Path],
    library_dirs: Iterable[Path],
) -> dict[str, tuple[bytes, str]]:
    libraries: dict[str, tuple[bytes, str]] = {}

    for apk_path in apk_paths:
        try:
            with zipfile.ZipFile(apk_path) as apk:
                candidates = [
                    info for info in apk.infolist()
                    if not info.is_dir()
                    and info.filename.endswith(".so")
                    and PurePosixPath(info.filename).parts[:2] == ("lib", "arm64-v8a")
                ]
                if not candidates:
                    # Do not silently mistake split APK bundles/APKS for an APK
                    # with no ARM64 native code.
                    names = apk.namelist()
                    nested_apks = [name for name in names if name.lower().endswith(".apk")]
                    if nested_apks and apk_path.suffix.lower() != ".apk":
                        raise ValueError(
                            f"{apk_path}: looks like an APK set/bundle containing "
                            "nested APKs; pass the extracted split APK files individually"
                        )
                    print(
                        f"warning: {apk_path} contains no lib/arm64-v8a/*.so entries",
                        file=sys.stderr,
                    )
                for info in candidates:
                    if info.file_size > MAX_LIBRARY_SIZE:
                        raise ValueError(
                            f"{apk_path}:{info.filename} exceeds the 512 MiB size limit"
                        )
                    data = apk.read(info)
                    _add_library(
                        libraries,
                        PurePosixPath(info.filename).name,
                        data,
                        f"{apk_path}:{info.filename}",
                        require_aarch64=True,
                    )
        except zipfile.BadZipFile as exc:
            raise ValueError(f"{apk_path} is not a valid ZIP/APK archive: {exc}") from exc
        except OSError as exc:
            raise ValueError(f"cannot read APK {apk_path}: {exc}") from exc

    for directory in library_dirs:
        if not directory.is_dir():
            raise ValueError(f"library directory does not exist: {directory}")
        found_any = False
        for path in sorted(directory.rglob("*.so")):
            if not path.is_file():
                continue
            found_any = True
            try:
                size = path.stat().st_size
                if size > MAX_LIBRARY_SIZE:
                    raise ValueError(f"{path} exceeds the 512 MiB size limit")
                data = path.read_bytes()
            except OSError as exc:
                raise ValueError(f"cannot read guest library {path}: {exc}") from exc
            _add_library(
                libraries, path.name, data, str(path), require_aarch64=False
            )
        if not found_any:
            print(f"warning: no .so files found under {directory}", file=sys.stderr)

    if not libraries:
        raise ValueError(
            "no AArch64 native libraries found; supply an APK with "
            "lib/arm64-v8a/*.so or an --library-dir containing ARM64 .so files"
        )
    return libraries


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Extract ARM64 shared objects from APKs and exercise Mocktail's "
            "experimental x86-64 AArch64 guest runtime."
        )
    )
    parser.add_argument("apks", nargs="+", type=Path, help="APK files (pass every split APK)")
    parser.add_argument(
        "--root",
        required=True,
        help="root library basename or APK member path, for example libroblox.so",
    )
    parser.add_argument(
        "--probe",
        type=Path,
        default=DEFAULT_PROBE,
        help=f"native probe executable (default: {DEFAULT_PROBE})",
    )
    parser.add_argument(
        "--library-dir",
        action="append",
        type=Path,
        default=[],
        help="additional directory of ARM64 system/dependency .so files (repeatable)",
    )
    parser.add_argument("--list-exports", action="store_true", help="list loaded ELF exports")
    parser.add_argument("--call", metavar="SYMBOL", help="explicitly execute an exported guest symbol")
    parser.add_argument(
        "--external-dependency",
        action="append",
        default=[],
        metavar="SONAME",
        help="allow an absent DT_NEEDED library (repeatable; does not provide its symbols)",
    )
    parser.add_argument("--run-initializers", action="store_true", help="run guest constructors before --call")
    parser.add_argument("--budget", type=int, help="instruction budget for --call")
    parser.add_argument("--memory-mib", type=int, default=1024, help="guest memory limit (16-16384 MiB)")
    for index in range(8):
        parser.add_argument(
            f"--arg{index}",
            help=f"integer value for guest register X{index} (decimal or 0x-prefixed hex)",
        )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.probe.is_file() or not os.access(args.probe, os.X_OK):
        print(
            f"error: guest probe is not executable: {args.probe}\n"
            "Build it with -DMOCKTAIL_ENABLE_ROBLOX_ARM_TRANSLATION=ON.",
            file=sys.stderr,
        )
        return 2
    if args.budget is not None and args.budget <= 0:
        print("error: --budget must be greater than zero", file=sys.stderr)
        return 2
    if not 16 <= args.memory_mib <= 16384:
        print("error: --memory-mib must be between 16 and 16384", file=sys.stderr)
        return 2
    if args.run_initializers and not args.call:
        print("error: --run-initializers requires --call", file=sys.stderr)
        return 2
    for soname in args.external_dependency:
        if (
            len(soname) < 4
            or PurePosixPath(soname).name != soname
            or not soname.endswith(".so")
        ):
            print(
                f"error: invalid --external-dependency SONAME: {soname!r}",
                file=sys.stderr,
            )
            return 2
    if any(getattr(args, f"arg{i}") is not None for i in range(8)) and not args.call:
        print("error: --arg0 through --arg7 require --call", file=sys.stderr)
        return 2

    try:
        libraries = collect_apk_libraries(args.apks, args.library_dir)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    root_name = PurePosixPath(args.root).name
    if root_name not in libraries:
        available = ", ".join(sorted(libraries))
        print(
            f"error: root library {root_name!r} was not found. "
            f"Available modules: {available}",
            file=sys.stderr,
        )
        return 2

    with tempfile.TemporaryDirectory(prefix="mocktail-a64-apk-probe-") as directory:
        extracted: list[str] = []
        for name, (data, _source) in sorted(libraries.items()):
            path = Path(directory) / name
            path.write_bytes(data)
            extracted.append(str(path))

        command = [str(args.probe), "--root", root_name,
                   "--memory-mib", str(args.memory_mib)]
        for soname in args.external_dependency:
            command.extend(["--external-dependency", soname])
        if args.list_exports:
            command.append("--list-exports")
        if args.call:
            command.extend(["--call", args.call])
        if args.run_initializers:
            command.append("--run-initializers")
        if args.budget is not None:
            command.extend(["--budget", str(args.budget)])
        for index in range(8):
            value = getattr(args, f"arg{index}")
            if value is not None:
                command.extend([f"--arg{index}", value])
        command.extend(extracted)

        print(
            f"Prepared {len(extracted)} ARM64 library/libraries; root={root_name}.",
            file=sys.stderr,
        )
        print(
            "Note: APK contents do not include the complete Android system image. "
            "A failed load may identify missing Bionic/platform dependencies or "
            "unsupported relocations; this is expected during prototype bring-up.",
            file=sys.stderr,
        )
        try:
            return subprocess.run(command, check=False).returncode
        except OSError as exc:
            print(f"error: could not start guest probe: {exc}", file=sys.stderr)
            return 2


if __name__ == "__main__":
    raise SystemExit(main())
