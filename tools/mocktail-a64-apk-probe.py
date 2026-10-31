#!/usr/bin/env python3
"""Extract ARM64 native libraries from APK(s) and feed them to the experimental Mocktail guest probe.

This is a native-library/runtime probe, not a full Android application launcher.
It does not emulate Android framework services, Activity lifecycle, graphics
surface ownership, or the complete Bionic system image.
"""
from __future__ import annotations

import argparse
import io
import hashlib
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
MAX_NESTED_APK_SIZE = 512 * 1024 * 1024
MAX_APK_SET_SIZE = 2 * 1024 * 1024 * 1024
MAX_APK_ASSET_ENTRY_SIZE = 64 * 1024 * 1024
MAX_APK_ASSET_TOTAL_SIZE = 2 * 1024 * 1024 * 1024

MAX_DEX_BYTES = 256 * 1024 * 1024
MAX_DEX_TYPES = 250_000
MAX_DEX_STRING_BYTES = 4096
SUPPORTED_DEX_VERSIONS = {
    b"035", b"037", b"038", b"039", b"040", b"041",
}


def _read_uleb128(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    for shift in range(0, 35, 7):
        if offset >= len(data):
            raise ValueError("truncated DEX ULEB128 value")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            if value > 0xFFFFFFFF:
                raise ValueError("DEX ULEB128 value exceeds 32-bit range")
            return value, offset
    raise ValueError("DEX ULEB128 value exceeds five bytes")


def _parse_dex_logical_classes(
    data: bytes, header_offset: int, container_size: int, header_size: int
) -> set[str]:
    """Parse one DEX logical file whose table offsets are absolute container offsets."""
    file_size = struct.unpack_from("<I", data, header_offset + 32)[0]
    if (
        file_size < header_size
        or header_offset > container_size
        or file_size > container_size - header_offset
    ):
        raise ValueError("invalid DEX logical file size")

    string_count, string_offset = struct.unpack_from(
        "<II", data, header_offset + 56
    )
    type_count, type_offset = struct.unpack_from(
        "<II", data, header_offset + 64
    )
    if string_count > MAX_DEX_TYPES or type_count > MAX_DEX_TYPES:
        raise ValueError("DEX string/type table exceeds the 250000 entry limit")

    def table_bounds(offset: int, count: int, item_size: int, label: str) -> None:
        if count == 0:
            return
        if (
            offset < header_offset + header_size
            or offset > container_size
            or count > (container_size - offset) // item_size
        ):
            raise ValueError(f"DEX {label} table is outside the container")

    table_bounds(string_offset, string_count, 4, "string identifier")
    table_bounds(type_offset, type_count, 4, "type identifier")
    string_data_offsets = [
        struct.unpack_from("<I", data, string_offset + index * 4)[0]
        for index in range(string_count)
    ]

    class_names: set[str] = set()
    for index in range(type_count):
        descriptor_index = struct.unpack_from(
            "<I", data, type_offset + index * 4
        )[0]
        if descriptor_index >= string_count:
            raise ValueError("DEX type descriptor index is outside string table")
        cursor = string_data_offsets[descriptor_index]
        if cursor < header_offset + header_size or cursor >= container_size:
            raise ValueError("DEX string data offset is outside the container")
        _utf16_length, cursor = _read_uleb128(data, cursor)
        end = data.find(
            b"\0", cursor,
            min(container_size, cursor + MAX_DEX_STRING_BYTES + 1),
        )
        if end < 0:
            raise ValueError("DEX descriptor string is unterminated or exceeds 4096 bytes")
        encoded = data[cursor:end]
        if not encoded or len(encoded) > MAX_DEX_STRING_BYTES:
            raise ValueError("DEX descriptor string is empty or too long")
        try:
            descriptor = encoded.decode("ascii")
        except UnicodeDecodeError:
            # JNI class names can technically contain Unicode. Skip those
            # uncommon names rather than mis-decoding modified UTF-8.
            continue
        if descriptor.startswith("L") and descriptor.endswith(";") and len(descriptor) > 2:
            name = descriptor[1:-1]
            if (
                not name.startswith("/")
                and not name.endswith("/")
                and "//" not in name
                and not any(character in name for character in (".", ";", "[", "]", "\0"))
            ):
                class_names.add(name)
    return class_names


def parse_dex_class_names(data: bytes) -> list[str]:
    """Extract Java class names from bounded DEX tables, including DEX 041 containers.

    Only headers, string/type identifier tables, and descriptor strings are
    read. Bytecode is never parsed or executed.
    """
    if len(data) < 112 or data[:4] != b"dex\n":
        raise ValueError("missing or truncated DEX header")
    if data[7] != 0:
        raise ValueError("invalid DEX magic terminator")
    version = data[4:7]
    if version not in SUPPORTED_DEX_VERSIONS:
        raise ValueError("unsupported DEX version/magic")

    if version != b"041":
        if len(data) < 112:
            raise ValueError("missing or truncated DEX header")
        file_size, header_size, endian_tag = struct.unpack_from("<III", data, 32)
        if header_size != 112:
            raise ValueError("invalid DEX header size")
        if file_size < header_size or file_size > len(data):
            raise ValueError("invalid DEX file/header size")
        if endian_tag != 0x12345678:
            raise ValueError("unsupported DEX endianness")
        return sorted(_parse_dex_logical_classes(data, 0, file_size, header_size))

    # DEX 041 uses a container header (120 bytes) and absolute offsets that may
    # refer to data shared by this or later logical DEX files in the container.
    # Walk each logical header using file_size, validating its location and
    # container_size rather than treating the container as a v039-style file.
    if len(data) < 120:
        raise ValueError("truncated DEX 041 container header")
    _logical_size, header_size, endian_tag = struct.unpack_from("<III", data, 32)
    container_size, first_header_offset = struct.unpack_from("<II", data, 112)
    if header_size != 120 or endian_tag != 0x12345678:
        raise ValueError("invalid DEX 041 header size or endianness")
    if (
        container_size < header_size
        or container_size > len(data)
        or first_header_offset != 0
    ):
        raise ValueError("invalid DEX 041 container size or first header offset")

    class_names: set[str] = set()
    header_offset = 0
    logical_file_count = 0
    while header_offset < container_size:
        if logical_file_count >= MAX_DEX_TYPES:
            raise ValueError("DEX 041 container has too many logical files")
        if container_size - header_offset < 120:
            raise ValueError("truncated DEX 041 logical header")
        if data[header_offset:header_offset + 8] != b"dex\n041\0":
            raise ValueError("invalid DEX 041 logical header in container")
        file_size, logical_header_size, logical_endian = struct.unpack_from(
            "<III", data, header_offset + 32
        )
        logical_container_size, recorded_header_offset = struct.unpack_from(
            "<II", data, header_offset + 112
        )
        if (
            logical_header_size != 120
            or logical_endian != 0x12345678
            or logical_container_size != container_size
            or recorded_header_offset != header_offset
            or file_size < 120
            or file_size > container_size - header_offset
        ):
            raise ValueError("invalid DEX 041 logical-file bounds")
        class_names.update(
            _parse_dex_logical_classes(data, header_offset, container_size, 120)
        )
        if len(class_names) > MAX_DEX_TYPES:
            raise ValueError("DEX container exceeds 250000 unique classes")
        header_offset += file_size
        logical_file_count += 1
    if header_offset != container_size or logical_file_count == 0:
        raise ValueError("DEX 041 logical files do not fill the container")
    return sorted(class_names)


def _is_root_dex_member(name: str) -> bool:
    if "/" in name or "\\" in name:
        return False
    if name == "classes.dex":
        return True
    if name.startswith("classes") and name.endswith(".dex"):
        suffix = name[len("classes"):-len(".dex")]
        return bool(suffix) and suffix.isdigit() and int(suffix) >= 2
    return False


def _collect_dex_from_archive(
    archive: zipfile.ZipFile, label: str, classes: set[str], warnings: list[str]
) -> None:
    for info in archive.infolist():
        if info.is_dir() or not _is_root_dex_member(info.filename):
            continue
        if info.file_size > MAX_DEX_BYTES:
            warnings.append(f"{label}:{info.filename}: DEX exceeds 256 MiB; skipped")
            continue
        try:
            data = archive.read(info)
            classes.update(parse_dex_class_names(data))
        except (OSError, RuntimeError, zipfile.BadZipFile, ValueError) as exc:
            warnings.append(f"{label}:{info.filename}: cannot inspect DEX: {exc}")
        if len(classes) > MAX_DEX_TYPES:
            warnings.append("APK DEX type catalogue exceeds 250000 unique classes; further DEX entries skipped")
            return


def collect_apk_java_classes(apk_paths: Iterable[Path]) -> tuple[list[str], list[str]]:
    """Collect class names from APK/APKS DEX metadata for JNI FindClass seeding."""
    classes: set[str] = set()
    warnings: list[str] = []
    for apk_path in apk_paths:
        try:
            with zipfile.ZipFile(apk_path) as archive:
                if apk_path.suffix.lower() != ".apks":
                    _collect_dex_from_archive(archive, str(apk_path), classes, warnings)
                    continue
                nested_apks = [
                    info for info in archive.infolist()
                    if not info.is_dir() and info.filename.lower().endswith(".apk")
                ]
                if not nested_apks:
                    warnings.append(f"{apk_path}: APK set contains no nested APK files")
                    continue
                nested_total = sum(info.file_size for info in nested_apks)
                if nested_total > MAX_APK_SET_SIZE:
                    warnings.append(f"{apk_path}: expanded APK set exceeds 2 GiB; DEX class discovery skipped")
                    continue
                for info in nested_apks:
                    if info.file_size > MAX_NESTED_APK_SIZE:
                        warnings.append(f"{apk_path}:{info.filename}: split APK exceeds 512 MiB; skipped")
                        continue
                    try:
                        nested_data = archive.read(info)
                        with zipfile.ZipFile(io.BytesIO(nested_data)) as split:
                            _collect_dex_from_archive(
                                split, f"{apk_path}:{info.filename}", classes, warnings
                            )
                    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                        warnings.append(f"{apk_path}:{info.filename}: cannot inspect split DEX: {exc}")
                    if len(classes) > MAX_DEX_TYPES:
                        break
        except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
            warnings.append(f"{apk_path}: cannot inspect DEX metadata: {exc}")
    if len(classes) > MAX_DEX_TYPES:
        classes = set(sorted(classes)[:MAX_DEX_TYPES])
    return sorted(classes), warnings


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


def _collect_archive_libraries(
    apk: zipfile.ZipFile,
    label: str,
    libraries: dict[str, tuple[bytes, str]],
) -> bool:
    """Collect ARM64 library entries from one APK ZIP. Return whether any were found."""
    candidates = [
        info for info in apk.infolist()
        if not info.is_dir()
        and info.filename.endswith(".so")
        and PurePosixPath(info.filename).parts[:2] == ("lib", "arm64-v8a")
    ]
    for info in candidates:
        if info.file_size > MAX_LIBRARY_SIZE:
            raise ValueError(
                f"{label}:{info.filename} exceeds the 512 MiB size limit"
            )
        data = apk.read(info)
        _add_library(
            libraries,
            PurePosixPath(info.filename).name,
            data,
            f"{label}:{info.filename}",
            require_aarch64=True,
        )
    return bool(candidates)



def extract_apk_assets(apk_paths: Iterable[Path], output_root: Path) -> int:
    """Safely extract APK assets into a directory for the guest AAssetManager."""
    output_root.mkdir(parents=True, exist_ok=True)
    seen: dict[str, tuple[int, str]] = {}
    total_bytes = 0

    def extract_archive(archive: zipfile.ZipFile, label: str) -> None:
        nonlocal total_bytes
        for info in archive.infolist():
            if info.is_dir() or not info.filename.startswith("assets/"):
                continue
            name = info.filename[len("assets/"):]
            relative = PurePosixPath(name)
            mode = (info.external_attr >> 16) & 0o170000
            if (
                not name or relative.is_absolute()
                or "\\" in name
                or any(part in ("", ".", "..") for part in relative.parts)
                or mode == 0o120000
            ):
                raise ValueError(f"{label}:{info.filename}: unsafe APK asset path")
            if info.file_size > MAX_APK_ASSET_ENTRY_SIZE:
                raise ValueError(
                    f"{label}:{info.filename}: asset exceeds the 64 MiB limit"
                )
            data = archive.read(info)
            digest = hashlib.sha256(data).hexdigest()
            previous = seen.get(name)
            if previous is not None:
                if previous != (len(data), digest):
                    raise ValueError(
                        f"conflicting APK asset with duplicate path {name!r}"
                    )
                continue
            if total_bytes > MAX_APK_ASSET_TOTAL_SIZE - len(data):
                raise ValueError("expanded APK assets exceed the 2 GiB safety limit")
            destination = output_root.joinpath(*relative.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            seen[name] = (len(data), digest)
            total_bytes += len(data)

    for apk_path in apk_paths:
        try:
            with zipfile.ZipFile(apk_path) as archive:
                if apk_path.suffix.lower() != ".apks":
                    extract_archive(archive, str(apk_path))
                    continue
                nested_apks = [
                    info for info in archive.infolist()
                    if not info.is_dir() and info.filename.lower().endswith(".apk")
                ]
                nested_total = sum(info.file_size for info in nested_apks)
                if nested_total > MAX_APK_SET_SIZE:
                    raise ValueError(
                        f"{apk_path}: expanded APK set exceeds the 2 GiB safety limit"
                    )
                for info in nested_apks:
                    if info.file_size > MAX_NESTED_APK_SIZE:
                        raise ValueError(
                            f"{apk_path}:{info.filename}: split exceeds 512 MiB"
                        )
                    nested_data = archive.read(info)
                    with zipfile.ZipFile(io.BytesIO(nested_data)) as split:
                        extract_archive(split, f"{apk_path}:{info.filename}")
        except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
            raise ValueError(f"{apk_path}: cannot extract APK assets: {exc}") from exc

    return len(seen)


def collect_apk_libraries(
    apk_paths: Iterable[Path],
    library_dirs: Iterable[Path],
) -> dict[str, tuple[bytes, str]]:
    libraries: dict[str, tuple[bytes, str]] = {}

    for apk_path in apk_paths:
        try:
            with zipfile.ZipFile(apk_path) as archive:
                if apk_path.suffix.lower() == ".apks":
                    nested_apks = [
                        info for info in archive.infolist()
                        if not info.is_dir() and info.filename.lower().endswith(".apk")
                    ]
                    if not nested_apks:
                        raise ValueError(
                            f"{apk_path}: APK-set archive contains no nested .apk files"
                        )
                    nested_total = sum(info.file_size for info in nested_apks)
                    if nested_total > MAX_APK_SET_SIZE:
                        raise ValueError(
                            f"{apk_path}: expanded APK set exceeds the 2 GiB safety limit"
                        )
                    for info in nested_apks:
                        if info.file_size > MAX_NESTED_APK_SIZE:
                            raise ValueError(
                                f"{apk_path}:{info.filename} exceeds the 512 MiB "
                                "per-split size limit"
                            )
                        nested_data = archive.read(info)
                        try:
                            with zipfile.ZipFile(io.BytesIO(nested_data)) as split:
                                _collect_archive_libraries(
                                    split, f"{apk_path}:{info.filename}", libraries
                                )
                        except zipfile.BadZipFile as exc:
                            raise ValueError(
                                f"{apk_path}:{info.filename} is not a valid nested APK: {exc}"
                            ) from exc
                else:
                    if not _collect_archive_libraries(archive, str(apk_path), libraries):
                        names = archive.namelist()
                        nested_apks = [
                            name for name in names if name.lower().endswith(".apk")
                        ]
                        if nested_apks:
                            print(
                                f"warning: {apk_path} appears to be a ZIP/APK set; "
                                "rename it to .apks or pass its split APK files "
                                "individually to inspect nested ARM64 libraries",
                                file=sys.stderr,
                            )
                        else:
                            print(
                                f"warning: {apk_path} contains no "
                                "lib/arm64-v8a/*.so entries",
                                file=sys.stderr,
                            )
        except zipfile.BadZipFile as exc:
            raise ValueError(f"{apk_path} is not a valid ZIP/APK archive: {exc}") from exc
        except (OSError, RuntimeError) as exc:
            raise ValueError(f"cannot read APK archive {apk_path}: {exc}") from exc

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
            "no AArch64 native libraries found; supply an APK/APKS file with "
            "lib/arm64-v8a/*.so entries or an --library-dir containing ARM64 .so files"
        )
    return libraries


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Extract ARM64 shared objects from APKs and exercise Mocktail's "
            "experimental x86-64 AArch64 guest runtime."
        )
    )
    parser.add_argument("apks", nargs="*", type=Path, help="APK files, an .apks split set, or individual split APKs")
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
        "--call-native",
        nargs=3,
        metavar=("CLASS", "NAME", "SIGNATURE"),
        help="run JNI_OnLoad then invoke an exact registered static native method",
    )
    parser.add_argument(
        "--jni-onload",
        action="store_true",
        help="call JNI_OnLoad with a guest JavaVM/JNIEnv bridge",
    )
    parser.add_argument(
        "--java-class",
        action="append",
        default=[],
        metavar="NAME",
        help="class available to JNI FindClass when using --jni-onload/--call-native (repeatable)",
    )
    parser.add_argument(
        "--external-dependency",
        action="append",
        default=[],
        metavar="SONAME",
        help="allow an absent DT_NEEDED library (repeatable; does not provide its symbols)",
    )
    parser.add_argument("--run-initializers", action="store_true", help="run guest constructors before the requested entrypoint")
    parser.add_argument("--budget", type=int, help="instruction budget for guest entrypoint execution")
    parser.add_argument("--memory-mib", type=int, default=1024, help="guest memory limit (16-16384 MiB)")
    for index in range(262):
        parser.add_argument(
            f"--arg{index}",
            help=(
                f"integer/raw value for guest argument {index} "
                "(--call: X0-X7 only; --call-native: Java arguments 0-261)"
            ),
        )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.apks and not args.library_dir:
        print("error: supply at least one APK/APKS file or --library-dir", file=sys.stderr)
        return 2
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
    if args.call and args.call_native:
        print("error: --call and --call-native are mutually exclusive", file=sys.stderr)
        return 2
    if args.jni_onload and (args.call or args.call_native):
        print("error: --jni-onload cannot be combined with --call or --call-native", file=sys.stderr)
        return 2
    if args.java_class and not (args.jni_onload or args.call_native):
        print("error: --java-class requires --jni-onload or --call-native", file=sys.stderr)
        return 2
    if args.run_initializers and not (args.call or args.jni_onload or args.call_native):
        print("error: --run-initializers requires an entrypoint option", file=sys.stderr)
        return 2
    if args.call_native:
        native_class, native_name, native_signature = args.call_native
        if (
            not native_class or not native_name or not native_signature
            or "." in native_class or native_class.startswith("/")
            or native_class.endswith("/")
        ):
            print("error: --call-native requires a JNI slash-form class, method name, and signature", file=sys.stderr)
            return 2
    for class_name in args.java_class:
        if not class_name or "." in class_name:
            print(
                f"error: invalid JNI class name {class_name!r}; use slash form, e.g. com/example/Native",
                file=sys.stderr,
            )
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
    arg_is_set = [getattr(args, f"arg{i}") is not None for i in range(262)]
    if any(arg_is_set) and not (args.call or args.call_native):
        print("error: --argN requires --call or --call-native", file=sys.stderr)
        return 2
    if args.call and not args.call_native and any(arg_is_set[8:]):
        print("error: --call supports only --arg0 through --arg7", file=sys.stderr)
        return 2
    if args.call_native:
        gap_seen = False
        for is_set in arg_is_set:
            if not is_set:
                gap_seen = True
            elif gap_seen:
                print("error: --call-native arguments must be contiguous starting at --arg0", file=sys.stderr)
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
        if args.apks:
            asset_root = Path(directory) / "android-assets"
            try:
                asset_count = extract_apk_assets(args.apks, asset_root)
            except ValueError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
            command.extend(["--asset-root", str(asset_root)])
            print(f"Extracted {asset_count} APK asset file(s) for AAssetManager.", file=sys.stderr)
        for soname in args.external_dependency:
            command.extend(["--external-dependency", soname])
        if args.list_exports:
            command.append("--list-exports")
        if args.call:
            command.extend(["--call", args.call])
        if args.call_native:
            command.extend(["--call-native", *args.call_native])
        if args.jni_onload:
            command.append("--jni-onload")
        for class_name in args.java_class:
            command.extend(["--java-class", class_name])
        if args.run_initializers:
            command.append("--run-initializers")
        if args.budget is not None:
            command.extend(["--budget", str(args.budget)])
        for index in range(262):
            value = getattr(args, f"arg{index}")
            if value is not None:
                command.extend([f"--arg{index}", value])

        # JNI_OnLoad commonly calls FindClass for app and Android framework
        # types referenced by DEX. Seed those names automatically so testing a
        # real APK does not require thousands of hand-written --java-class flags.
        if args.jni_onload or args.call_native:
            dex_classes, dex_warnings = collect_apk_java_classes(args.apks)
            for warning in dex_warnings:
                print(f"warning: {warning}", file=sys.stderr)
            if dex_classes:
                class_list_path = Path(directory) / "java-classes.txt"
                class_list_path.write_text("\n".join(dex_classes) + "\n", encoding="utf-8")
                command.extend(["--java-classes-file", str(class_list_path)])
                print(
                    f"Seeded JNI FindClass with {len(dex_classes)} class name(s) from APK DEX metadata.",
                    file=sys.stderr,
                )
            else:
                print(
                    "warning: no DEX class names found; use --java-class for classes not present in supplied APKs",
                    file=sys.stderr,
                )

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
