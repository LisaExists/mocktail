import importlib.util
import io
import os
import struct
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import zipfile
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "tools" / "mocktail-a64-apk-probe.py"
SPEC = importlib.util.spec_from_file_location("mocktail_a64_apk_probe", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def elf_header(machine: int, *, elf_class: int = 2, byte_order: int = 1) -> bytes:
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4] = elf_class
    header[5] = byte_order
    struct.pack_into("<H", header, 18, machine)
    return bytes(header)


class ApkProbeInputTests(unittest.TestCase):
    def make_apk(self, path: Path, entries: dict[str, bytes]) -> Path:
        with zipfile.ZipFile(path, "w") as apk:
            for name, data in entries.items():
                apk.writestr(name, data)
        return path

    def test_extracts_only_arm64_native_objects(self):
        with tempfile.TemporaryDirectory() as directory:
            apk_path = self.make_apk(
                Path(directory) / "client.apk",
                {
                    "lib/arm64-v8a/libroblox.so": elf_header(183),
                    "lib/arm64-v8a/libc++_shared.so": elf_header(183),
                    "lib/x86_64/libignored.so": b"not an ELF",
                    "assets/something.so": b"not an ELF",
                },
            )
            libraries = MODULE.collect_apk_libraries([apk_path], [])
            self.assertEqual(
                set(libraries),
                {"libroblox.so", "libc++_shared.so"},
            )
            self.assertIn("lib/arm64-v8a/libroblox.so", libraries["libroblox.so"][1])

    def test_rejects_wrong_architecture_under_arm64_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            apk_path = self.make_apk(
                Path(directory) / "bad.apk",
                {"lib/arm64-v8a/libwrong.so": elf_header(62)},
            )
            with self.assertRaisesRegex(ValueError, "not a little-endian ELF64 AArch64"):
                MODULE.collect_apk_libraries([apk_path], [])

    def test_skips_host_architecture_objects_in_additional_library_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            library_dir = Path(directory) / "libs"
            library_dir.mkdir()
            (library_dir / "libhost.so").write_bytes(elf_header(62))
            (library_dir / "libguest.so").write_bytes(elf_header(183))
            libraries = MODULE.collect_apk_libraries([], [library_dir])
            self.assertEqual(set(libraries), {"libguest.so"})

    def test_rejects_ambiguous_module_basenames(self):
        with tempfile.TemporaryDirectory() as directory:
            first = self.make_apk(
                Path(directory) / "one.apk",
                {"lib/arm64-v8a/libsame.so": elf_header(183)},
            )
            different_guest_elf = bytearray(elf_header(183))
            different_guest_elf[40] = 1
            second = self.make_apk(
                Path(directory) / "two.apk",
                {"lib/arm64-v8a/libsame.so": bytes(different_guest_elf)},
            )
            with self.assertRaisesRegex(ValueError, "multiple different ARM64 libraries"):
                MODULE.collect_apk_libraries([first, second], [])

    def test_extracts_native_libraries_from_apks_split_set(self):
        with tempfile.TemporaryDirectory() as directory:
            def apk_bytes(entries: dict[str, bytes]) -> bytes:
                stream = io.BytesIO()
                with zipfile.ZipFile(stream, "w") as apk:
                    for name, data in entries.items():
                        apk.writestr(name, data)
                return stream.getvalue()

            base = apk_bytes({"classes.dex": b"dex"})
            arm64_split = apk_bytes({
                "lib/arm64-v8a/libroblox.so": elf_header(183),
                "lib/arm64-v8a/libc++_shared.so": elf_header(183),
            })
            apks_path = Path(directory) / "roblox.apks"
            with zipfile.ZipFile(apks_path, "w") as bundle:
                bundle.writestr("splits/base-master.apk", base)
                bundle.writestr("splits/config.arm64_v8a.apk", arm64_split)

            libraries = MODULE.collect_apk_libraries([apks_path], [])
            self.assertEqual(
                set(libraries),
                {"libroblox.so", "libc++_shared.so"},
            )
            self.assertIn("config.arm64_v8a.apk", libraries["libroblox.so"][1])

    def test_library_directory_can_be_used_without_positional_apks(self):
        args = MODULE.parse_args([
            "--root", "libroot.so", "--library-dir", "/tmp/guest-libs"
        ])
        self.assertEqual(args.apks, [])
        self.assertEqual(args.root, "libroot.so")

    def test_reports_when_no_arm64_library_is_available(self):
        with tempfile.TemporaryDirectory() as directory:
            apk_path = self.make_apk(
                Path(directory) / "empty.apk",
                {"classes.dex": b"dex"},
            )
            with self.assertRaisesRegex(ValueError, "no AArch64 native libraries found"):
                MODULE.collect_apk_libraries([apk_path], [])

    def test_call_native_and_java_arguments_are_forwarded_to_native_probe(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            apk_path = self.make_apk(
                root / "client.apk",
                {"lib/arm64-v8a/libroot.so": elf_header(183)},
            )
            probe = root / "probe"
            probe.write_text("#!/bin/sh\\nexit 0\\n", encoding="utf-8")
            probe.chmod(probe.stat().st_mode | 0o111)

            with patch.object(
                MODULE.subprocess,
                "run",
                return_value=SimpleNamespace(returncode=0),
            ) as run:
                result = MODULE.main([
                    "--probe", str(probe),
                    "--root", "libroot.so",
                    "--call-native", "com/mocktail/Smoke", "nativeSum", "(II)I",
                    "--arg0", "20", "--arg1", "22",
                    str(apk_path),
                ])

            self.assertEqual(result, 0)
            command = run.call_args.args[0]
            self.assertIn(
                ["--call-native", "com/mocktail/Smoke", "nativeSum", "(II)I"],
                [command[i:i + 4] for i in range(len(command) - 3)],
            )
            self.assertIn(["--arg0", "20"], [
                command[i:i + 2] for i in range(len(command) - 1)
            ])
            self.assertIn(["--arg1", "22"], [
                command[i:i + 2] for i in range(len(command) - 1)
            ])

    def test_external_dependency_option_is_forwarded_to_native_probe(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            apk_path = self.make_apk(
                root / "client.apk",
                {"lib/arm64-v8a/libroot.so": elf_header(183)},
            )
            probe = root / "probe"
            probe.write_text("#!/bin/sh\\nexit 0\\n", encoding="utf-8")
            probe.chmod(probe.stat().st_mode | 0o111)

            with patch.object(
                MODULE.subprocess,
                "run",
                return_value=SimpleNamespace(returncode=0),
            ) as run:
                result = MODULE.main([
                    "--probe", str(probe),
                    "--root", "libroot.so",
                    "--external-dependency", "libm.so",
                    str(apk_path),
                ])

            self.assertEqual(result, 0)
            command = run.call_args.args[0]
            self.assertIn("--external-dependency", command)
            option_index = command.index("--external-dependency")
            self.assertEqual(command[option_index + 1], "libm.so")



if __name__ == "__main__":
    unittest.main()
