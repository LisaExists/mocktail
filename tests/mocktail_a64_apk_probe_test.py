import importlib.util
import struct
import tempfile
import unittest
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

    def test_reports_when_no_arm64_library_is_available(self):
        with tempfile.TemporaryDirectory() as directory:
            apk_path = self.make_apk(
                Path(directory) / "empty.apk",
                {"classes.dex": b"dex"},
            )
            with self.assertRaisesRegex(ValueError, "no AArch64 native libraries found"):
                MODULE.collect_apk_libraries([apk_path], [])


if __name__ == "__main__":
    unittest.main()
