import contextlib
import importlib.util
import io
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "tools" / "roblox-arm-preflight.py"
SPEC = importlib.util.spec_from_file_location("arm64_x86_preflight", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def elf_header(machine: int, *, elf_class: int = 2, byte_order: int = 1) -> bytes:
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4] = elf_class
    header[5] = byte_order
    endian = "<" if byte_order == 1 else ">"
    struct.pack_into(endian + "H", header, 18, machine)
    return bytes(header)


class ElfHeaderTests(unittest.TestCase):
    def test_aarch64_elf64_little_endian(self):
        self.assertEqual(
            MODULE.read_elf_machine(elf_header(183)),
            ("ELF64", 183, None),
        )

    def test_x86_64_elf64_little_endian(self):
        self.assertEqual(
            MODULE.read_elf_machine(elf_header(62)),
            ("ELF64", 62, None),
        )

    def test_non_elf_rejected(self):
        self.assertEqual(
            MODULE.read_elf_machine(b"not an ELF"),
            ("not ELF", None, "missing or truncated ELF header"),
        )

    def test_unknown_byte_order_rejected(self):
        data = bytearray(elf_header(183))
        data[5] = 0
        self.assertEqual(
            MODULE.read_elf_machine(bytes(data)),
            ("ELF64", None, "unknown ELF byte order 0"),
        )


class ApkInspectionTests(unittest.TestCase):
    def make_apk(self, entries: dict[str, bytes]) -> str:
        temporary = tempfile.NamedTemporaryFile(suffix=".apk", delete=False)
        temporary.close()
        with zipfile.ZipFile(temporary.name, "w") as apk:
            for name, content in entries.items():
                apk.writestr(name, content)
        self.addCleanup(Path(temporary.name).unlink, missing_ok=True)
        return temporary.name

    def inspect_output(self, path: str) -> tuple[bool, str]:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            success = MODULE.inspect_apk(path)
        return success, output.getvalue()

    def test_arm64_library_is_reported_as_translation_requirement(self):
        path = self.make_apk({
            "AndroidManifest.xml": b"manifest",
            "classes.dex": b"dex",
            "lib/arm64-v8a/libroblox.so": elf_header(183),
        })
        success, output = self.inspect_output(path)
        self.assertTrue(success)
        self.assertIn("arm64-v8a", output)
        self.assertIn("AArch64", output)
        self.assertIn("guest instruction translation and ABI bridging are required", output)

    def test_abi_directory_elf_mismatch_is_reported(self):
        path = self.make_apk({"lib/x86_64/libroblox.so": elf_header(183)})
        success, output = self.inspect_output(path)
        self.assertTrue(success)
        self.assertIn("MISMATCH", output)
        self.assertIn("ELF warnings", output)

    def test_apk_set_is_not_misreported_as_native_abi_free_apk(self):
        path = self.make_apk({"splits/base.apk": b"placeholder", "splits/config.arm64_v8a.apk": b"placeholder"})
        success, output = self.inspect_output(path)
        self.assertTrue(success)
        self.assertIn("APK set/bundle", output)
        self.assertIn("config.arm64_v8a.apk", output)

    def test_non_archive_fails(self):
        temporary = tempfile.NamedTemporaryFile(suffix=".apk", delete=False)
        temporary.write(b"not an apk")
        temporary.close()
        self.addCleanup(Path(temporary.name).unlink, missing_ok=True)
        success, output = self.inspect_output(temporary.name)
        self.assertFalse(success)
        self.assertIn("not a ZIP/APK archive", output)


if __name__ == "__main__":
    unittest.main()
