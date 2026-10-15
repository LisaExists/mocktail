import importlib.util
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "tools" / "a64-elf-audit.py"
SPEC = importlib.util.spec_from_file_location("a64_elf_audit", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def make_elf(dynamic, *, machine=183, extra_tls=False):
    data = bytearray(0x800)
    ident = bytearray(16)
    ident[:4] = b"\x7fELF"
    ident[4] = 2
    ident[5] = 1
    ident[6] = 1
    struct.pack_into("<16sHHIQQQIHHHHHH", data, 0,
                     bytes(ident), 3, machine, 1, 0, 64, 0, 0,
                     64, 56, 3 if extra_tls else 2, 0, 0, 0)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 7, 0, 0, 0,
                     len(data), len(data), 0x1000)
    struct.pack_into("<IIQQQQQQ", data, 120, 2, 6, 0x100, 0x100, 0,
                     len(dynamic) * 16, len(dynamic) * 16, 8)
    if extra_tls:
        struct.pack_into("<IIQQQQQQ", data, 176, 7, 4, 0x400, 0x400, 0,
                         16, 32, 8)
    for i, (tag, value) in enumerate(dynamic):
        struct.pack_into("<qQ", data, 0x100 + i * 16, tag, value)
    return data


class ELFReportTests(unittest.TestCase):
    def test_simple_aarch64_shared_object_is_a_loader_candidate(self):
        data = make_elf([(MODULE.DT_NULL, 0)])
        report = MODULE.audit_elf(bytes(data), "libtiny.so")
        self.assertTrue(report["prototype_loader_compatible"])
        self.assertFalse(report["ready_for_roblox"])
        self.assertEqual(report["machine_name"], "AArch64")

    def test_unsupported_dynamic_relocation_is_reported_by_name(self):
        data = make_elf([
            (MODULE.DT_RELA, 0x300),
            (MODULE.DT_RELASZ, 24),
            (MODULE.DT_RELAENT, 24),
            (MODULE.DT_NULL, 0),
        ])
        struct.pack_into("<QQq", data, 0x300, 0x400, 1032, 0)
        report = MODULE.audit_elf(bytes(data))
        self.assertFalse(report["prototype_loader_compatible"])
        self.assertEqual(report["unsupported_relocations"]["R_AARCH64_IRELATIVE"], 1)

    def test_static_tlsdesc_relocation_is_in_the_supported_subset(self):
        data = make_elf([
            (MODULE.DT_RELA, 0x300),
            (MODULE.DT_RELASZ, 24),
            (MODULE.DT_RELAENT, 24),
            (MODULE.DT_NULL, 0),
        ])
        struct.pack_into("<QQq", data, 0x300, 0x400, 1031, 0)
        report = MODULE.audit_elf(bytes(data))
        self.assertTrue(report["prototype_loader_compatible"])
        self.assertEqual(report["relocation_counts"]["R_AARCH64_TLSDESC"], 1)
        self.assertNotIn("R_AARCH64_TLSDESC", report["unsupported_relocations"])

    def test_jmprel_uses_dt_pltrel_as_format_not_entry_size(self):
        data = make_elf([
            (MODULE.DT_JMPREL, 0x300),
            (MODULE.DT_PLTRELSZ, 24),
            (MODULE.DT_PLTREL, MODULE.DT_RELA),
            (MODULE.DT_NULL, 0),
        ])
        struct.pack_into("<QQq", data, 0x300, 0x400, 1026, 0)
        report = MODULE.audit_elf(bytes(data))
        self.assertEqual(report["relocation_counts"]["R_AARCH64_JUMP_SLOT"], 1)
        self.assertNotIn("R_AARCH64_JUMP_SLOT", report["unsupported_relocations"])

    def test_non_aarch64_elf_is_rejected(self):
        report = MODULE.audit_elf(bytes(make_elf([(MODULE.DT_NULL, 0)], machine=62)))
        self.assertFalse(report["prototype_loader_compatible"])
        self.assertTrue(any("not AArch64" in b for b in report["prototype_loader_blockers"]))

    def test_tls_program_header_reports_remaining_bionic_tls_gaps(self):
        data = make_elf([(MODULE.DT_NULL, 0)], extra_tls=True)
        report = MODULE.audit_elf(bytes(data))
        self.assertTrue(report["has_tls_segment"])
        self.assertTrue(report["prototype_loader_compatible"])
        self.assertTrue(any("DTV" in gap or "TLSDESC" in gap
                            for gap in report["runtime_gaps"]))
        self.assertFalse(any("PT_TLS" in b
                             for b in report["prototype_loader_blockers"]))

    def test_apk_inspection_only_audits_arm64_shared_objects(self):
        with tempfile.TemporaryDirectory() as directory:
            apk_path = Path(directory) / "client.apk"
            with zipfile.ZipFile(apk_path, "w") as apk:
                apk.writestr("lib/arm64-v8a/libtiny.so",
                             bytes(make_elf([(MODULE.DT_NULL, 0)])))
                apk.writestr("lib/x86_64/libignored.so", b"not an ELF")
            inputs, errors = MODULE.collect_inputs([str(apk_path)])
            self.assertFalse(errors)
            self.assertEqual(len(inputs), 1)
            self.assertTrue(inputs[0][0].endswith("lib/arm64-v8a/libtiny.so"))

    def test_apk_set_nested_apk_is_audited(self):
        child_bytes = None
        from io import BytesIO
        child = BytesIO()
        with zipfile.ZipFile(child, "w") as apk:
            apk.writestr("lib/arm64-v8a/libnested.so",
                         bytes(make_elf([(MODULE.DT_NULL, 0)])))
        with tempfile.TemporaryDirectory() as directory:
            outer_path = Path(directory) / "client.apks"
            with zipfile.ZipFile(outer_path, "w") as apks:
                apks.writestr("splits/base.apk", child.getvalue())
            inputs, errors = MODULE.collect_inputs([str(outer_path)])
            self.assertFalse(errors)
            self.assertEqual(len(inputs), 1)
            self.assertIn("splits/base.apk!lib/arm64-v8a/libnested.so", inputs[0][0])


if __name__ == "__main__":
    unittest.main()
