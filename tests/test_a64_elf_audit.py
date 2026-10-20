import importlib.util
import json
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "tools" / "a64-elf-audit.py"
SPEC = importlib.util.spec_from_file_location("a64_elf_audit", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def sleb128(value: int) -> bytes:
    encoded = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        done = (value == 0 and not (byte & 0x40)) or (
            value == -1 and bool(byte & 0x40)
        )
        encoded.append(byte if done else byte | 0x80)
        if done:
            return bytes(encoded)


def android_packed_relative(offset: int = 0x700) -> bytes:
    # One APS2 relocation: R_AARCH64_RELATIVE at the chosen offset, addend 0.
    stream = b"APS2" + sleb128(1) + sleb128(0x100)
    stream += sleb128(1) + sleb128(0)  # group count, flags
    stream += sleb128(offset - 0x100) + sleb128(1027)  # offset delta, info
    return stream


def android_packed_relative_negative_group_delta() -> bytes:
    # One APS2 relocation: 0x180 + (-0x80) = 0x100.
    return (b"APS2" + sleb128(1) + sleb128(0x180) +
            sleb128(1) + sleb128(2) + sleb128(-0x80) + sleb128(1027))


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
            (MODULE.DT_SYMTAB, 0x500),
            (MODULE.DT_SYMENT, 24),
            (MODULE.DT_HASH, 0x540),
            (MODULE.DT_STRTAB, 0x600),
            (MODULE.DT_STRSZ, 8),
            (MODULE.DT_NULL, 0),
        ], extra_tls=True)
        struct.pack_into("<QQq", data, 0x300, 0x700, (1 << 32) | 1031, 0)
        # Minimal SysV hash table: one bucket, two dynamic symbols.
        struct.pack_into("<IIIII", data, 0x540, 1, 2, 1, 0, 0)
        struct.pack_into("<IBBHQQ", data, 0x500 + 24,
                         1, (1 << 4) | MODULE.STT_TLS, 0, 1, 8, 8)
        data[0x600:0x608] = b"\x00tlsvar\x00"
        report = MODULE.audit_elf(bytes(data))
        self.assertTrue(report["prototype_loader_compatible"])
        self.assertEqual(report["relocation_counts"]["R_AARCH64_TLSDESC"], 1)
        self.assertNotIn("R_AARCH64_TLSDESC", report["unsupported_relocations"])

    def test_android_aps2_packed_rela_is_decoded_and_classified(self):
        packed = android_packed_relative()
        data = make_elf([
            (MODULE.DT_ANDROID_RELA, 0x300),
            (MODULE.DT_ANDROID_RELASZ, len(packed)),
            (MODULE.DT_SYMTAB, 0x500),
            (MODULE.DT_SYMENT, 24),
            (MODULE.DT_HASH, 0x540),
            (MODULE.DT_STRTAB, 0x600),
            (MODULE.DT_STRSZ, 1),
            (MODULE.DT_NULL, 0),
        ])
        data[0x300:0x300 + len(packed)] = packed
        # Minimal SysV hash table containing only the null symbol.
        struct.pack_into("<IIII", data, 0x540, 1, 1, 0, 0)
        data[0x600] = 0

        report = MODULE.audit_elf(bytes(data), "libandroid-packed.so")
        self.assertTrue(report["has_android_packed_rela"])
        self.assertEqual(report["relocation_counts"]["R_AARCH64_RELATIVE"], 1)
        self.assertTrue(
            report["prototype_loader_compatible"],
            report["prototype_loader_blockers"],
        )
        self.assertFalse(any("cannot classify" in blocker
                             for blocker in report["prototype_loader_blockers"]))

    def test_android_aps2_accepts_negative_offset_deltas(self):
        streams = [
            ("libnegative-aps2.so", android_packed_relative(offset=0x80)),
            ("libnegative-grouped-aps2.so",
             android_packed_relative_negative_group_delta()),
        ]
        for name, packed in streams:
            with self.subTest(name=name):
                data = make_elf([
                    (MODULE.DT_ANDROID_RELA, 0x300),
                    (MODULE.DT_ANDROID_RELASZ, len(packed)),
                    (MODULE.DT_SYMTAB, 0x500),
                    (MODULE.DT_SYMENT, 24),
                    (MODULE.DT_HASH, 0x540),
                    (MODULE.DT_STRTAB, 0x600),
                    (MODULE.DT_STRSZ, 1),
                    (MODULE.DT_NULL, 0),
                ])
                data[0x300:0x300 + len(packed)] = packed
                struct.pack_into("<IIII", data, 0x540, 1, 1, 0, 0)
                data[0x600] = 0
                report = MODULE.audit_elf(bytes(data), name)
                self.assertTrue(report["prototype_loader_compatible"],
                                report["prototype_loader_blockers"])
                self.assertEqual(report["relocation_counts"]["R_AARCH64_RELATIVE"], 1)

    def test_android_aps2_allows_empty_conventional_rela_placeholder(self):
        packed = android_packed_relative()
        data = make_elf([
            (MODULE.DT_ANDROID_RELA, 0x300),
            (MODULE.DT_ANDROID_RELASZ, len(packed)),
            (MODULE.DT_RELA, 0x200),
            (MODULE.DT_RELASZ, 0),
            (MODULE.DT_RELAENT, 24),
            (MODULE.DT_SYMTAB, 0x500),
            (MODULE.DT_SYMENT, 24),
            (MODULE.DT_HASH, 0x540),
            (MODULE.DT_STRTAB, 0x600),
            (MODULE.DT_STRSZ, 1),
            (MODULE.DT_NULL, 0),
        ])
        data[0x300:0x300 + len(packed)] = packed
        struct.pack_into("<IIII", data, 0x540, 1, 1, 0, 0)
        data[0x600] = 0

        report = MODULE.audit_elf(bytes(data), "libandroid-empty-rela.so")
        self.assertTrue(
            report["prototype_loader_compatible"],
            report["prototype_loader_blockers"],
        )
        self.assertEqual(report["relocation_counts"]["R_AARCH64_RELATIVE"], 1)

    def test_android_aps2_allows_rela_entry_size_only_placeholder(self):
        packed = android_packed_relative()
        data = make_elf([
            (MODULE.DT_ANDROID_RELA, 0x300),
            (MODULE.DT_ANDROID_RELASZ, len(packed)),
            (MODULE.DT_RELAENT, 24),
            (MODULE.DT_SYMTAB, 0x500),
            (MODULE.DT_SYMENT, 24),
            (MODULE.DT_HASH, 0x540),
            (MODULE.DT_STRTAB, 0x600),
            (MODULE.DT_STRSZ, 1),
            (MODULE.DT_NULL, 0),
        ])
        data[0x300:0x300 + len(packed)] = packed
        struct.pack_into("<IIII", data, 0x540, 1, 1, 0, 0)
        data[0x600] = 0

        report = MODULE.audit_elf(bytes(data), "libandroid-relaent-only.so")
        self.assertTrue(
            report["prototype_loader_compatible"],
            report["prototype_loader_blockers"],
        )
        self.assertEqual(report["relocation_counts"]["R_AARCH64_RELATIVE"], 1)

    def test_malformed_android_aps2_signature_is_rejected(self):
        packed = b"NOPE" + sleb128(0) + sleb128(0)
        data = make_elf([
            (MODULE.DT_ANDROID_RELA, 0x300),
            (MODULE.DT_ANDROID_RELASZ, len(packed)),
            (MODULE.DT_NULL, 0),
        ])
        data[0x300:0x300 + len(packed)] = packed
        report = MODULE.audit_elf(bytes(data), "libbad-aps2.so")
        self.assertFalse(report["prototype_loader_compatible"])
        self.assertTrue(any(
            "invalid APS2 packed RELA" in blocker and "signature" in blocker
            for blocker in report["prototype_loader_blockers"]
        ))

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

    def test_extracts_referenced_undefined_symbols_and_exports(self):
        data = make_elf([
            (MODULE.DT_RELA, 0x300),
            (MODULE.DT_RELASZ, 24),
            (MODULE.DT_RELAENT, 24),
            (MODULE.DT_SYMTAB, 0x500),
            (MODULE.DT_SYMENT, 24),
            (MODULE.DT_HASH, 0x540),
            (MODULE.DT_STRTAB, 0x600),
            (MODULE.DT_STRSZ, 24),
            (MODULE.DT_NULL, 0),
        ])
        struct.pack_into("<QQq", data, 0x300, 0x700, (1 << 32) | 1026, 0)
        struct.pack_into("<IIIII", data, 0x540, 1, 2, 1, 0, 0)
        struct.pack_into("<IBBHQQ", data, 0x500 + 24,
                         1, (1 << 4), 0, 0, 0, 0)
        data[0x600:0x618] = b"\x00host_api\x00export_api\x00\x00\x00\x00"
        struct.pack_into("<IBBHQQ", data, 0x500 + 0,
                         10, (1 << 4), 0, 1, 0x700, 8)
        report = MODULE.audit_elf(bytes(data), "libtiny.so")
        self.assertIn(
            {"name": "host_api", "version": "", "provider": "",
             "binding": "GLOBAL", "tls": False},
            report["imports"],
        )
        self.assertTrue(any(item["name"] == "export_api"
                            for item in report["exports"]))

    def test_catalogue_resolves_internal_symbols_and_reports_platform_gaps(self):
        provider = {
            "source": "libprovider.so", "soname": "libprovider.so",
            "needed": [], "imports": [],
            "exports": [{"name": "inner_api", "version": "",
                         "version_hidden": False}],
        }
        consumer = {
            "source": "libconsumer.so", "soname": "libconsumer.so",
            "needed": ["libprovider.so", "libc.so"],
            "imports": [
                {"name": "inner_api", "version": "", "provider": "",
                 "binding": "GLOBAL", "tls": False},
                {"name": "open", "version": "", "provider": "libc.so",
                 "binding": "GLOBAL", "tls": False},
            ],
            "exports": [],
        }
        catalog = MODULE.audit_catalog([consumer, provider])
        self.assertEqual(catalog["missing_package_dependencies"], [])
        self.assertEqual(catalog["unresolved_package_symbols"], [])
        self.assertEqual(len(catalog["external_platform_dependencies"]), 1)
        self.assertEqual(len(catalog["platform_symbol_requirements"]), 1)
        self.assertEqual(catalog["platform_symbol_requirements"][0]["symbol"], "open")
        self.assertFalse(catalog["ready_to_launch"])

    def test_platform_import_is_not_mislabeled_when_other_package_dependency_exists(self):
        provider = {
            "source": "libprovider.so", "soname": "libprovider.so",
            "needed": [], "imports": [],
            "exports": [{"name": "inner_api", "version": "",
                         "version_hidden": False}],
        }
        consumer = {
            "source": "libconsumer.so", "soname": "libconsumer.so",
            "needed": ["libprovider.so", "libc.so"],
            "imports": [{"name": "open", "version": "", "provider": "",
                         "binding": "GLOBAL", "tls": False}],
            "exports": [],
        }
        catalog = MODULE.audit_catalog([consumer, provider])
        self.assertEqual(catalog["unresolved_package_symbols"], [])
        self.assertTrue(any(item["symbol"] == "open"
                            for item in catalog["platform_symbol_requirements"]))

    def test_unversioned_guest_libc_thunks_are_in_the_known_runtime_set(self):
        consumer = {
            "source": "libconsumer.so", "soname": "libconsumer.so",
            "needed": ["libc.so"],
            "imports": [
                {"name": "memchr", "version": "", "provider": "libc.so",
                 "binding": "GLOBAL", "tls": False},
                {"name": "strcat", "version": "", "provider": "libc.so",
                 "binding": "GLOBAL", "tls": False},
                {"name": "strcasecmp", "version": "", "provider": "libc.so",
                 "binding": "GLOBAL", "tls": False},
                {"name": "__errno", "version": "", "provider": "libc.so",
                 "binding": "GLOBAL", "tls": False},
            ],
            "exports": [],
        }
        catalog = MODULE.audit_catalog([consumer])
        self.assertEqual(catalog["unresolved_package_symbols"], [])
        self.assertEqual(catalog["platform_symbol_requirements"], [])
        self.assertTrue({
            "memchr", "strcat", "strcasecmp", "__errno"
        }.issubset(set(catalog["prototype_host_call_symbols"])))

    def test_single_thread_pthread_and_cxx_guard_shims_are_classified(self):
        consumer = {
            "source": "libconsumer.so", "soname": "libconsumer.so",
            "needed": ["libc.so", "libc++_shared.so"],
            "imports": [
                {"name": "pthread_mutex_init", "version": "",
                 "provider": "libc.so", "binding": "GLOBAL", "tls": False},
                {"name": "pthread_mutex_lock", "version": "",
                 "provider": "libc.so", "binding": "GLOBAL", "tls": False},
                {"name": "pthread_self", "version": "",
                 "provider": "libc.so", "binding": "GLOBAL", "tls": False},
                {"name": "__cxa_guard_acquire", "version": "",
                 "provider": "libc++_shared.so", "binding": "GLOBAL", "tls": False},
                {"name": "__cxa_guard_release", "version": "",
                 "provider": "libc++_shared.so", "binding": "GLOBAL", "tls": False},
            ],
            "exports": [],
        }
        catalog = MODULE.audit_catalog([consumer])
        self.assertEqual(catalog["unresolved_package_symbols"], [])
        self.assertEqual(catalog["platform_symbol_requirements"], [])
        self.assertTrue({
            "pthread_mutex_init", "pthread_mutex_lock", "pthread_self",
            "__cxa_guard_acquire", "__cxa_guard_release",
        }.issubset(set(catalog["prototype_host_call_symbols"])))

    def test_android_prop_info_thunks_are_in_the_known_runtime_set(self):
        consumer = {
            "source": "libconsumer.so", "soname": "libconsumer.so",
            "needed": ["libc.so"],
            "imports": [
                {"name": "__system_property_find", "version": "",
                 "provider": "libc.so", "binding": "GLOBAL", "tls": False},
                {"name": "__system_property_read", "version": "",
                 "provider": "libc.so", "binding": "GLOBAL", "tls": False},
                {"name": "__system_property_serial", "version": "",
                 "provider": "libc.so", "binding": "GLOBAL", "tls": False},
                {"name": "__system_property_area_serial", "version": "",
                 "provider": "libc.so", "binding": "GLOBAL", "tls": False},
            ],
            "exports": [],
        }
        catalog = MODULE.audit_catalog([consumer])
        self.assertEqual(catalog["unresolved_package_symbols"], [])
        self.assertEqual(catalog["platform_symbol_requirements"], [])
        self.assertTrue({
            "__system_property_find", "__system_property_read",
            "__system_property_serial", "__system_property_area_serial",
        }.issubset(set(catalog["prototype_host_call_symbols"])))

    def test_android_liblog_thunks_are_in_the_known_runtime_set(self):
        consumer = {
            "source": "libconsumer.so", "soname": "libconsumer.so",
            "needed": ["liblog.so"],
            "imports": [
                {"name": "__android_log_write", "version": "",
                 "provider": "liblog.so", "binding": "GLOBAL", "tls": False},
                {"name": "__android_log_buf_write", "version": "",
                 "provider": "liblog.so", "binding": "GLOBAL", "tls": False},
                {"name": "__android_log_is_loggable", "version": "",
                 "provider": "liblog.so", "binding": "GLOBAL", "tls": False},
            ],
            "exports": [],
        }
        catalog = MODULE.audit_catalog([consumer])
        self.assertEqual(catalog["unresolved_package_symbols"], [])
        self.assertEqual(catalog["platform_symbol_requirements"], [])
        self.assertTrue({
            "__android_log_write", "__android_log_buf_write",
            "__android_log_is_loggable",
        }.issubset(set(catalog["prototype_host_call_symbols"])))

    def test_versioned_hostcall_is_not_satisfied_by_name_only(self):
        consumer = {
            "source": "libconsumer.so", "soname": "libconsumer.so",
            "needed": ["libc.so"],
            "imports": [{"name": "memcpy", "version": "LIBC",
                         "provider": "libc.so", "binding": "GLOBAL", "tls": False}],
            "exports": [],
        }
        catalog = MODULE.audit_catalog([consumer])
        self.assertTrue(any(
            item["symbol"] == "memcpy" and
            item["versioned_host_call_needs_registration"]
            for item in catalog["platform_symbol_requirements"]
        ))

    def test_catalogue_follows_transitive_needed_edges(self):
        android_bridge = {
            "source": "libbridge.so", "soname": "libbridge.so",
            "needed": ["libc.so"], "imports": [], "exports": [],
        }
        consumer = {
            "source": "libconsumer.so", "soname": "libconsumer.so",
            "needed": ["libbridge.so"],
            "imports": [{"name": "open", "version": "", "provider": "",
                         "binding": "GLOBAL", "tls": False}],
            "exports": [],
        }
        catalog = MODULE.audit_catalog([consumer, android_bridge])
        self.assertEqual(catalog["unresolved_package_symbols"], [])
        self.assertTrue(any(item["symbol"] == "open"
                            for item in catalog["platform_symbol_requirements"]))
        closure = next(item for item in catalog["dependency_closures"]
                       if item["source"] == "libconsumer.so")
        self.assertEqual(closure["package_dependencies"], ["libbridge.so"])
        self.assertEqual(closure["platform_dependencies"], ["libc.so"])

    def test_transitive_package_export_satisfies_import(self):
        provider = {
            "source": "libprovider.so", "soname": "libprovider.so",
            "needed": [], "imports": [],
            "exports": [{"name": "deep_symbol", "version": "",
                         "version_hidden": False}],
        }
        bridge = {
            "source": "libbridge.so", "soname": "libbridge.so",
            "needed": ["libprovider.so"], "imports": [], "exports": [],
        }
        consumer = {
            "source": "libconsumer.so", "soname": "libconsumer.so",
            "needed": ["libbridge.so"],
            "imports": [{"name": "deep_symbol", "version": "", "provider": "",
                         "binding": "GLOBAL", "tls": False}],
            "exports": [],
        }
        catalog = MODULE.audit_catalog([consumer, bridge, provider])
        self.assertEqual(catalog["unresolved_package_symbols"], [])
        self.assertEqual(catalog["unclassified_unresolved_symbols"], [])

    def test_catalogue_reports_missing_dependency_and_ambiguous_soname(self):
        one = {"source": "split1/libsame.so", "soname": "libsame.so",
               "needed": ["libnotbundled.so"], "imports": [], "exports": []}
        two = {"source": "split2/libsame.so", "soname": "libsame.so",
               "needed": [], "imports": [], "exports": []}
        catalog = MODULE.audit_catalog([one, two])
        self.assertEqual(len(catalog["missing_package_dependencies"]), 1)
        self.assertEqual(catalog["missing_package_dependencies"][0]["dependency"],
                         "libnotbundled.so")
        self.assertTrue(any(item["soname"] == "libsame.so"
                            for item in catalog["soname_conflicts"]))

    def test_json_cli_reports_a_conservative_package_readiness_result(self):
        with tempfile.TemporaryDirectory() as directory:
            apk_path = Path(directory) / "client.apk"
            with zipfile.ZipFile(apk_path, "w") as apk:
                apk.writestr("lib/arm64-v8a/libtiny.so",
                             bytes(make_elf([(MODULE.DT_NULL, 0)])))

            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--json", str(apk_path)],
                check=False, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(len(payload["reports"]), 1)
            self.assertEqual(payload["catalog"]["library_count"], 1)
            self.assertFalse(payload["catalog"]["ready_to_launch"])
            self.assertEqual(payload["errors"], [])

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
