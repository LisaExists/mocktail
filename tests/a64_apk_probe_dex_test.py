import importlib.util
import io
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


def uleb128(value: int) -> bytes:
    encoded = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        encoded.append(byte if value == 0 else byte | 0x80)
        if value == 0:
            return bytes(encoded)


def make_dex(descriptors: list[str], *, version: str = "039") -> bytes:
    """Construct valid DEX headers and string/type tables for class discovery tests."""
    header_size = 120 if version == "041" else 112
    strings = list(dict.fromkeys(descriptors))
    string_ids_offset = header_size
    type_ids_offset = string_ids_offset + len(strings) * 4
    string_data_offset = type_ids_offset + len(descriptors) * 4
    string_payload = bytearray()
    string_offsets = {}
    for value in strings:
        string_offsets[value] = string_data_offset + len(string_payload)
        encoded = value.encode("ascii")
        string_payload.extend(uleb128(len(value)))
        string_payload.extend(encoded)
        string_payload.append(0)
    file_size = string_data_offset + len(string_payload)
    data = bytearray(file_size)
    data[:8] = b"dex\n" + version.encode("ascii") + b"\0"
    struct.pack_into("<III", data, 32, file_size, header_size, 0x12345678)
    struct.pack_into("<II", data, 56, len(strings), string_ids_offset)
    struct.pack_into("<II", data, 64, len(descriptors), type_ids_offset)
    if version == "041":
        struct.pack_into("<II", data, 112, file_size, 0)
    for index, descriptor in enumerate(strings):
        struct.pack_into("<I", data, string_ids_offset + index * 4,
                         string_offsets[descriptor])
    for index, descriptor in enumerate(descriptors):
        struct.pack_into("<I", data, type_ids_offset + index * 4,
                         strings.index(descriptor))
    data[string_data_offset:] = string_payload
    return bytes(data)


def make_dex041_container(descriptors_by_file: list[list[str]]) -> bytes:
    """Combine minimal DEX 041 logical files while keeping absolute offsets valid."""
    files = [make_dex(items, version="041") for items in descriptors_by_file]
    container_size = sum(len(item) for item in files)
    relocated = []
    base = 0
    for data in files:
        item = bytearray(data)
        struct.pack_into("<II", item, 112, container_size, base)
        if base:
            string_count, string_ids_offset = struct.unpack_from("<II", item, 56)
            _type_count, type_ids_offset = struct.unpack_from("<II", item, 64)
            struct.pack_into("<I", item, 60, string_ids_offset + base)
            struct.pack_into("<I", item, 68, type_ids_offset + base)
            for index in range(string_count):
                offset_at = string_ids_offset + index * 4
                offset = struct.unpack_from("<I", item, offset_at)[0]
                struct.pack_into("<I", item, offset_at, offset + base)
        relocated.append(bytes(item))
        base += len(item)
    return b"".join(relocated)


def make_apk(entries: dict[str, bytes]) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return stream.getvalue()


class DexClassDiscoveryTests(unittest.TestCase):
    def test_extracts_referenced_classes_and_skips_primitive_and_array_types(self):
        data = make_dex([
            "Lcom/mocktail/Smoke;",
            "Landroid/os/Build;",
            "I",
            "[Ljava/lang/String;",
        ])
        self.assertEqual(
            MODULE.parse_dex_class_names(data),
            ["android/os/Build", "com/mocktail/Smoke"],
        )

    def test_rejects_unsupported_dex_version(self):
        data = bytearray(make_dex(["Lcom/mocktail/Smoke;"]))
        data[4:7] = b"999"
        with self.assertRaisesRegex(ValueError, "DEX version/magic"):
            MODULE.parse_dex_class_names(bytes(data))

    def test_rejects_type_descriptors_outside_string_table(self):
        data = bytearray(make_dex(["Lcom/mocktail/Smoke;"]))
        type_ids_offset = struct.unpack_from("<I", data, 68)[0]
        struct.pack_into("<I", data, type_ids_offset, 100)
        with self.assertRaisesRegex(ValueError, "outside string table"):
            MODULE.parse_dex_class_names(bytes(data))

    def test_parses_a_single_dex_041_container(self):
        self.assertEqual(
            MODULE.parse_dex_class_names(
                make_dex(["Lcom/mocktail/Smoke;"], version="041")
            ),
            ["com/mocktail/Smoke"],
        )

    def test_parses_multiple_logical_files_in_a_dex_041_container(self):
        data = make_dex041_container([
            ["Lcom/mocktail/Smoke;"],
            ["Landroid/os/Build;"],
        ])
        self.assertEqual(
            MODULE.parse_dex_class_names(data),
            ["android/os/Build", "com/mocktail/Smoke"],
        )

    def test_rejects_inconsistent_dex_041_container_size(self):
        data = bytearray(make_dex(["Lcom/mocktail/Smoke;"], version="041"))
        struct.pack_into("<I", data, 112, len(data) + 1)
        with self.assertRaisesRegex(ValueError, "container size"):
            MODULE.parse_dex_class_names(bytes(data))

    def test_discovers_classes_from_apk_and_multidex_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            apk_path = Path(directory) / "client.apk"
            with zipfile.ZipFile(apk_path, "w") as archive:
                archive.writestr("classes.dex", make_dex(["Lcom/mocktail/Smoke;"]))
                archive.writestr("classes2.dex", make_dex(["Landroid/os/Build;"]))
                archive.writestr("assets/classes.dex", b"not a root dex")
            classes, warnings = MODULE.collect_apk_java_classes([apk_path])
            self.assertEqual(classes, ["android/os/Build", "com/mocktail/Smoke"])
            self.assertEqual(warnings, [])

    def test_discovers_classes_from_nested_apks_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            apks_path = Path(directory) / "client.apks"
            nested = make_apk({
                "classes.dex": make_dex(["Lcom/mocktail/Smoke;"]),
            })
            with zipfile.ZipFile(apks_path, "w") as bundle:
                bundle.writestr("splits/base-master.apk", nested)
                bundle.writestr("splits/config.arm64_v8a.apk", make_apk({
                    "classes.dex": make_dex(["Landroid/os/Build;"]),
                }))
            classes, warnings = MODULE.collect_apk_java_classes([apks_path])
            self.assertEqual(classes, ["android/os/Build", "com/mocktail/Smoke"])
            self.assertEqual(warnings, [])

    def test_missing_dex_is_nonfatal_for_native_only_apks(self):
        with tempfile.TemporaryDirectory() as directory:
            apk_path = Path(directory) / "native-only.apk"
            with zipfile.ZipFile(apk_path, "w") as archive:
                archive.writestr("lib/arm64-v8a/libnative.so", b"placeholder")
            classes, warnings = MODULE.collect_apk_java_classes([apk_path])
            self.assertEqual(classes, [])
            self.assertEqual(warnings, [])


if __name__ == "__main__":
    unittest.main()
