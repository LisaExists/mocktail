#!/usr/bin/env python3
"""Read-only audit of AArch64 ELF dependencies and relocation requirements.

Accepts ELF shared objects, directories of extracted libraries, APKs, and APK-set
archives containing nested APKs. Never extracts files to disk, executes native
code, patches packages, or changes signatures.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import struct
import sys
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

MAX_ELF_BYTES = 512 * 1024 * 1024
MAX_SYMBOLS = 1_000_000
MAX_PROGRAM_HEADERS = 4096
MAX_DYNAMIC_ENTRIES = 1_000_000

EM_AARCH64, ET_EXEC, ET_DYN = 183, 2, 3
PT_LOAD, PT_DYNAMIC, PT_TLS = 1, 2, 7

DT_NULL, DT_NEEDED, DT_PLTRELSZ, DT_HASH = 0, 1, 2, 4
DT_STRTAB, DT_SYMTAB, DT_RELA, DT_RELASZ = 5, 6, 7, 8
DT_RELAENT, DT_STRSZ, DT_SYMENT, DT_SONAME = 9, 10, 11, 14
DT_INIT, DT_FINI, DT_REL, DT_RELSZ = 12, 13, 17, 18
DT_RELENT, DT_PLTREL, DT_JMPREL = 19, 20, 23
DT_INIT_ARRAY, DT_FINI_ARRAY, DT_INIT_ARRAYSZ, DT_FINI_ARRAYSZ = 25, 26, 27, 28
DT_FLAGS, DT_TEXTREL = 30, 22
DT_GNU_HASH, DT_VERSYM = 0x6FFFFEF5, 0x6FFFFFF0
DT_VERDEF, DT_VERDEFNUM = 0x6FFFFFFC, 0x6FFFFFFD
DT_VERNEED, DT_VERNEEDNUM = 0x6FFFFFFE, 0x6FFFFFFF
DT_ANDROID_REL, DT_ANDROID_RELSZ = 0x6000000F, 0x60000010
DT_ANDROID_RELA, DT_ANDROID_RELASZ = 0x60000011, 0x60000012
DT_RELR, DT_RELRSZ, DT_RELRENT = 36, 35, 37
DT_ANDROID_RELR, DT_ANDROID_RELRSZ, DT_ANDROID_RELRENT = 0x6FFFE000, 0x6FFFE001, 0x6FFFE003
DF_TEXTREL = 0x4
STT_TLS, STT_GNU_IFUNC = 6, 10
ABI_DIRECTORY = "arm64-v8a"

RELOCATION_NAMES = {
    0: "R_AARCH64_NONE",
    257: "R_AARCH64_ABS64",
    258: "R_AARCH64_ABS32",
    259: "R_AARCH64_ABS16",
    260: "R_AARCH64_PREL64",
    261: "R_AARCH64_PREL32",
    262: "R_AARCH64_PREL16",
    1024: "R_AARCH64_COPY",
    1025: "R_AARCH64_GLOB_DAT",
    1026: "R_AARCH64_JUMP_SLOT",
    1027: "R_AARCH64_RELATIVE",
    1028: "R_AARCH64_TLS_DTPMOD64",
    1029: "R_AARCH64_TLS_DTPREL64",
    1030: "R_AARCH64_TLS_TPREL64",
    1031: "R_AARCH64_TLSDESC",
    1032: "R_AARCH64_IRELATIVE",
}
PROTOTYPE_RELOCATIONS = {0, 257, 1025, 1026, 1027, 1028, 1029, 1030, 1031}


class AuditError(ValueError):
    pass


def relocation_name(relocation_type: int) -> str:
    return RELOCATION_NAMES.get(relocation_type, f"R_AARCH64_{relocation_type}")


class ELF64Image:
    def __init__(self, data: bytes):
        self.data = data
        self.machine = -1
        self.elf_type = -1
        self.loads: list[tuple[int, int, int, int]] = []
        self.dynamic_segment: tuple[int, int] | None = None
        self.has_tls_segment = False
        self._parse_program_headers()

    def _parse_program_headers(self) -> None:
        data = self.data
        if len(data) < 64 or data[:4] != b"\x7fELF":
            raise AuditError("missing or truncated ELF64 header")
        if data[4] != 2:
            raise AuditError(f"ELF class is {data[4]}, expected ELF64")
        if data[5] != 1:
            raise AuditError(f"ELF byte order is {data[5]}, expected little-endian")
        if data[6] != 1:
            raise AuditError("unsupported ELF identification version")
        h = struct.unpack_from("<16sHHIQQQIHHHHHH", data, 0)
        self.elf_type, self.machine = h[1], h[2]
        phoff, ehsize, phentsize, phnum = h[5], h[8], h[9], h[10]
        if ehsize < 64 or phentsize < 56:
            raise AuditError("ELF header or program-header entry is too small")
        if phnum == 0 or phnum >= 0xFFFF or phnum > MAX_PROGRAM_HEADERS:
            raise AuditError("ELF has an empty or unsupported program-header table")
        if phoff > len(data) or phnum * phentsize > len(data) - phoff:
            raise AuditError("ELF program-header table is truncated")
        for index in range(phnum):
            off = phoff + index * phentsize
            p_type, _flags, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, _align = (
                struct.unpack_from("<IIQQQQQQ", data, off)
            )
            if p_type == PT_LOAD:
                if p_offset > len(data) or p_filesz > len(data) - p_offset:
                    raise AuditError("PT_LOAD file range is out of bounds")
                if p_filesz > p_memsz:
                    raise AuditError("PT_LOAD p_filesz exceeds p_memsz")
                self.loads.append((p_vaddr, p_filesz, p_offset, p_memsz))
            elif p_type == PT_DYNAMIC:
                if self.dynamic_segment is not None:
                    raise AuditError("ELF contains multiple PT_DYNAMIC segments")
                if p_offset > len(data) or p_filesz > len(data) - p_offset:
                    raise AuditError("PT_DYNAMIC file range is out of bounds")
                self.dynamic_segment = (p_offset, p_filesz)
            elif p_type == PT_TLS:
                self.has_tls_segment = True

    def vaddr_offset(self, address: int, length: int) -> int:
        if address < 0 or length < 0:
            raise AuditError("negative guest address or length")
        for vaddr, filesz, offset, _memsz in self.loads:
            if address < vaddr:
                continue
            delta = address - vaddr
            if delta <= filesz and length <= filesz - delta:
                return offset + delta
        raise AuditError(f"virtual range 0x{address:x}+0x{length:x} is not file-backed")

    def read_vaddr(self, address: int, length: int) -> bytes:
        offset = self.vaddr_offset(address, length)
        return self.data[offset:offset + length]

    def dynamic_tags(self, blockers: list[str]) -> dict[int, list[int]]:
        if self.dynamic_segment is None:
            blockers.append("missing PT_DYNAMIC segment")
            return {}
        offset, size = self.dynamic_segment
        if size == 0 or size % 16:
            blockers.append("PT_DYNAMIC is empty or not a whole number of entries")
        count = min(size // 16, MAX_DYNAMIC_ENTRIES)
        if size // 16 > MAX_DYNAMIC_ENTRIES:
            blockers.append("PT_DYNAMIC exceeds the audit entry limit")
        tags: dict[int, list[int]] = {}
        terminated = False
        for index in range(count):
            tag, value = struct.unpack_from("<qQ", self.data, offset + index * 16)
            if tag == DT_NULL:
                terminated = True
                break
            tags.setdefault(tag, []).append(value)
        if not terminated:
            blockers.append("PT_DYNAMIC has no DT_NULL terminator")
        return tags


def first_tag(tags: dict[int, list[int]], tag: int, blockers: list[str],
              label: str) -> int | None:
    values = tags.get(tag, [])
    if len(values) > 1:
        blockers.append(f"duplicate {label} dynamic tags")
    return values[0] if values else None


def dynamic_string(image: ELF64Image, tags: dict[int, list[int]],
                   offset: int, blockers: list[str]) -> str | None:
    strtab = first_tag(tags, DT_STRTAB, blockers, "DT_STRTAB")
    strsz = first_tag(tags, DT_STRSZ, blockers, "DT_STRSZ")
    if strtab is None or strsz is None or offset >= strsz:
        blockers.append("dynamic string offset is outside DT_STRTAB")
        return None
    length = min(strsz - offset, 4096)
    try:
        start = image.vaddr_offset(strtab + offset, length)
    except AuditError as exc:
        blockers.append(str(exc))
        return None
    raw = image.data[start:start + length]
    terminator = raw.find(b"\0")
    if terminator < 0:
        blockers.append("dynamic string is unterminated or exceeds 4096 bytes")
        return None
    return raw[:terminator].decode("utf-8", errors="replace")


def dynsym_count(image: ELF64Image, tags: dict[int, list[int]],
                 blockers: list[str]) -> int | None:
    hash_addr = first_tag(tags, DT_HASH, blockers, "DT_HASH")
    if hash_addr is not None:
        try:
            _buckets, count = struct.unpack("<II", image.read_vaddr(hash_addr, 8))
        except (AuditError, struct.error) as exc:
            blockers.append(f"cannot read DT_HASH: {exc}")
            return None
        if count == 0 or count > MAX_SYMBOLS:
            blockers.append("DT_HASH contains an invalid/excessive symbol count")
            return None
        return count

    gnu_addr = first_tag(tags, DT_GNU_HASH, blockers, "DT_GNU_HASH")
    if gnu_addr is None:
        return None
    try:
        nbuckets, symoffset, bloom_size, _shift = struct.unpack(
            "<IIII", image.read_vaddr(gnu_addr, 16)
        )
        if (nbuckets == 0 or nbuckets > MAX_SYMBOLS or bloom_size == 0 or
                bloom_size > MAX_SYMBOLS or symoffset > MAX_SYMBOLS):
            raise AuditError("invalid DT_GNU_HASH dimensions")
        buckets_addr = gnu_addr + 16 + bloom_size * 8
        chains_addr = buckets_addr + nbuckets * 4
        image.vaddr_offset(buckets_addr, nbuckets * 4)
        count = symoffset
        for bucket_index in range(nbuckets):
            bucket = struct.unpack("<I", image.read_vaddr(buckets_addr + bucket_index * 4, 4))[0]
            if bucket == 0:
                continue
            if bucket < symoffset or bucket >= MAX_SYMBOLS:
                raise AuditError("invalid DT_GNU_HASH bucket symbol index")
            index = bucket
            while index < MAX_SYMBOLS:
                chain_addr = chains_addr + (index - symoffset) * 4
                value = struct.unpack("<I", image.read_vaddr(chain_addr, 4))[0]
                count = max(count, index + 1)
                if value & 1:
                    break
                index += 1
            else:
                raise AuditError("DT_GNU_HASH chain exceeds the symbol limit")
        if count == 0 or count > MAX_SYMBOLS:
            raise AuditError("DT_GNU_HASH produced an invalid symbol count")
        return count
    except (AuditError, struct.error) as exc:
        blockers.append(f"cannot determine DT_GNU_HASH symbol count: {exc}")
        return None


def audit_elf(data: bytes, source: str = "<memory>") -> dict[str, Any]:
    report: dict[str, Any] = {
        "source": source, "elf_class": "unknown", "machine": None,
        "machine_name": "unknown", "type": "unknown", "soname": None,
        "needed": [], "relocation_counts": {}, "unsupported_relocations": {},
        "versioned_symbols": 0, "versioned_relocations": 0,
        "tls_symbols": 0, "ifunc_symbols": 0, "has_tls_segment": False,
        "has_android_packed_rela": False, "has_relr": False,
        "has_text_relocations": False, "has_initializers": False,
        "prototype_loader_blockers": [], "runtime_gaps": [
            "Android/Bionic startup, JNI integration, guest threads and graphics are not implemented"
        ], "prototype_loader_compatible": False, "ready_for_roblox": False,
    }
    blockers: list[str] = report["prototype_loader_blockers"]
    if len(data) > MAX_ELF_BYTES:
        blockers.append(f"ELF exceeds the configured {MAX_ELF_BYTES}-byte audit limit")
        return report
    try:
        image = ELF64Image(data)
    except AuditError as exc:
        blockers.append(str(exc))
        return report

    report["elf_class"] = "ELF64"
    report["machine"] = image.machine
    report["machine_name"] = "AArch64" if image.machine == EM_AARCH64 else f"e_machine={image.machine}"
    report["type"] = {ET_DYN: "ET_DYN", ET_EXEC: "ET_EXEC"}.get(image.elf_type, f"e_type={image.elf_type}")
    report["has_tls_segment"] = image.has_tls_segment
    if image.machine != EM_AARCH64:
        blockers.append("ELF machine is not AArch64")
        return report
    if image.elf_type != ET_DYN:
        blockers.append("prototype module loader only accepts ET_DYN shared objects")
    if not image.loads:
        blockers.append("ELF contains no PT_LOAD segments")
    if image.has_tls_segment:
        report["runtime_gaps"].append(
            "static TLS and preloaded-module TLSDESC are supported by the prototype; "
            "Bionic TCB/DTV, dlopen-style dynamic TLS, and guest pthread scheduling remain gaps"
        )

    tags = image.dynamic_tags(blockers)
    soname_offset = first_tag(tags, DT_SONAME, blockers, "DT_SONAME")
    if soname_offset is not None:
        report["soname"] = dynamic_string(image, tags, soname_offset, blockers)
    for needed_offset in tags.get(DT_NEEDED, []):
        name = dynamic_string(image, tags, needed_offset, blockers)
        if name is not None:
            report["needed"].append(name)

    report["has_initializers"] = any(tag in tags for tag in (
        DT_INIT, DT_FINI, DT_INIT_ARRAY, DT_FINI_ARRAY
    ))
    if report["has_initializers"]:
        report["runtime_gaps"].append(
            "ELF initializers/finalizers can be executed by the opt-in smoke harness, "
            "but automatic Android linker startup and finalization are not implemented"
        )
    if DT_TEXTREL in tags or any(v & DF_TEXTREL for v in tags.get(DT_FLAGS, [])):
        report["has_text_relocations"] = True
        blockers.append("text relocations are unsupported")
    if DT_ANDROID_REL in tags or DT_ANDROID_RELSZ in tags:
        blockers.append("Android packed REL relocations are unsupported")

    android_rela_addr = first_tag(tags, DT_ANDROID_RELA, blockers, "DT_ANDROID_RELA")
    android_rela_size = first_tag(tags, DT_ANDROID_RELASZ, blockers, "DT_ANDROID_RELASZ")
    if (android_rela_addr is None) != (android_rela_size is None):
        blockers.append("DT_ANDROID_RELA and DT_ANDROID_RELASZ must be provided together")
    elif android_rela_addr is not None and android_rela_size:
        report["has_android_packed_rela"] = True
        blockers.append(
            "APS2 packed RELA is present; the audit cannot classify its relocation types"
        )

    relocations: list[tuple[int, int]] = []
    seen_tables: set[tuple[int, int, str]] = set()

    def scan_table(address_tag: int, size_tag: int, entry_tag: int | None,
                   entry_size: int, label: str, fmt: str) -> None:
        address = first_tag(tags, address_tag, blockers, label)
        size = first_tag(tags, size_tag, blockers, label + " size")
        ent = entry_size if entry_tag is None else first_tag(
            tags, entry_tag, blockers, label + " entry size"
        )
        if address is None and (size is None or size == 0):
            return
        if address is None or size is None or ent is None:
            blockers.append(f"{label} table metadata is incomplete")
            return
        if size == 0:
            return
        if ent != entry_size or size % entry_size:
            blockers.append(f"{label} has an invalid entry size")
            return
        key = (address, size, fmt)
        if key in seen_tables:
            return
        seen_tables.add(key)
        try:
            file_offset = image.vaddr_offset(address, size)
        except AuditError as exc:
            blockers.append(f"{label} table is out of bounds: {exc}")
            return
        for off in range(file_offset, file_offset + size, entry_size):
            if fmt == "RELA":
                _target, info, _addend = struct.unpack_from("<QQq", data, off)
            else:
                _target, info = struct.unpack_from("<QQ", data, off)
            relocations.append((info & 0xFFFFFFFF, info >> 32))

    rela_metadata = (DT_RELA in tags, DT_RELASZ in tags, DT_RELAENT in tags)
    if any(rela_metadata):
        if not all(rela_metadata):
            blockers.append("DT_RELA, DT_RELASZ and DT_RELAENT must be provided together")
        else:
            scan_table(DT_RELA, DT_RELASZ, DT_RELAENT, 24, "DT_RELA", "RELA")

    rel_metadata = (DT_REL in tags, DT_RELSZ in tags, DT_RELENT in tags)
    if any(rel_metadata):
        if not all(rel_metadata):
            blockers.append("DT_REL, DT_RELSZ and DT_RELENT must be provided together")
        else:
            rel_size = first_tag(tags, DT_RELSZ, blockers, "DT_RELSZ") or 0
            if rel_size:
                blockers.append("DT_REL relocations are unsupported; this loader needs RELA")
            scan_table(DT_REL, DT_RELSZ, DT_RELENT, 16, "DT_REL", "REL")

    jmprel = first_tag(tags, DT_JMPREL, blockers, "DT_JMPREL")
    pltrelsz = first_tag(tags, DT_PLTRELSZ, blockers, "DT_PLTRELSZ")
    pltrel = first_tag(tags, DT_PLTREL, blockers, "DT_PLTREL")
    if jmprel is not None or (pltrelsz is not None and pltrelsz):
        if jmprel is None or pltrelsz is None or pltrel is None:
            blockers.append("DT_JMPREL, DT_PLTRELSZ and DT_PLTREL must be provided together")
        elif pltrelsz:
            if pltrel == DT_RELA:
                scan_table(DT_JMPREL, DT_PLTRELSZ, None, 24, "DT_JMPREL", "RELA")
            elif pltrel == DT_REL:
                blockers.append("PLT relocations use DT_REL; only RELA PLT tables are supported")
                scan_table(DT_JMPREL, DT_PLTRELSZ, None, 16, "DT_JMPREL", "REL")
            else:
                blockers.append(f"DT_PLTREL has unknown format {pltrel}")

    relr_addr = first_tag(tags, DT_RELR, blockers, "DT_RELR")
    if relr_addr is None:
        relr_addr = first_tag(tags, DT_ANDROID_RELR, blockers, "DT_ANDROID_RELR")
    relr_size = first_tag(tags, DT_RELRSZ, blockers, "DT_RELRSZ")
    if relr_size is None:
        relr_size = first_tag(tags, DT_ANDROID_RELRSZ, blockers, "DT_ANDROID_RELRSZ")
    relr_ent = first_tag(tags, DT_RELRENT, blockers, "DT_RELRENT")
    if relr_ent is None:
        relr_ent = first_tag(tags, DT_ANDROID_RELRENT, blockers, "DT_ANDROID_RELRENT")
    if any(v is not None for v in (relr_addr, relr_size, relr_ent)):
        if relr_addr is None or relr_size is None or relr_ent is None:
            blockers.append("DT_RELR, DT_RELRSZ and DT_RELRENT must be provided together")
        elif relr_ent != 8 or relr_size % 8:
            blockers.append("RELR table has an invalid entry size")
        elif relr_size:
            try:
                image.vaddr_offset(relr_addr, relr_size)
                report["has_relr"] = True
            except AuditError as exc:
                blockers.append(f"RELR table is out of bounds: {exc}")

    counts: dict[int, int] = {}
    for relocation_type, _symidx in relocations:
        counts[relocation_type] = counts.get(relocation_type, 0) + 1
    report["relocation_counts"] = {
        relocation_name(t): n for t, n in sorted(counts.items())
    }
    unsupported = {t: n for t, n in counts.items() if t not in PROTOTYPE_RELOCATIONS}
    report["unsupported_relocations"] = {
        relocation_name(t): n for t, n in sorted(unsupported.items())
    }
    if unsupported:
        blockers.append("unsupported dynamic relocation types: " + ", ".join(
            f"{relocation_name(t)} ({n})" for t, n in sorted(unsupported.items())
        ))

    symtab_addr = first_tag(tags, DT_SYMTAB, blockers, "DT_SYMTAB")
    syment = first_tag(tags, DT_SYMENT, blockers, "DT_SYMENT")
    symbol_count = dynsym_count(image, tags, blockers) if (
        symtab_addr is not None or relocations
    ) else None
    if (symtab_addr is not None or relocations) and syment != 24:
        blockers.append("dynamic symbol table lacks a valid 24-byte DT_SYMENT")
        symbol_count = None
    if symtab_addr is not None and symbol_count is None:
        blockers.append("dynamic symbol table has no usable SysV/GNU hash symbol count")
    if symbol_count is None and any(symidx for _typ, symidx in relocations):
        blockers.append("symbol relocations require DT_HASH or DT_GNU_HASH metadata")
    if symbol_count is not None and symtab_addr is not None and syment == 24:
        try:
            symtab_offset = image.vaddr_offset(symtab_addr, symbol_count * 24)
            versym_addr = first_tag(tags, DT_VERSYM, blockers, "DT_VERSYM")
            version_indices: list[int] | None = None
            if versym_addr is not None:
                raw = image.read_vaddr(versym_addr, symbol_count * 2)
                version_indices = list(struct.unpack("<" + "H" * symbol_count, raw))
                report["versioned_symbols"] = sum(
                    1 for version in version_indices if (version & 0x7FFF) > 1
                )
            symbol_types: list[int] = []
            for index in range(symbol_count):
                _name, info, _other, _shndx, _value, _size = struct.unpack_from(
                    "<IBBHQQ", data, symtab_offset + index * 24
                )
                symbol_type = info & 0xF
                symbol_types.append(symbol_type)
                if symbol_type == STT_TLS:
                    report["tls_symbols"] += 1
                if symbol_type == STT_GNU_IFUNC:
                    report["ifunc_symbols"] += 1
            used_symbols = {index for _typ, index in relocations if index < len(symbol_types) and index != 0}
            tls_relocation_types = {1028, 1029, 1030, 1031}
            if any(symbol_types[symbol_index] == STT_TLS and
                   relocation_type not in tls_relocation_types
                   for relocation_type, symbol_index in relocations
                   if symbol_index < len(symbol_types) and symbol_index != 0):
                blockers.append(
                    "a TLS symbol is referenced by a relocation outside the supported "
                    "DTPMOD64/DTPREL64/TPREL64/TLSDESC subset"
                )
            if any(symbol_types[index] == STT_GNU_IFUNC for index in used_symbols):
                blockers.append("a dynamic relocation references a GNU IFUNC symbol")
            if version_indices is not None:
                report["versioned_relocations"] = sum(
                    1 for _typ, index in relocations
                    if index < len(version_indices) and
                    (version_indices[index] & 0x7FFF) > 1
                )
                if report["versioned_relocations"]:
                    report["runtime_gaps"].append(
                        "versioned relocations are matched by exact GNU version/provider; "
                        "validate default-version interposition against the target Android libraries"
                    )
        except (AuditError, struct.error) as exc:
            blockers.append(f"cannot inspect dynamic symbol table: {exc}")

    report["prototype_loader_compatible"] = (
        image.elf_type == ET_DYN and bool(image.loads) and
        image.dynamic_segment is not None and not blockers
    )
    return report


def member_is_arm64_library(name: str) -> bool:
    parts = PurePosixPath(name).parts
    return (len(parts) >= 3 and parts[0] == "lib" and
            parts[1] == ABI_DIRECTORY and name.lower().endswith(".so"))


def inspect_archive(data: bytes, label: str, depth: int = 0) -> tuple[list[tuple[str, bytes]], list[str]]:
    libraries: list[tuple[str, bytes]] = []
    errors: list[str] = []
    if depth > 2:
        return libraries, [f"{label}: nested archive depth exceeds limit"]
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                if member_is_arm64_library(info.filename):
                    if info.file_size > MAX_ELF_BYTES:
                        errors.append(f"{label}!{info.filename}: exceeds audit size limit")
                        continue
                    try:
                        libraries.append((f"{label}!{info.filename}", archive.read(info)))
                    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                        errors.append(f"{label}!{info.filename}: cannot read: {exc}")
                elif info.filename.lower().endswith(".apk"):
                    if info.file_size > MAX_ELF_BYTES:
                        errors.append(f"{label}!{info.filename}: nested APK exceeds audit size limit")
                        continue
                    try:
                        child = archive.read(info)
                    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                        errors.append(f"{label}!{info.filename}: cannot read nested APK: {exc}")
                        continue
                    if zipfile.is_zipfile(io.BytesIO(child)):
                        nested, nested_errors = inspect_archive(
                            child, f"{label}!{info.filename}", depth + 1
                        )
                        libraries.extend(nested)
                        errors.extend(nested_errors)
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        errors.append(f"{label}: cannot inspect archive: {exc}")
    return libraries, errors


def collect_inputs(inputs: Iterable[str]) -> tuple[list[tuple[str, bytes]], list[str]]:
    found: list[tuple[str, bytes]] = []
    errors: list[str] = []
    def inspect_file(path: Path) -> None:
        label = str(path)
        try:
            size = path.stat().st_size
            if size > MAX_ELF_BYTES:
                errors.append(f"{label}: exceeds audit size limit")
                return
            if path.suffix.lower() in {".apk", ".apks"} or zipfile.is_zipfile(path):
                libs, archive_errors = inspect_archive(path.read_bytes(), label)
                found.extend(libs)
                errors.extend(archive_errors)
                if not libs and not archive_errors:
                    errors.append(f"{label}: no lib/arm64-v8a/*.so entries found")
                return
            found.append((label, path.read_bytes()))
        except OSError as exc:
            errors.append(f"{label}: cannot read input: {exc}")

    for raw in inputs:
        path = Path(os.path.expanduser(raw))
        if not path.exists():
            errors.append(f"{path}: file or directory does not exist")
        elif path.is_dir():
            candidates = sorted(p for p in path.rglob("*")
                                if p.is_file() and p.suffix.lower() in {".apk", ".apks", ".so"})
            if not candidates:
                errors.append(f"{path}: directory contains no APK or .so files")
            for candidate in candidates:
                inspect_file(candidate)
        else:
            inspect_file(path)
    return found, errors


def print_human(reports: list[dict[str, Any]], errors: list[str]) -> None:
    print("AArch64 ELF audit (static inspection only)")
    print("This is a loader-coverage report, not a guarantee that the app will start.")
    for report in reports:
        print(f"\n{report['source']}")
        print(f"  ELF:       {report['elf_class']} {report['machine_name']} {report['type']}")
        if report["soname"]:
            print(f"  SONAME:    {report['soname']}")
        print(f"  Needed:    {', '.join(report['needed']) if report['needed'] else '(none or unavailable)'}")
        if report["relocation_counts"]:
            print("  Relocs:    " + ", ".join(
                f"{name}={count}" for name, count in report["relocation_counts"].items()
            ))
        else:
            print("  Relocs:    (none detected)")
        print(f"  TLS:       segment={report['has_tls_segment']}, symbols={report['tls_symbols']}")
        print(f"  Versions:  symbols={report['versioned_symbols']}, relocations={report['versioned_relocations']}")
        print(f"  Prototype loader candidate: {'yes' if report['prototype_loader_compatible'] else 'no'}")
        for blocker in report["prototype_loader_blockers"]:
            print(f"  BLOCKER:   {blocker}")
        for gap in report["runtime_gaps"]:
            print(f"  GAP:       {gap}")
    for error in errors:
        print(f"\nERROR: {error}")


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", help="APK/APKS files, directories, or ELF shared objects")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument("--strict", action="store_true", help="return 2 if any ELF has prototype-loader blockers")
    args = parser.parse_args(argv)
    inputs, errors = collect_inputs(args.paths)
    reports = [audit_elf(data, source) for source, data in inputs]
    if args.json:
        print(json.dumps({"reports": reports, "errors": errors}, indent=2))
    else:
        print_human(reports, errors)
    blocked = any(report["prototype_loader_blockers"] for report in reports)
    return 2 if not reports or errors or (args.strict and blocked) else 0


if __name__ == "__main__":
    sys.exit(main())
