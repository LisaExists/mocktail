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
MAX_RELOCATIONS = 4_000_000
MAX_PACKED_RELA_BYTES = 64 * 1024 * 1024

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


def read_sleb128(data: bytes, position: int) -> tuple[int, int]:
    """Decode one bounded signed LEB128 value as a signed 64-bit integer."""
    value = 0
    shift = 0
    for _ in range(10):
        if position >= len(data):
            raise AuditError("truncated SLEB128 value")
        byte = data[position]
        position += 1
        payload = byte & 0x7F
        if shift == 63:
            if payload not in {0, 0x7F}:
                raise AuditError("SLEB128 value overflows signed 64-bit range")
            value |= (payload & 1) << 63
        elif shift < 63:
            value |= payload << shift
        if not byte & 0x80:
            total_shift = shift + 7
            if total_shift < 64 and byte & 0x40:
                value |= - (1 << total_shift)
            value &= (1 << 64) - 1
            if value & (1 << 63):
                value -= 1 << 64
            return value, position
        shift += 7
    raise AuditError("SLEB128 value exceeds ten bytes")


def decode_android_packed_rela(
    image: ELF64Image, address: int, size: int
) -> list[tuple[int, int]]:
    """Decode Android's APS2 RELA stream into (relocation type, symbol index)."""
    if size < 4 or size > MAX_PACKED_RELA_BYTES:
        raise AuditError("DT_ANDROID_RELA size is empty or exceeds the 64 MiB limit")
    data = image.read_vaddr(address, size)
    if data[:4] != b"APS2":
        raise AuditError("DT_ANDROID_RELA has an invalid APS2 signature")

    position = 4
    relocation_count, position = read_sleb128(data, position)
    initial_offset, position = read_sleb128(data, position)
    if relocation_count < 0 or relocation_count > MAX_RELOCATIONS or initial_offset < 0:
        raise AuditError("DT_ANDROID_RELA has invalid relocation count or initial offset")

    running_offset = initial_offset
    running_addend = 0
    relocations: list[tuple[int, int]] = []
    while len(relocations) < relocation_count:
        group_size, position = read_sleb128(data, position)
        flags, position = read_sleb128(data, position)
        if group_size <= 0 or flags < 0 or flags & ~0xF:
            raise AuditError("DT_ANDROID_RELA contains an invalid relocation group")
        if group_size > relocation_count - len(relocations):
            raise AuditError("DT_ANDROID_RELA group exceeds the declared relocation count")

        grouped_by_info = bool(flags & 1)
        grouped_by_offset_delta = bool(flags & 2)
        grouped_by_addend = bool(flags & 4)
        has_addend = bool(flags & 8)
        if grouped_by_addend and not has_addend:
            raise AuditError("DT_ANDROID_RELA groups addends without declaring them")

        group_offset_delta = 0
        group_info = 0
        if grouped_by_offset_delta:
            group_offset_delta, position = read_sleb128(data, position)
        if grouped_by_info:
            group_info, position = read_sleb128(data, position)
            if group_info < 0:
                raise AuditError("DT_ANDROID_RELA has negative relocation info")

        if not has_addend:
            running_addend = 0
        elif grouped_by_addend:
            addend_delta, position = read_sleb128(data, position)
            running_addend += addend_delta
            if not -(1 << 63) <= running_addend < (1 << 63):
                raise AuditError("DT_ANDROID_RELA grouped addend overflows signed 64-bit range")

        for _ in range(group_size):
            if grouped_by_offset_delta:
                delta = group_offset_delta
            else:
                delta, position = read_sleb128(data, position)
            running_offset += delta
            if running_offset < 0 or running_offset > (1 << 64) - 1:
                raise AuditError("DT_ANDROID_RELA relocation offset underflows or overflows")

            if grouped_by_info:
                info = group_info
            else:
                info, position = read_sleb128(data, position)
                if info < 0:
                    raise AuditError("DT_ANDROID_RELA has negative relocation info")

            if has_addend and not grouped_by_addend:
                addend_delta, position = read_sleb128(data, position)
                running_addend += addend_delta
                if not -(1 << 63) <= running_addend < (1 << 63):
                    raise AuditError("DT_ANDROID_RELA relocation addend overflows signed 64-bit range")

            relocations.append((info & 0xFFFFFFFF, info >> 32))

    if position != len(data):
        raise AuditError("DT_ANDROID_RELA has trailing or unconsumed APS2 data")
    return relocations


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



ANDROID_PLATFORM_LIBRARIES = {
    "libc.so", "libm.so", "libdl.so", "liblog.so", "libandroid.so",
    "libEGL.so", "libGLESv1_CM.so", "libGLESv2.so", "libGLESv3.so", "libvulkan.so",
    "libOpenSLES.so", "libOpenMAXAL.so", "libmediandk.so",
    "libjnigraphics.so", "libz.so",
    "libc++_shared.so", "libstdc++.so", "libaaudio.so", "libcamera2ndk.so",
    "libnativewindow.so", "libsync.so", "libui.so", "libutils.so",
    "libbinder_ndk.so", "libcrypto.so", "libssl.so", "libicuuc.so",
    "libicui18n.so", "libandroid_runtime.so",
}
# Kept in sync with guest host-call registrations in
# A64GuestHostCalls and A64GuestRuntime::Impl.
# Infer providers only for well-known Android NDK symbol families. Unversioned
# ELF imports do not encode a DT_VERNEED provider, so dependency order is not proof.
ANDROID_SYMBOL_PROVIDER_PREFIXES = {
    "__system_property_": "libc.so",
    "AMediaCodec_": "libmediandk.so",
    "AMediaFormat_": "libmediandk.so",
    "AMediaExtractor_": "libmediandk.so",
    "AMediaMuxer_": "libmediandk.so",
    "AMediaDrm_": "libmediandk.so",
    "AMediaCrypto_": "libmediandk.so",
    "AMediaDataSource_": "libmediandk.so",
    "AAsset": "libandroid.so",
    "AndroidBitmap_": "libjnigraphics.so",
    "mmap": "libc.so",
    "munmap": "libc.so",
    "mprotect": "libc.so",
    "madvise": "libc.so",
    "getpid": "libc.so",
    "gettid": "libc.so",
    "getuid": "libc.so",
    "geteuid": "libc.so",
    "getgid": "libc.so",
    "getegid": "libc.so",
    "sysconf": "libc.so",
    "prctl": "libc.so",
    "clock_gettime": "libc.so",
    "clock_gettime64": "libc.so",
    "gettimeofday": "libc.so",
    "time": "libc.so",
    "sched_yield": "libc.so",
    "__memcpy_chk": "libc.so",
    "__memmove_chk": "libc.so",
    "__memset_chk": "libc.so",
    "__strlen_chk": "libc.so",
    "SL_IID_": "libOpenSLES.so",
    "slCreateEngine": "libOpenSLES.so",
    "alCreateEngine": "libOpenMAXAL.so",
    "egl": "libEGL.so",
    "glGet": "libGLESv2.so",
    "glGen": "libGLESv2.so",
    "glCreate": "libGLESv2.so",
    "glCheck": "libGLESv2.so",
    "glViewport": "libGLESv2.so",
    "glActive": "libGLESv2.so",
    "glAttach": "libGLESv2.so",
    "glBind": "libGLESv2.so",
    "glBlend": "libGLESv2.so",
    "glBuffer": "libGLESv2.so",
    "glClear": "libGLESv2.so",
    "glColor": "libGLESv2.so",
    "glCompile": "libGLESv2.so",
    "glCompressed": "libGLESv2.so",
    "glCopy": "libGLESv2.so",
    "glCull": "libGLESv2.so",
    "glDelete": "libGLESv2.so",
    "glDepth": "libGLESv2.so",
    "glDisable": "libGLESv2.so",
    "glDraw": "libGLESv2.so",
    "glEnable": "libGLESv2.so",
    "glFramebuffer": "libGLESv2.so",
    "glGenerate": "libGLESv2.so",
    "glLink": "libGLESv2.so",
    "glPixel": "libGLESv2.so",
    "glPolygon": "libGLESv2.so",
    "glRead": "libGLESv2.so",
    "glRelease": "libGLESv2.so",
    "glRenderbuffer": "libGLESv2.so",
    "glScissor": "libGLESv2.so",
    "glShader": "libGLESv2.so",
    "glStencil": "libGLESv2.so",
    "glTex": "libGLESv2.so",
    "glUniform": "libGLESv2.so",
    "glUse": "libGLESv2.so",
    "glVertex": "libGLESv2.so",
    "ALooper_": "libandroid.so",
    "ANativeWindow_": "libandroid.so",
    "AConfiguration_": "libandroid.so",
    "AChoreographer_": "libandroid.so",
    "AInputQueue_": "libandroid.so",
    "AKeyEvent_": "libandroid.so",
    "AMotionEvent_": "libandroid.so",
    "ASensor": "libandroid.so",
    "__android_log_": "liblog.so",
}

ANDROID_SYMBOL_PROVIDER_EXACT = {
    "android_get_device_api_level": "libandroid.so",
}


def infer_android_symbol_provider(name: str) -> str:
    exact = ANDROID_SYMBOL_PROVIDER_EXACT.get(name)
    if exact:
        return exact
    for prefix, provider in ANDROID_SYMBOL_PROVIDER_PREFIXES.items():
        if name.startswith(prefix):
            return provider
    return ""

PROTOTYPE_HOST_CALLS = {
    "__cxa_atexit", "__cxa_finalize", "__errno", "__errno_location",
    "__mocktail_tlsdesc_static", "__stack_chk_fail", "__tls_get_addr", "abort",
    "calloc", "fflush", "fputs", "free",
    "malloc", "memchr", "memcmp", "memcpy",
    "memmove", "memset", "realloc", "strcasecmp",
    "strcat", "strchr", "strcmp", "strcpy",
    "strdup", "strlen", "strncasecmp", "strncat",
    "strncmp", "strncpy", "strnlen", "strrchr",
    "strstr",
}

# Names registered by the current guest runtime. Registration means the loader
# can resolve the import; it does not imply full Android API semantics. In
# particular, AMediaFormat is currently a placeholder implementation.
PROTOTYPE_REGISTERED_ANDROID_HOST_CALLS = {
    "libc.so": {
        "__system_property_area_serial", "__system_property_find",
        "__system_property_get", "__system_property_read",
        "__system_property_serial",
        "mmap", "mmap64", "munmap", "mprotect", "madvise",
        "getpid", "gettid", "getuid", "geteuid", "getgid", "getegid",
        "sysconf", "prctl", "clock_gettime", "clock_gettime64",
        "gettimeofday", "time", "sched_yield",
    },
    "libandroid.so": {
        "android_get_device_api_level",
        "ALooper_prepare", "ALooper_forThread", "ALooper_acquire",
        "ALooper_release", "ALooper_addFd", "ALooper_removeFd",
        "ALooper_wake", "ALooper_isPolling", "ALooper_pollOnce",
        "ALooper_pollAll",
        "ANativeWindow_fromSurface", "ANativeWindow_acquire",
        "ANativeWindow_release", "ANativeWindow_getWidth",
        "ANativeWindow_getHeight", "ANativeWindow_getFormat",
        "ANativeWindow_setBuffersGeometry", "ANativeWindow_lock",
        "ANativeWindow_unlockAndPost",
        "AAssetManager_fromJava", "AAssetManager_open", "AAsset_close",
        "AAsset_getLength", "AAsset_getLength64",
        "AAsset_getRemainingLength", "AAsset_getRemainingLength64",
        "AAsset_getBuffer", "AAsset_read", "AAsset_seek", "AAsset_seek64",
        "AConfiguration_new", "AConfiguration_delete",
        "AConfiguration_fromAssetManager", "AConfiguration_getLanguage",
        "AConfiguration_getCountry", "AConfiguration_getScreenSize",
        "AConfiguration_getScreenWidthDp",
        "AConfiguration_getScreenHeightDp", "AConfiguration_getNavHidden",
    },
    "liblog.so": {
        "__android_log_buf_write", "__android_log_is_loggable",
        "__android_log_print", "__android_log_write",
    },
    "libEGL.so": {
        "eglGetDisplay", "eglInitialize", "eglBindAPI", "eglChooseConfig",
        "eglGetConfigAttrib", "eglCreateWindowSurface",
        "eglCreatePbufferSurface", "eglCreateContext", "eglMakeCurrent",
        "eglGetCurrentContext", "eglGetCurrentSurface",
        "eglGetCurrentDisplay", "eglSwapBuffers", "eglSwapInterval",
        "eglQuerySurface", "eglQueryString", "eglDestroyContext",
        "eglDestroySurface", "eglTerminate", "eglGetProcAddress",
        "eglGetError",
    },
    "libGLESv2.so": {
        "glGetString", "glGetError", "glGetIntegerv",
        "glGenTextures", "glGenBuffers", "glGenFramebuffers",
        "glGenRenderbuffers", "glCreateShader", "glCreateProgram",
        "glGetShaderiv", "glGetProgramiv", "glGetShaderInfoLog",
        "glGetProgramInfoLog", "glGetActiveUniform",
        "glGetUniformLocation", "glCheckFramebufferStatus", "glViewport",
        "glActiveTexture", "glAttachShader", "glBindAttribLocation",
        "glBindBuffer", "glBindFramebuffer", "glBindRenderbuffer",
        "glBindTexture", "glBlendFunc", "glBlendFuncSeparate",
        "glBufferData", "glBufferSubData", "glClear", "glClearColor",
        "glClearDepthf", "glClearStencil", "glColorMask", "glCompileShader",
        "glCompressedTexImage2D", "glCompressedTexSubImage2D",
        "glCopyTexSubImage2D", "glCullFace", "glDeleteBuffers",
        "glDeleteFramebuffers", "glDeleteProgram", "glDeleteRenderbuffers",
        "glDeleteShader", "glDeleteTextures", "glDepthFunc", "glDepthMask",
        "glDisable", "glDisableVertexAttribArray", "glDrawArrays",
        "glDrawElements", "glEnable", "glEnableVertexAttribArray",
        "glFramebufferRenderbuffer", "glFramebufferTexture2D",
        "glGenerateMipmap", "glLinkProgram", "glPixelStorei",
        "glPolygonOffset", "glReadPixels", "glReleaseShaderCompiler",
        "glRenderbufferStorage", "glScissor", "glShaderSource",
        "glStencilFunc", "glStencilMask", "glStencilOp", "glTexImage2D",
        "glTexParameterf", "glTexParameterfv", "glTexParameteri",
        "glTexSubImage2D", "glUniform1i", "glUseProgram",
        "glVertexAttribPointer",
    },
    "libjnigraphics.so": {
        "AndroidBitmap_getInfo", "AndroidBitmap_lockPixels",
        "AndroidBitmap_unlockPixels",
    },
    "libOpenSLES.so": {
        "slCreateEngine",
        "SL_IID_ANDROIDCONFIGURATION", "SL_IID_ANDROIDSIMPLEBUFFERQUEUE",
        "SL_IID_BUFFERQUEUE", "SL_IID_ENGINE", "SL_IID_PLAY",
        "SL_IID_RECORD", "SL_IID_VOLUME",
    },
    "libOpenMAXAL.so": {"alCreateEngine"},
    "libmediandk.so": {
        "AMediaFormat_new", "AMediaFormat_delete", "AMediaFormat_toString",
        "AMediaFormat_setInt32", "AMediaFormat_setInt64",
        "AMediaFormat_setFloat", "AMediaFormat_setDouble",
        "AMediaFormat_setSize", "AMediaFormat_setString",
        "AMediaFormat_setBuffer", "AMediaFormat_setRect",
        "AMediaFormat_getInt32", "AMediaFormat_getInt64",
        "AMediaFormat_getFloat", "AMediaFormat_getDouble",
        "AMediaFormat_getSize", "AMediaFormat_getString",
        "AMediaFormat_getBuffer", "AMediaFormat_getRect",
        "AMEDIAFORMAT_KEY_AAC_PROFILE", "AMEDIAFORMAT_KEY_BIT_RATE",
        "AMEDIAFORMAT_KEY_BITRATE_MODE", "AMEDIAFORMAT_KEY_CHANNEL_COUNT",
        "AMEDIAFORMAT_KEY_COLOR_FORMAT", "AMEDIAFORMAT_KEY_COLOR_RANGE",
        "AMEDIAFORMAT_KEY_COLOR_STANDARD", "AMEDIAFORMAT_KEY_COLOR_TRANSFER",
        "AMEDIAFORMAT_KEY_COMPLEXITY", "AMEDIAFORMAT_KEY_CROP_BOTTOM",
        "AMEDIAFORMAT_KEY_CROP_LEFT", "AMEDIAFORMAT_KEY_CROP_RIGHT",
        "AMEDIAFORMAT_KEY_CROP_TOP", "AMEDIAFORMAT_KEY_CSD_0",
        "AMEDIAFORMAT_KEY_CSD_1", "AMEDIAFORMAT_KEY_CSD_2",
        "AMEDIAFORMAT_KEY_DISPLAY_HEIGHT", "AMEDIAFORMAT_KEY_DISPLAY_WIDTH",
        "AMEDIAFORMAT_KEY_DURATION", "AMEDIAFORMAT_KEY_ENCODER_DELAY",
        "AMEDIAFORMAT_KEY_ENCODER_PADDING",
        "AMEDIAFORMAT_KEY_FLAC_COMPRESSION_LEVEL",
        "AMEDIAFORMAT_KEY_FRAME_RATE", "AMEDIAFORMAT_KEY_HDR_STATIC_INFO",
        "AMEDIAFORMAT_KEY_HEIGHT", "AMEDIAFORMAT_KEY_INTRA_REFRESH_PERIOD",
        "AMEDIAFORMAT_KEY_IS_ADTS", "AMEDIAFORMAT_KEY_IS_AUTOSELECT",
        "AMEDIAFORMAT_KEY_IS_DEFAULT", "AMEDIAFORMAT_KEY_IS_FORCED_SUBTITLE",
        "AMEDIAFORMAT_KEY_I_FRAME_INTERVAL", "AMEDIAFORMAT_KEY_LANGUAGE",
        "AMEDIAFORMAT_KEY_LEVEL", "AMEDIAFORMAT_KEY_MAX_B_FRAMES",
        "AMEDIAFORMAT_KEY_MAX_FPS_TO_ENCODER", "AMEDIAFORMAT_KEY_MAX_HEIGHT",
        "AMEDIAFORMAT_KEY_MAX_INPUT_SIZE",
        "AMEDIAFORMAT_KEY_MAX_PTS_GAP_TO_ENCODER",
        "AMEDIAFORMAT_KEY_MAX_WIDTH", "AMEDIAFORMAT_KEY_MIME",
        "AMEDIAFORMAT_KEY_OPERATING_RATE", "AMEDIAFORMAT_KEY_PCM_ENCODING",
        "AMEDIAFORMAT_KEY_PROFILE", "AMEDIAFORMAT_KEY_PRIORITY",
        "AMEDIAFORMAT_KEY_PUSH_BLANK_BUFFERS_ON_STOP",
        "AMEDIAFORMAT_KEY_QUALITY",
        "AMEDIAFORMAT_KEY_REPEAT_PREVIOUS_FRAME_AFTER",
        "AMEDIAFORMAT_KEY_ROTATION", "AMEDIAFORMAT_KEY_SAMPLE_RATE",
        "AMEDIAFORMAT_KEY_SLICE_HEIGHT", "AMEDIAFORMAT_KEY_STRIDE",
        "AMEDIAFORMAT_KEY_TEMPORAL_LAYERING", "AMEDIAFORMAT_KEY_WIDTH",

        "AMediaCodec_createDecoderByType",
        "AMediaCodec_createEncoderByType", "AMediaCodec_delete",
        "AMediaCodec_configure", "AMediaCodec_start",
        "AMediaCodec_stop", "AMediaCodec_flush",
        "AMediaCodec_getInputBuffer", "AMediaCodec_getOutputBuffer",
        "AMediaCodec_dequeueInputBuffer", "AMediaCodec_dequeueOutputBuffer",
        "AMediaCodec_queueInputBuffer", "AMediaCodec_releaseOutputBuffer",
        "AMediaCodec_getOutputFormat",    },
}


def is_registered_prototype_host_call(
        name: str, provider: str, version: str) -> bool:
    if name in PROTOTYPE_HOST_CALLS:
        if not version:
            return True
        return (provider in ANDROID_PLATFORM_LIBRARIES and
                is_supported_android_symbol_version(version))
    if name not in PROTOTYPE_REGISTERED_ANDROID_HOST_CALLS.get(provider, set()):
        return False
    if not version:
        return True
    return is_supported_android_symbol_version(version)



def version_requirements(image: ELF64Image, tags: dict[int, list[int]],
                         blockers: list[str]) -> dict[int, dict[str, str]]:
    address = first_tag(tags, DT_VERNEED, blockers, "DT_VERNEED")
    count = first_tag(tags, DT_VERNEEDNUM, blockers, "DT_VERNEEDNUM")
    if (address is None) != (count is None):
        blockers.append("DT_VERNEED and DT_VERNEEDNUM must be provided together")
        return {}
    if address is None or count == 0:
        return {}
    if count is None or count > MAX_DYNAMIC_ENTRIES:
        blockers.append("DT_VERNEEDNUM exceeds the audit record limit")
        return {}

    requirements: dict[int, dict[str, str]] = {}
    current = address
    try:
        for record_index in range(count):
            version, aux_count, provider_offset, aux_offset, next_offset = (
                struct.unpack("<HHIII", image.read_vaddr(current, 16))
            )
            if version != 1 or aux_count == 0 or aux_count > MAX_SYMBOLS or aux_offset == 0:
                raise AuditError("DT_VERNEED contains invalid record metadata")
            provider = dynamic_string(image, tags, provider_offset, blockers)
            if not provider:
                raise AuditError("DT_VERNEED provider name is empty or invalid")
            auxiliary = current + aux_offset
            for aux_index in range(aux_count):
                _hash, _flags, other, name_offset, aux_next = struct.unpack(
                    "<IHHII", image.read_vaddr(auxiliary, 16)
                )
                version_index = other & 0x7FFF
                version_name = dynamic_string(image, tags, name_offset, blockers)
                if version_index < 2 or not version_name:
                    raise AuditError("DT_VERNEED auxiliary has an invalid index/name")
                if version_index in requirements:
                    raise AuditError("DT_VERNEED repeats a symbol-version index")
                requirements[version_index] = {
                    "version": version_name,
                    "provider": provider,
                }
                if aux_index + 1 < aux_count:
                    if aux_next == 0:
                        raise AuditError("DT_VERNEED auxiliary chain is truncated")
                    auxiliary += aux_next
                elif aux_next != 0:
                    raise AuditError("DT_VERNEED auxiliary chain exceeds its count")
            if record_index + 1 < count:
                if next_offset == 0:
                    raise AuditError("DT_VERNEED chain is shorter than DT_VERNEEDNUM")
                current += next_offset
            elif next_offset != 0:
                raise AuditError("DT_VERNEED chain exceeds DT_VERNEEDNUM")
    except (AuditError, struct.error) as exc:
        blockers.append(f"cannot inspect DT_VERNEED: {exc}")
        return {}
    return requirements


def version_definitions(image: ELF64Image, tags: dict[int, list[int]],
                        blockers: list[str]) -> dict[int, str]:
    address = first_tag(tags, DT_VERDEF, blockers, "DT_VERDEF")
    count = first_tag(tags, DT_VERDEFNUM, blockers, "DT_VERDEFNUM")
    if (address is None) != (count is None):
        blockers.append("DT_VERDEF and DT_VERDEFNUM must be provided together")
        return {}
    if address is None or count == 0:
        return {}
    if count is None or count > MAX_DYNAMIC_ENTRIES:
        blockers.append("DT_VERDEFNUM exceeds the audit record limit")
        return {}

    definitions: dict[int, str] = {}
    current = address
    try:
        for record_index in range(count):
            version, _flags, index, aux_count, _hash, aux_offset, next_offset = (
                struct.unpack("<HHHHIII", image.read_vaddr(current, 20))
            )
            version_index = index & 0x7FFF
            if version != 1 or version_index == 0 or aux_count == 0 or aux_count > MAX_SYMBOLS or aux_offset == 0:
                raise AuditError("DT_VERDEF contains invalid record metadata")
            auxiliary = current + aux_offset
            first_name = ""
            for aux_index in range(aux_count):
                name_offset, aux_next = struct.unpack(
                    "<II", image.read_vaddr(auxiliary, 8)
                )
                name = dynamic_string(image, tags, name_offset, blockers)
                if not name:
                    raise AuditError("DT_VERDEF auxiliary has an empty version name")
                if aux_index == 0:
                    first_name = name
                if aux_index + 1 < aux_count:
                    if aux_next == 0:
                        raise AuditError("DT_VERDEF auxiliary chain is truncated")
                    auxiliary += aux_next
                elif aux_next != 0:
                    raise AuditError("DT_VERDEF auxiliary chain exceeds its count")
            if version_index in definitions:
                raise AuditError("DT_VERDEF repeats a symbol-version index")
            definitions[version_index] = first_name
            if record_index + 1 < count:
                if next_offset == 0:
                    raise AuditError("DT_VERDEF chain is shorter than DT_VERDEFNUM")
                current += next_offset
            elif next_offset != 0:
                raise AuditError("DT_VERDEF chain exceeds DT_VERDEFNUM")
    except (AuditError, struct.error) as exc:
        blockers.append(f"cannot inspect DT_VERDEF: {exc}")
        return {}
    return definitions


def audit_elf(data: bytes, source: str = "<memory>") -> dict[str, Any]:
    report: dict[str, Any] = {
        "source": source, "elf_class": "unknown", "machine": None,
        "machine_name": "unknown", "type": "unknown", "soname": None,
        "needed": [], "imports": [], "exports": [],
        "relocation_counts": {}, "unsupported_relocations": {},
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
            "preloaded static TLS, static TLSDESC and the guest __tls_get_addr "
            "lookup thunk are supported; Bionic TCB/DTV, dlopen-style dynamic "
            "TLS, and guest pthread scheduling remain gaps"
        )

    tags = image.dynamic_tags(blockers)
    required_versions = version_requirements(image, tags, blockers)
    defined_versions = version_definitions(image, tags, blockers)
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

    relocations: list[tuple[int, int]] = []
    android_rela_addr = first_tag(tags, DT_ANDROID_RELA, blockers, "DT_ANDROID_RELA")
    android_rela_size = first_tag(tags, DT_ANDROID_RELASZ, blockers, "DT_ANDROID_RELASZ")
    if (android_rela_addr is None) != (android_rela_size is None):
        blockers.append("DT_ANDROID_RELA and DT_ANDROID_RELASZ must be provided together")
    elif android_rela_addr is not None and android_rela_size is not None:
        if android_rela_size == 0:
            blockers.append("DT_ANDROID_RELA is present with an empty relocation stream")
        else:
            report["has_android_packed_rela"] = True
            try:
                relocations.extend(
                    decode_android_packed_rela(image, android_rela_addr, android_rela_size)
                )
            except AuditError as exc:
                blockers.append(f"invalid APS2 packed RELA: {exc}")

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
    # Android linkers can leave a zero-sized DT_RELASZ placeholder after moving
    # conventional RELA entries into APS2-packed RELA and/or RELR tables.
    has_alternative_relocation_table = (
        report["has_android_packed_rela"]
        or DT_RELR in tags
        or DT_ANDROID_RELR in tags
    )
    empty_rela_placeholder = has_alternative_relocation_table and (
        (
            tags.get(DT_RELASZ) == [0]
            and (
                DT_RELAENT not in tags or tags.get(DT_RELAENT) == [24]
            )
        )
        or (
            DT_RELA not in tags
            and DT_RELASZ not in tags
            and tags.get(DT_RELAENT) == [24]
        )
    )
    if any(rela_metadata) and not empty_rela_placeholder:
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
            if ((DT_VERNEED in tags or DT_VERNEEDNUM in tags or
                 DT_VERDEF in tags or DT_VERDEFNUM in tags) and versym_addr is None):
                blockers.append("DT_VERNEED/DT_VERDEF requires DT_VERSYM")

            symbol_types: list[int] = []
            symbol_rows: list[tuple[str, int, int, int, int, int]] = []
            for index in range(symbol_count):
                name_offset, info, other, section_index, value, size = (
                    struct.unpack_from("<IBBHQQ", data, symtab_offset + index * 24)
                )
                symbol_type = info & 0xF
                symbol_types.append(symbol_type)
                symbol_rows.append(
                    (dynamic_string(image, tags, name_offset, blockers) or "",
                     info >> 4, other & 0x3, section_index, value, size)
                )
                if symbol_type == STT_TLS:
                    report["tls_symbols"] += 1
                if symbol_type == STT_GNU_IFUNC:
                    report["ifunc_symbols"] += 1

            used_symbols = {
                symbol_index for _typ, symbol_index in relocations
                if 0 < symbol_index < len(symbol_types)
            }
            tls_relocation_types = {1028, 1029, 1030, 1031}
            if any(symbol_types[symbol_index] == STT_TLS and
                   relocation_type not in tls_relocation_types
                   for relocation_type, symbol_index in relocations
                   if 0 < symbol_index < len(symbol_types)):
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

            seen_imports: set[tuple[str, str, str]] = set()
            for symbol_index in sorted(used_symbols):
                name, binding, visibility, section_index, _value, _size = symbol_rows[symbol_index]
                if section_index != 0 or not name or binding not in {1, 2, 10} or visibility not in {0, 3}:
                    continue
                version_name = ""
                provider = ""
                version_index = 0
                if version_indices is not None:
                    version_index = version_indices[symbol_index] & 0x7FFF
                    if version_index > 1:
                        required = required_versions.get(version_index)
                        if required is None:
                            blockers.append(
                                f"undefined symbol {name} references a missing DT_VERNEED index {version_index}"
                            )
                        else:
                            version_name = required["version"]
                            provider = required["provider"]
                identity = (name, version_name, provider)
                if identity in seen_imports:
                    continue
                seen_imports.add(identity)
                report["imports"].append({
                    "name": name,
                    "version": version_name,
                    "provider": provider,
                    "binding": "WEAK" if binding == 2 else ("GNU_UNIQUE" if binding == 10 else "GLOBAL"),
                    "tls": symbol_types[symbol_index] == STT_TLS,
                })

            seen_exports: set[tuple[str, str, bool]] = set()
            for symbol_index, row in enumerate(symbol_rows):
                name, binding, visibility, section_index, _value, _size = row
                if section_index in {0, 0xFFF2, 0xFFFF} or not name:
                    continue
                if binding not in {1, 2, 10} or visibility not in {0, 3}:
                    continue
                version_name = ""
                hidden = False
                if version_indices is not None:
                    raw_version = version_indices[symbol_index]
                    version_index = raw_version & 0x7FFF
                    hidden = bool(raw_version & 0x8000)
                    if version_index > 1:
                        version_name = defined_versions.get(version_index, "")
                        if not version_name:
                            blockers.append(
                                f"defined symbol {name} references a missing DT_VERDEF index {version_index}"
                            )
                identity = (name, version_name, hidden)
                if identity in seen_exports:
                    continue
                seen_exports.add(identity)
                report["exports"].append({
                    "name": name,
                    "version": version_name,
                    "version_hidden": hidden,
                    "binding": "WEAK" if binding == 2 else ("GNU_UNIQUE" if binding == 10 else "GLOBAL"),
                    "tls": symbol_types[symbol_index] == STT_TLS,
                })
        except (AuditError, struct.error) as exc:
            blockers.append(f"cannot inspect dynamic symbol table: {exc}")

    report["prototype_loader_compatible"] = (
        image.elf_type == ET_DYN and bool(image.loads) and
        image.dynamic_segment is not None and not blockers
    )
    return report



def is_supported_android_symbol_version(version: str) -> bool:
    # Keep this namespace list aligned with A64GuestHostCalls' provider-scoped
    # Android version fallback. Media NDK exports use LIBMEDIANDK.
    bases = ("LIBC", "LIBM", "LIBDL", "LIBLOG", "LIBANDROID", "LIBMEDIANDK")
    if version in bases:
        return True
    for base in bases:
        if (len(version) == len(base) + 2 and
                version.startswith(base + "_") and
                "A" <= version[-1] <= "Z"):
            return True
    return False


def audit_catalog(reports: list[dict[str, Any]]) -> dict[str, Any]:
    """Resolve package dependency closures and expose remaining platform API gaps."""
    aliases: dict[str, list[dict[str, Any]]] = {}
    for report in reports:
        source_path = report.get("source", "")
        basename = PurePosixPath(source_path.replace("!", "/")).name
        for alias in {report.get("soname") or "", basename}:
            if alias:
                aliases.setdefault(alias, []).append(report)

    soname_conflicts = []
    for alias, candidates in sorted(aliases.items()):
        distinct_sources = sorted({item.get("source", "") for item in candidates})
        if len(distinct_sources) > 1 and alias in {item.get("soname") for item in candidates}:
            soname_conflicts.append({"soname": alias, "sources": distinct_sources})

    def dependency_scope(root: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
        """Return package libraries and platform libraries reachable from root."""
        package_scope: list[dict[str, Any]] = []
        platform_scope: list[str] = []
        queue = list(root.get("needed", []))
        seen_names: set[str] = set()
        seen_sources = {root.get("source", "")}
        cursor = 0
        while cursor < len(queue):
            dependency = queue[cursor]
            cursor += 1
            if dependency in seen_names:
                continue
            seen_names.add(dependency)
            candidates = aliases.get(dependency, [])
            if candidates:
                for candidate in candidates:
                    candidate_source = candidate.get("source", "")
                    if candidate_source in seen_sources:
                        continue
                    seen_sources.add(candidate_source)
                    package_scope.append(candidate)
                    queue.extend(candidate.get("needed", []))
            elif dependency in ANDROID_PLATFORM_LIBRARIES:
                platform_scope.append(dependency)
        return package_scope, platform_scope

    missing_dependencies = []
    external_platform_dependencies = []
    unresolved_package_symbols = []
    platform_symbol_requirements = []
    unresolved_symbols = []
    dependency_closures = []

    # Dependency diagnostics cover every supplied library, not just the root's
    # reachable closure, so an incomplete split package cannot hide an orphan.
    for report in reports:
        source = report.get("source", "")
        needed = report.get("needed", [])
        for dependency in needed:
            if dependency in aliases:
                continue
            if dependency in ANDROID_PLATFORM_LIBRARIES:
                external_platform_dependencies.append({
                    "source": source, "dependency": dependency
                })
            else:
                missing_dependencies.append({
                    "source": source, "dependency": dependency
                })

        package_scope, platform_scope = dependency_scope(report)
        dependency_closures.append({
            "source": source,
            "package_dependencies": [
                item.get("soname") or PurePosixPath(
                    item.get("source", "").replace("!", "/")
                ).name for item in package_scope
            ],
            "platform_dependencies": platform_scope,
        })

        for item in report.get("imports", []):
            name = item.get("name", "")
            version = item.get("version", "")
            provider = item.get("provider", "")

            if provider:
                provider_names = [provider]
                package_providers = list(aliases.get(provider, []))
                external_providers = (
                    [] if package_providers or provider not in ANDROID_PLATFORM_LIBRARIES
                    else [provider]
                )
            else:
                provider_names = needed
                package_providers = package_scope
                external_providers = platform_scope

            matched = False
            for candidate in package_providers:
                for export in candidate.get("exports", []):
                    if export.get("name") != name:
                        continue
                    if version:
                        if export.get("version") == version:
                            matched = True
                            break
                    elif not export.get("version") or not export.get("version_hidden"):
                        matched = True
                        break
                if matched:
                    break
            if matched:
                continue

            # Unversioned imports and known public Bionic version namespaces can
            # use provider-matched prototype shims. Unknown/private versions stay
            # strict; a named export in another dependency cannot mask coverage.
            inferred_provider = provider or infer_android_symbol_provider(name)
            if is_registered_prototype_host_call(
                    name, inferred_provider, version):
                continue

            provider_description: Any = provider or provider_names
            if package_providers:
                if external_providers:
                    platform_symbol_requirements.append({
                        "source": source, "symbol": name, "version": version,
                        "provider": provider or external_providers[0],
                        "prototype_host_call": False,
                        "host_call_name_known": name in PROTOTYPE_HOST_CALLS,
                        "versioned_host_call_needs_registration":
                            bool(version and name in PROTOTYPE_HOST_CALLS),
                    })
                else:
                    unresolved_package_symbols.append({
                        "source": source, "symbol": name,
                        "version": version, "provider": provider_description,
                    })
                continue

            if external_providers:
                inferred_provider = infer_android_symbol_provider(name)
                platform_symbol_requirements.append({
                    "source": source, "symbol": name, "version": version,
                    "provider": provider or inferred_provider,
                    "provider_candidates": (
                        [inferred_provider]
                        if inferred_provider in external_providers
                        else external_providers
                    ),
                    "prototype_host_call": False,
                    "host_call_name_known": name in PROTOTYPE_HOST_CALLS,
                    "versioned_host_call_needs_registration":
                        bool(version and name in PROTOTYPE_HOST_CALLS),
                })
            else:
                unresolved_symbols.append({
                    "source": source, "symbol": name, "version": version,
                    "provider": provider,
                })

    def deduplicate(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        # JSON gives deterministic hashable keys even when a diagnostic contains
        # a list of candidate providers.
        unique: dict[str, dict[str, Any]] = {}
        for item in items:
            unique[json.dumps(item, sort_keys=True)] = item
        return list(unique.values())

    missing_dependencies = deduplicate(missing_dependencies)
    external_platform_dependencies = deduplicate(external_platform_dependencies)
    unresolved_package_symbols = deduplicate(unresolved_package_symbols)
    platform_symbol_requirements = deduplicate(platform_symbol_requirements)
    unresolved_symbols = deduplicate(unresolved_symbols)
    dependency_closures = deduplicate(dependency_closures)

    return {
        "library_count": len(reports),
        "soname_conflicts": soname_conflicts,
        "dependency_closures": dependency_closures,
        "missing_package_dependencies": missing_dependencies,
        "external_platform_dependencies": external_platform_dependencies,
        "unresolved_package_symbols": unresolved_package_symbols,
        "platform_symbol_requirements": platform_symbol_requirements,
        "unclassified_unresolved_symbols": unresolved_symbols,
        "prototype_host_call_symbols": sorted(PROTOTYPE_HOST_CALLS),
        "prototype_registered_android_host_calls": {
            provider: sorted(names)
            for provider, names in sorted(
                PROTOTYPE_REGISTERED_ANDROID_HOST_CALLS.items()
            )
        },
        "ready_to_launch": False,
        "runtime_gaps": [
            "static audit does not prove Android/Bionic startup or JNI compatibility",
            "platform imports are reported as requirements and are not automatically implemented",
            "guest threading, Android services, graphics, input/audio and process lifecycle remain separate runtime work",
        ],
    }


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
    catalog = audit_catalog(reports)
    print("\nPackage dependency/API summary")
    print(f"  ARM64 libraries: {catalog['library_count']}")
    print(f"  Missing package dependencies: {len(catalog['missing_package_dependencies'])}")
    print(f"  Unresolved package symbols: {len(catalog['unresolved_package_symbols'])}")
    print(f"  Platform symbol requirements not covered by prototype thunks: {len(catalog['platform_symbol_requirements'])}")
    print(f"  Unclassified unresolved symbols: {len(catalog['unclassified_unresolved_symbols'])}")
    for item in catalog["soname_conflicts"]:
        print(f"  SONAME CONFLICT: {item['soname']}: {', '.join(item['sources'])}")
    for item in catalog["missing_package_dependencies"][:50]:
        print(f"  MISSING DEP: {item['source']}: {item['dependency']}")
    for item in catalog["unresolved_package_symbols"][:50]:
        suffix = f"@{item['version']}" if item["version"] else ""
        print(f"  PACKAGE SYMBOL GAP: {item['source']}: {item['symbol']}{suffix}")
    for item in catalog["platform_symbol_requirements"][:50]:
        suffix = f"@{item['version']}" if item["version"] else ""
        provider = f" from {item['provider']}" if item["provider"] else ""
        print(f"  PLATFORM API GAP: {item['source']}: {item['symbol']}{suffix}{provider}")
    for item in catalog["unclassified_unresolved_symbols"][:50]:
        print(f"  UNRESOLVED SYMBOL: {item['source']}: {item['symbol']}")
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
    catalog = audit_catalog(reports)
    if args.json:
        print(json.dumps({"reports": reports, "catalog": catalog, "errors": errors}, indent=2))
    else:
        print_human(reports, errors)
    blocked = any(report["prototype_loader_blockers"] for report in reports)
    catalog_blocked = bool(
        catalog["missing_package_dependencies"] or
        catalog["soname_conflicts"] or
        catalog["unresolved_package_symbols"] or
        catalog["unclassified_unresolved_symbols"]
    )
    return 2 if not reports or errors or (args.strict and (blocked or catalog_blocked)) else 0


if __name__ == "__main__":
    sys.exit(main())
