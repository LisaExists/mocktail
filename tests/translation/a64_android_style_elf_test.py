#!/usr/bin/env python3
"""Assert that the Android-targeted fixture actually contains APS2 symbol relocations."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
AUDIT_SCRIPT = REPO_ROOT / "tools" / "a64-elf-audit.py"
SPEC = importlib.util.spec_from_file_location("mocktail_a64_android_style_audit", AUDIT_SCRIPT)
assert SPEC and SPEC.loader
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: a64_android_style_elf_test.py ANDROID_TARGETED_ELF", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    try:
        data = path.read_bytes()
    except OSError as exc:
        print(f"cannot read Android-targeted ELF {path}: {exc}", file=sys.stderr)
        return 2

    report = AUDIT.audit_elf(data, str(path))
    if not report["has_android_packed_rela"]:
        print("Android-targeted fixture did not contain DT_ANDROID_RELA/APS2", file=sys.stderr)
        return 1
    if report["relocation_counts"].get("R_AARCH64_GLOB_DAT", 0) < 1:
        print(
            "Android-targeted fixture did not contain the expected symbol-based "
            "R_AARCH64_GLOB_DAT relocation",
            file=sys.stderr,
        )
        return 1
    if not report["prototype_loader_compatible"]:
        print(
            "Android-targeted fixture is blocked by the audit: "
            + "; ".join(report["prototype_loader_blockers"]),
            file=sys.stderr,
        )
        return 1

    print("[PASS] Android-targeted ELF contains classifiable APS2 GLOB_DAT relocations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
