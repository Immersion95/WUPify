#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WUPify.py

Features:
  1) Add .app to files without an extension
  2) Keep only highest tmd.XXX -> rename to title.tmd (delete lower ones)
  3) Keep only highest cetk.XXX -> rename to title.tik (delete lower ones)
  4) Copy title.cert (adjacent to this script or --cert-path) ONLY to folders that contain BOTH title.tmd and title.tik
     - Verify title.cert hashes before copying:
         CRC32: 0B80C239
         MD5  : 420D5E6BB1BCB09B234F02CF6A6F4597

Output style:
  - English messages
  - No per-file details
  - Final summary with success/skip/error counts
  - List of problematic folders (path + reason)

Examples:
  python WUPify.py --path . --recursive
  python WUPify.py --path . --only-cert --cert-path /path/to/title.cert --force-cert
"""

from __future__ import annotations
import argparse
import logging
import sys
import re
from pathlib import Path
import shutil
from typing import Iterable, List, Tuple
import hashlib
import zlib

EXPECTED_CRC32 = "0B80C239"
EXPECTED_MD5   = "420D5E6BB1BCB09B234F02CF6A6F4597"

# --------------------------------------------------------------------
# Logging (summary-oriented: INFO shows only step headers + totals)
# --------------------------------------------------------------------
def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s | %(message)s")

# --------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------
def iter_files(base: Path, recursive: bool) -> Iterable[Path]:
    if recursive:
        yield from (p for p in base.rglob("*") if p.is_file())
    else:
        yield from (p for p in base.iterdir() if p.is_file())

def file_exists_case_insensitive(d: Path, name: str) -> Path | None:
    lname = name.lower()
    for p in d.iterdir():
        if p.is_file() and p.name.lower() == lname:
            return p
    return None

def compute_crc32_hex(data: bytes) -> str:
    return f"{zlib.crc32(data) & 0xFFFFFFFF:08X}"

def compute_md5_hex(data: bytes) -> str:
    return hashlib.md5(data).hexdigest().upper()

# --------------------------------------------------------------------
# Step 1: add .app to files without extension
# --------------------------------------------------------------------
def add_app_extension(base: Path, recursive: bool, dry_run: bool) -> Tuple[int, int, List[Tuple[Path, str]]]:
    renamed = 0
    skipped = 0
    problems: List[Tuple[Path, str]] = []
    for f in iter_files(base, recursive):
        if f.suffix == "" and not f.name.startswith("."):
            target = f.with_suffix(".app")
            if target.exists():
                skipped += 1
                problems.append((f.parent, f"skip .app: target exists ({target.name})"))
                continue
            try:
                if not dry_run:
                    f.rename(target)
                renamed += 1
            except Exception as e:
                problems.append((f.parent, f".app rename failed: {e}"))
    return renamed, skipped, problems

# --------------------------------------------------------------------
# Steps 2 & 3: numbered series (tmd.XXX / cetk.XXX)
# --------------------------------------------------------------------
def process_numbered_series(
    base: Path,
    recursive: bool,
    dry_run: bool,
    overwrite: bool,
    prefix: str,
    target_name: str,
) -> Tuple[int, int, int, List[Tuple[Path, str]]]:
    """
    Keep highest `<prefix>.NUM` -> rename to `target_name`, delete lower ones.
    Returns (changed_dirs, skipped_dirs, deleted_files_count, problems[])
    """
    pattern = re.compile(rf"^{re.escape(prefix)}\.(\d+)$", re.IGNORECASE)
    changed_dirs = 0
    skipped_dirs = 0
    deleted_files = 0
    problems: List[Tuple[Path, str]] = []

    dirs = {base}
    if recursive:
        dirs |= {d for d in base.rglob("*") if d.is_dir()}

    for d in sorted(dirs):
        try:
            numbered = []
            for f in d.iterdir():
                if f.is_file():
                    m = pattern.match(f.name)
                    if m:
                        numbered.append((int(m.group(1)), f))
            if not numbered:
                continue

            numbered.sort(key=lambda x: x[0])
            _, highest_file = numbered[-1]
            lower_files = [f for _, f in numbered[:-1]]
            target = d / target_name

            if target.exists() and not overwrite:
                skipped_dirs += 1
                # still delete lower ones
                for lf in lower_files:
                    try:
                        if not dry_run:
                            lf.unlink(missing_ok=True)
                        deleted_files += 1
                    except Exception as e:
                        problems.append((d, f"delete lower {prefix} failed: {lf.name}: {e}"))
                problems.append((d, f"skip {prefix}: {target_name} exists (use --overwrite)"))
                continue

            # rename highest
            try:
                if target.exists() and overwrite and not dry_run:
                    target.unlink()
                if not dry_run:
                    highest_file.rename(target)
            except Exception as e:
                skipped_dirs += 1
                problems.append((d, f"rename highest {prefix} -> {target_name} failed: {e}"))
                continue

            # delete lower ones
            for lf in lower_files:
                try:
                    if not dry_run:
                        lf.unlink(missing_ok=True)
                    deleted_files += 1
                except Exception as e:
                    problems.append((d, f"delete lower {prefix} failed: {lf.name}: {e}"))

            changed_dirs += 1
        except Exception as e:
            problems.append((d, f"series processing failed for {prefix}: {e}"))

    return changed_dirs, skipped_dirs, deleted_files, problems

# --------------------------------------------------------------------
# Step 4: copy title.cert if BOTH title.tmd and title.tik exist (with hash checks)
# --------------------------------------------------------------------
def copy_title_cert(
    base: Path,
    recursive: bool,
    dry_run: bool,
    cert_path: Path | None,
    force: bool
) -> Tuple[int, int, List[Tuple[Path, str]]]:
    """
    Returns (copied_count, skipped_count, problems[])
    """
    source_cert = cert_path if cert_path is not None else Path(__file__).resolve().parent / "title.cert"
    problems: List[Tuple[Path, str]] = []
    if not source_cert.exists():
        problems.append((source_cert.parent, f"title.cert not found at {source_cert}"))
        return 0, 0, problems

    # Verify hashes once
    data = source_cert.read_bytes()
    crc32_hex = compute_crc32_hex(data)
    md5_hex = compute_md5_hex(data)
    if crc32_hex != EXPECTED_CRC32 or md5_hex != EXPECTED_MD5:
        problems.append((source_cert.parent,
                         f"title.cert hash check failed: CRC32={crc32_hex} (expected {EXPECTED_CRC32}), "
                         f"MD5={md5_hex} (expected {EXPECTED_MD5})"))
        return 0, 0, problems

    dirs_to_check = [base]
    if recursive:
        dirs_to_check.extend(d for d in base.rglob("*") if d.is_dir())

    copied = 0
    skipped = 0
    for d in dirs_to_check:
        try:
            has_tmd = file_exists_case_insensitive(d, "title.tmd") is not None
            has_tik = file_exists_case_insensitive(d, "title.tik") is not None
            if not (has_tmd and has_tik):
                # Track as skipped-with-reason
                if has_tmd or has_tik:
                    missing = "title.tik" if has_tmd and not has_tik else "title.tmd"
                    problems.append((d, f"cert skipped: missing {missing}"))
                continue

            dest = d / "title.cert"
            if dest.exists() and not force:
                skipped += 1
                problems.append((d, "cert skipped: title.cert already exists (use --force-cert)"))
                continue

            if not dry_run:
                d.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source_cert, dest)
            copied += 1
        except Exception as e:
            problems.append((d, f"cert copy failed: {e}"))

    return copied, skipped, problems

# --------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------
def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="WUPify: .app, tmd.*, cetk.*, title.cert (summary logs)")
    p.add_argument("--path", type=Path, required=True, help="Base directory")
    p.add_argument("--recursive", action="store_true", help="Include subdirectories")
    p.add_argument("--overwrite", action="store_true", help="Allow replacing existing title.tmd/title.tik")
    p.add_argument("--dry-run", action="store_true", help="Preview only (no changes)")
    p.add_argument("--only-app", action="store_true", help="Run only step .app")
    p.add_argument("--only-tmd", action="store_true", help="Run only step tmd.*")
    p.add_argument("--only-cetk", action="store_true", help="Run only step cetk.*")
    p.add_argument("--only-cert", action="store_true", help="Run only step title.cert copy")
    p.add_argument("--cert-path", type=Path, help="Explicit path to title.cert (default: next to this script)")
    p.add_argument("--force-cert", action="store_true", help="Overwrite existing title.cert")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose (debug) logs")
    return p.parse_args(argv)

# --------------------------------------------------------------------
# Main
# --------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    setup_logging(args.verbose)

    base = args.path
    if not base.exists() or not base.is_dir():
        logging.error("Base path is not a directory: %s", base)
        return 2

    if sum([args.only_app, args.only_tmd, args.only_cetk, args.only_cert]) > 1:
        logging.error("Choose at most one --only-* option.")
        return 2

    run_app = run_tmd = run_cetk = run_cert = True
    if args.only_app:
        run_tmd = run_cetk = run_cert = False
    elif args.only_tmd:
        run_app = run_cetk = run_cert = False
    elif args.only_cetk:
        run_app = run_tmd = run_cert = False
    elif args.only_cert:
        run_app = run_tmd = run_cetk = False

    # Step 1
    total_app = (0, 0, [])
    if run_app:
        logging.info("== Step 1: add .app to files without extension ==")
        total_app = add_app_extension(base, args.recursive, args.dry_run)

    # Step 2
    total_tmd = (0, 0, 0, [])
    if run_tmd:
        logging.info("== Step 2: tmd.XXX -> title.tmd (keep highest) ==")
        total_tmd = process_numbered_series(base, args.recursive, args.dry_run, args.overwrite, "tmd", "title.tmd")

    # Step 3
    total_cetk = (0, 0, 0, [])
    if run_cetk:
        logging.info("== Step 3: cetk.XXX -> title.tik (keep highest) ==")
        total_cetk = process_numbered_series(base, args.recursive, args.dry_run, args.overwrite, "cetk", "title.tik")

    # Step 4
    total_cert = (0, 0, [])
    if run_cert:
        logging.info("== Step 4: copy title.cert (only if title.tmd & title.tik) + hash verification ==")
        total_cert = copy_title_cert(base, args.recursive, args.dry_run, args.cert_path, args.force_cert)

    # ----------------- Summary -----------------
    app_renamed, app_skipped, app_problems = total_app
    tmd_changed, tmd_skipped, tmd_deleted, tmd_problems = total_tmd
    cetk_changed, cetk_skipped, cetk_deleted, cetk_problems = total_cetk
    cert_copied, cert_skipped, cert_problems = total_cert

    problems = app_problems + tmd_problems + cetk_problems + cert_problems

    print("")
    print("========== SUMMARY ==========")
    if run_app:
        print(f"Step 1 (.app): renamed={app_renamed}, skipped={app_skipped}")
    if run_tmd:
        print(f"Step 2 (tmd):  changed_dirs={tmd_changed}, skipped_dirs={tmd_skipped}, lower_deleted={tmd_deleted}")
    if run_cetk:
        print(f"Step 3 (cetk): changed_dirs={cetk_changed}, skipped_dirs={cetk_skipped}, lower_deleted={cetk_deleted}")
    if run_cert:
        print(f"Step 4 (cert): copied={cert_copied}, skipped={cert_skipped}")

    if problems:
        print("\nProblems:")
        # Deduplicate (dir, reason) pairs while keeping order
        seen = set()
        for d, reason in problems:
            key = (str(d.resolve()), reason)
            if key in seen:
                continue
            seen.add(key)
            print(f"- {d} -> {reason}")
    else:
        print("\nProblems: none 🎉")
    print("=============================")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
