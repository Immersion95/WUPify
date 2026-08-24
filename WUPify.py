#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-only

"""Batch-convert No-Intro Wii U CDN folders into WUP-style folders.

WUPify normalizes content names, selects the newest numbered TMD/ticket,
generates a missing fake ticket when its title key can be verified locally,
and builds title.cert without requiring an external certificate file.

Ticket/key generation and certificate-chain handling are based on
WiiUDownloader: https://github.com/Xpl0itU/WiiUDownloader
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import logging
import os
import re
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# Wii U TMD layout.
TMD_VERSION_WIIU = 0x01
TMD_TITLE_ID_OFFSET = 0x18C
TMD_TITLE_VERSION_OFFSET = 0x1DC
TMD_CONTENT_COUNT_OFFSET = 0x1DE
TMD_CONTENT_START = 0xB04
TMD_CONTENT_STRIDE = 0x30
TMD_HASH_SIZE = 0x20

# Hashed-content layout.
CONTENT_TYPE_HASHED = 0x02
HASHED_BLOCK_SIZE = 0x10000
HASH_HEADER_SIZE = 0x0400
HASH_DATA_SIZE = 0xFC00
HASH_ENTRY_SIZE = 0x14
HASH_LEVEL_SIZE = 0x140

# Fake-ticket layout used by WiiUDownloader.
TICKET_ENCRYPTED_KEY_OFFSET = 0x1BF
TICKET_ENCRYPTED_KEY_SIZE = 0x10
TICKET_TITLE_ID_OFFSET = 0x1DC
TICKET_TITLE_ID_SIZE = 0x08
TICKET_TITLE_VERSION_OFFSET = 0x1E6
TICKET_TITLE_VERSION_SIZE = 0x02

# Key generation used by WiiUDownloader.
KEYGEN_SECRET = "fd040105060b111c2d49"
WIIU_COMMON_KEY = bytes.fromhex("d7b00402659ba2abd2cb0db27fa2b656")
TITLE_KEY_PASSWORDS = (
    b"mypass",
    b"nintendo",
    b"test",
    b"1234567890",
    b"Lucy131211",
    b"fbf10",
    b"5678",
    b"1234",
    b"",
    b"MAGIC",
)

# Immutable fake-ticket template from WiiUDownloader.
TICKET_TEMPLATE_HEX = (
    "00010004d15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed"
    "15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed"
    "15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed"
    "15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed"
    "15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed"
    "15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed"
    "15abe11ad15ea5ed15abe11ad15ea5ed15abe11a0000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "526f6f742d434130303030303030332d585330303030303030630000000000000000000000000000"
    "000000000000000000000000000000000000000000000000feedfacefeedfacefeedfacefeedface"
    "feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface"
    "feedface010000cccccccccccccccccccccccccccccccc00000000000000000000000000aaaaaaaa"
    "aaaaaaaa000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000010000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000010014"
    "000000ac000000140001001400000000000000280000000100000084000000840003000000000000"
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000"
)
TICKET_TEMPLATE = bytes.fromhex(TICKET_TEMPLATE_HEX)

# Retail Root-CA00000003-XS0000000c certificate.
# WiiUDownloader obtains this 0x300-byte certificate from the OSv10 cetk;
# embedding only this constant keeps WUPify fully offline. The other 0x700
# bytes of title.cert are read from each title.tmd.
RETAIL_XS_CERT_B64 = (
    "AAEABJGevkZK0PVSzRty54hJEM9VqfAuUHiWQdiWaD3ABb0K6ocHnYrChMZ1Bl90yL83yIBEQJUCoCKY"
    "C7itSDg/bSinneOWJsyysioPGeQQMvCUs5/wEzFG3sj2wanVXNKNnhxHs9EfT1QmwseAE1onddPKZ5vH"
    "6DTw4PtY5ohgpxMw/JV5F5PI+6k1p6aQjyKd7ioMprmyOxLUlab+GdDXJkghaHhgWmZTjb83aJmQXTRF"
    "/Fxyeg4T4OLIlxyc+mxgZ4h1cypOdVI9L1YvEqq9FXO/BslAVK76gacUF6+aSgZtD/xa1kurKLH/YGYf"
    "RDfUnh4NlBLrS8rPTP1qNAiEeYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAABSb290LUNBMDAwMDAwMDMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVhTMDAwMDAwMGMAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAATegiUrVBbtsZ+LlvdajvsQ9kQx3LpzCkNpYWI"
    "t33MEWgLs+KfTqu7JumMJgGYXAQbsUN45okYGq13BWjpKKK5gWfuPhDQcr7vH6Ivoqo+E/EeGDapKkKB"
    "73Cq9ORimYIhxvu5vdAX5qxZBJTpzqmFnOstKkwXZvLDORLFjxSoA+NvzNzM3BP9eud8enjZl+asw1VX"
    "4NPp62S0PJL0xQ1npgLes5GwZmHNMogL1kkSrxy8txYqBvAlZdOw7OT87N2uikk0247mfzAXmGIhFV0T"
    "HGw/CasZRcIGrHDJQrNvSaEYO814tuS0fGxcrA+NYviXxpU90S8otwxbffdRgZqYNGUmJQABAAEAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)
RETAIL_XS_CERT = base64.b64decode(RETAIL_XS_CERT_B64)

CONTENT_ID_RE = re.compile(r"^[0-9a-f]{8}$", re.IGNORECASE)
TMD_NUMBERED_RE = re.compile(r"^tmd\.(\d+)$", re.IGNORECASE)
CETK_NUMBERED_RE = re.compile(r"^cetk\.(\d+)$", re.IGNORECASE)


if len(TICKET_TEMPLATE) != 0x350:
    raise RuntimeError(f"Invalid embedded ticket template size: {len(TICKET_TEMPLATE):#x}")
if len(RETAIL_XS_CERT) != 0x300:
    raise RuntimeError(f"Invalid embedded XS certificate size: {len(RETAIL_XS_CERT):#x}")


@dataclass(frozen=True)
class Content:
    id: int
    index: int
    type: int
    size: int
    hash: bytes


@dataclass(frozen=True)
class TMD:
    title_id: int
    title_version: int
    contents: tuple[Content, ...]
    certificate1: bytes
    certificate2: bytes


@dataclass
class SeriesStats:
    selected: int = 0
    skipped: int = 0
    deleted: int = 0


@dataclass
class Stats:
    directories: int = 0

    titles_found: int = 0
    titles_updated: int = 0
    titles_unchanged: int = 0
    titles_failed: int = 0

    app_renamed: int = 0
    app_conflicts: int = 0

    tmd: SeriesStats = field(default_factory=SeriesStats)
    cetk: SeriesStats = field(default_factory=SeriesStats)

    tik_generated: int = 0
    tik_existing: int = 0
    tik_failed: int = 0

    cert_generated: int = 0
    cert_existing: int = 0
    cert_failed: int = 0

    problems: list[tuple[Path, str]] = field(default_factory=list)

    def change_count(self) -> int:
        """Return the number of successful file-changing operations."""
        return (
            self.app_renamed
            + self.tmd.selected
            + self.cetk.selected
            + self.tik_generated
            + self.cert_generated
        )


@dataclass(frozen=True)
class VerificationTarget:
    content: Content
    app_path: Path
    h3_path: Path | None


# ---------------------------------------------------------------------------
# Binary formats
# ---------------------------------------------------------------------------

def parse_tmd(path: Path) -> TMD:
    data = path.read_bytes()
    if len(data) < TMD_CONTENT_COUNT_OFFSET + 2:
        raise ValueError("TMD is too small")

    version = data[0x180]
    if version != TMD_VERSION_WIIU:
        raise ValueError(f"unsupported TMD version {version}; WUPify expects Wii U TMDs")

    title_id = struct.unpack_from(">Q", data, TMD_TITLE_ID_OFFSET)[0]
    title_version = struct.unpack_from(">H", data, TMD_TITLE_VERSION_OFFSET)[0]
    content_count = struct.unpack_from(">H", data, TMD_CONTENT_COUNT_OFFSET)[0]

    contents: list[Content] = []
    for i in range(content_count):
        offset = TMD_CONTENT_START + i * TMD_CONTENT_STRIDE
        end = offset + TMD_CONTENT_STRIDE
        if end > len(data):
            raise ValueError("TMD content table is truncated")

        contents.append(
            Content(
                id=struct.unpack_from(">I", data, offset)[0],
                index=struct.unpack_from(">H", data, offset + 4)[0],
                type=struct.unpack_from(">H", data, offset + 6)[0],
                size=struct.unpack_from(">Q", data, offset + 8)[0],
                hash=data[offset + 16 : offset + 16 + TMD_HASH_SIZE],
            )
        )

    cert_offset = TMD_CONTENT_START + content_count * TMD_CONTENT_STRIDE
    certificate1 = data[cert_offset : cert_offset + 0x400]
    certificate2 = data[cert_offset + 0x400 : cert_offset + 0x700]

    return TMD(
        title_id=title_id,
        title_version=title_version,
        contents=tuple(contents),
        certificate1=certificate1,
        certificate2=certificate2,
    )


def build_title_cert(tmd: TMD) -> bytes:
    if len(tmd.certificate1) != 0x400:
        raise ValueError("title.tmd does not contain the first certificate (0x400 bytes)")
    if len(tmd.certificate2) != 0x300:
        raise ValueError("title.tmd does not contain the second certificate (0x300 bytes)")
    return tmd.certificate1 + tmd.certificate2 + RETAIL_XS_CERT


# ---------------------------------------------------------------------------
# WiiUDownloader-compatible ticket/key generation
# ---------------------------------------------------------------------------

def trim_leading_zero_pairs(text: str) -> str:
    while text.startswith("00"):
        text = text[2:]
    return text


def keygen_pair_bytes(text: str) -> bytes:
    """Apply WiiUDownloader's legacy pair-to-byte transform."""
    if len(text) % 2:
        raise ValueError("keygen input must contain an even number of characters")

    output = bytearray()
    for i in range(0, len(text), 2):
        high = (ord(text[i]) % 32 + 9) % 25
        low = (ord(text[i + 1]) % 32 + 9) % 25
        output.append(high * 16 + low)
    return bytes(output)


def aes_cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def aes_cbc_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return decryptor.update(data) + decryptor.finalize()


def derive_title_key(title_id: int, key_type: int) -> bytes:
    if not 0 <= key_type < len(TITLE_KEY_PASSWORDS):
        raise ValueError(f"invalid title key type: {key_type}")

    title_id_hex = f"{title_id:016x}"
    salt_source = KEYGEN_SECRET + trim_leading_zero_pairs(title_id_hex)
    salt = hashlib.md5(keygen_pair_bytes(salt_source)).digest()
    password = TITLE_KEY_PASSWORDS[key_type]
    return hashlib.pbkdf2_hmac("sha1", password, salt, 20, 16)


def encrypt_title_key(title_id: int, title_key: bytes) -> bytes:
    title_id_hex = f"{title_id:016x}"
    iv = keygen_pair_bytes(title_id_hex) + b"\x00" * 8

    # WiiUDownloader pads the 16-byte title key, encrypts two blocks, then
    # stores only the first block in the ticket. Encrypting the first block
    # directly produces the same 16 bytes.
    return aes_cbc_encrypt(title_key, WIIU_COMMON_KEY, iv)


def build_ticket(tmd: TMD, title_key: bytes) -> bytes:
    encrypted_title_key = encrypt_title_key(tmd.title_id, title_key)
    ticket = bytearray(TICKET_TEMPLATE)

    ticket[
        TICKET_ENCRYPTED_KEY_OFFSET : TICKET_ENCRYPTED_KEY_OFFSET + TICKET_ENCRYPTED_KEY_SIZE
    ] = encrypted_title_key
    ticket[TICKET_TITLE_ID_OFFSET : TICKET_TITLE_ID_OFFSET + TICKET_TITLE_ID_SIZE] = struct.pack(
        ">Q", tmd.title_id
    )
    ticket[
        TICKET_TITLE_VERSION_OFFSET : TICKET_TITLE_VERSION_OFFSET + TICKET_TITLE_VERSION_SIZE
    ] = struct.pack(">H", tmd.title_version)

    return bytes(ticket)


# ---------------------------------------------------------------------------
# Local title-key verification
# ---------------------------------------------------------------------------

def align16(size: int) -> int:
    return (size + 15) & ~15


def verify_non_hashed_content(path: Path, content: Content, title_key: bytes) -> bool:
    iv = struct.pack(">H", content.index) + b"\x00" * 14
    decryptor = Cipher(algorithms.AES(title_key), modes.CBC(iv)).decryptor()
    digest = hashlib.sha1()
    remaining = content.size

    try:
        with path.open("rb") as source:
            while remaining:
                plain_size = min(8 * 1024 * 1024, remaining)
                encrypted_size = align16(plain_size)
                encrypted = source.read(encrypted_size)
                if len(encrypted) != encrypted_size:
                    return False

                decrypted = decryptor.update(encrypted)
                digest.update(decrypted[:plain_size])
                remaining -= plain_size
    except OSError:
        return False

    return digest.digest() == content.hash[:20]


def verify_hashed_content(path: Path, h3_path: Path, content: Content, title_key: bytes) -> bool:
    try:
        h3 = h3_path.read_bytes()
        with path.open("rb") as source:
            block = source.read(HASHED_BLOCK_SIZE)
    except OSError:
        return False

    if len(h3) < HASH_ENTRY_SIZE or hashlib.sha1(h3).digest() != content.hash[:20]:
        return False
    if len(block) != HASHED_BLOCK_SIZE:
        return False

    hashes = aes_cbc_decrypt(block[:HASH_HEADER_SIZE], title_key, b"\x00" * 16)
    h0_hashes = hashes[0x000:0x140]
    h1_hashes = hashes[0x140:0x280]
    h2_hashes = hashes[0x280:0x3C0]

    h0 = h0_hashes[:HASH_ENTRY_SIZE]
    h1 = h1_hashes[:HASH_ENTRY_SIZE]
    h2 = h2_hashes[:HASH_ENTRY_SIZE]
    h3_first = h3[:HASH_ENTRY_SIZE]

    if hashlib.sha1(h0_hashes).digest() != h1:
        return False
    if hashlib.sha1(h1_hashes).digest() != h2:
        return False
    if hashlib.sha1(h2_hashes).digest() != h3_first:
        return False

    payload = aes_cbc_decrypt(block[HASH_HEADER_SIZE:], title_key, h0[:16])
    return hashlib.sha1(payload).digest() == h0


def verification_targets(files: dict[str, Path], tmd: TMD) -> list[VerificationTarget]:
    hashed: list[VerificationTarget] = []
    normal: list[VerificationTarget] = []

    for content in tmd.contents:
        app_path = files.get(f"{content.id:08x}.app")
        if app_path is None:
            continue

        if content.type & CONTENT_TYPE_HASHED:
            h3_path = files.get(f"{content.id:08x}.h3")
            if h3_path is not None:
                hashed.append(VerificationTarget(content, app_path, h3_path))
        else:
            normal.append(VerificationTarget(content, app_path, None))

    # A hashed content needs only one 0x10000-byte block to identify the key,
    # so prefer it even when the content itself is large. Otherwise use the
    # smallest normal content to minimize I/O.
    hashed.sort(key=lambda target: target.content.size)
    normal.sort(key=lambda target: target.content.size)
    return hashed + normal


def detect_title_key(files: dict[str, Path], tmd: TMD) -> tuple[int, bytes]:
    targets = verification_targets(files, tmd)
    if not targets:
        raise ValueError("no .app content is available to verify the generated title key")

    for target in targets:
        for key_type in range(len(TITLE_KEY_PASSWORDS)):
            title_key = derive_title_key(tmd.title_id, key_type)

            if target.h3_path is not None:
                valid = verify_hashed_content(
                    target.app_path,
                    target.h3_path,
                    target.content,
                    title_key,
                )
            else:
                valid = verify_non_hashed_content(target.app_path, target.content, title_key)

            if valid:
                return key_type, title_key

    raise ValueError("none of the known WiiUDownloader title-key types matches the available content")


# ---------------------------------------------------------------------------
# Batch filesystem operations
# ---------------------------------------------------------------------------

def iter_directory_files(base: Path, recursive: bool) -> Iterator[tuple[Path, dict[str, Path]]]:
    if not recursive:
        files = {entry.name.lower(): entry for entry in base.iterdir() if entry.is_file()}
        yield base, files
        return

    for root, _, names in os.walk(base):
        directory = Path(root)
        yield directory, {name.lower(): directory / name for name in names}


def record_problem(stats: Stats, directory: Path, reason: str) -> None:
    stats.problems.append((directory, reason))
    logging.debug("%s -> %s", directory, reason)


def normalize_app_files(
    directory: Path,
    files: dict[str, Path],
    dry_run: bool,
    stats: Stats,
) -> None:
    for key, source in list(files.items()):
        if not CONTENT_ID_RE.fullmatch(source.name):
            continue

        target = source.with_name(source.name + ".app")
        target_key = target.name.lower()
        if target_key in files:
            stats.app_conflicts += 1
            record_problem(stats, directory, f"cannot rename {source.name}: {target.name} already exists")
            continue

        try:
            if not dry_run:
                source.rename(target)
        except OSError as exc:
            stats.app_conflicts += 1
            record_problem(stats, directory, f"cannot rename {source.name}: {exc}")
            continue

        del files[key]
        files[target_key] = source if dry_run else target
        stats.app_renamed += 1


def normalize_numbered_file(
    directory: Path,
    files: dict[str, Path],
    pattern: re.Pattern[str],
    target_name: str,
    overwrite: bool,
    dry_run: bool,
    series_stats: SeriesStats,
    stats: Stats,
) -> None:
    numbered: list[tuple[int, Path]] = []
    for path in files.values():
        match = pattern.fullmatch(path.name)
        if match:
            numbered.append((int(match.group(1)), path))

    if not numbered:
        return

    numbered.sort(key=lambda item: item[0])
    highest = numbered[-1][1]
    lower = [path for _, path in numbered[:-1]]
    target_key = target_name.lower()
    existing = files.get(target_key)

    if existing is not None and not overwrite:
        series_stats.skipped += 1
        return

    target = directory / target_name

    try:
        if not dry_run:
            if existing is not None:
                existing.unlink()
            highest.rename(target)
            for path in lower:
                path.unlink()
    except OSError as exc:
        series_stats.skipped += 1
        record_problem(stats, directory, f"cannot select {highest.name} as {target_name}: {exc}")
        return

    for path in lower:
        files.pop(path.name.lower(), None)
    files.pop(highest.name.lower(), None)
    if existing is not None:
        files.pop(existing.name.lower(), None)

    files[target_key] = highest if dry_run else target
    series_stats.selected += 1
    series_stats.deleted += len(lower)


def is_title_directory(files: dict[str, Path]) -> bool:
    """Return whether a directory contains enough metadata to represent a title."""
    for path in files.values():
        name = path.name.lower()
        if name in {"title.tmd", "title.tik"}:
            return True
        if TMD_NUMBERED_RE.fullmatch(path.name) or CETK_NUMBERED_RE.fullmatch(path.name):
            return True
    return False


def process_directory(
    directory: Path,
    files: dict[str, Path],
    args: argparse.Namespace,
    stats: Stats,
) -> None:
    stats.directories += 1

    title_directory = is_title_directory(files)
    changes_before = stats.change_count()
    problems_before = len(stats.problems)

    if title_directory:
        stats.titles_found += 1

    def enabled(step: str) -> bool:
        return args.only is None or args.only == step

    try:
        if enabled("app"):
            normalize_app_files(directory, files, args.dry_run, stats)

        if enabled("tmd"):
            normalize_numbered_file(
                directory,
                files,
                TMD_NUMBERED_RE,
                "title.tmd",
                args.overwrite,
                args.dry_run,
                stats.tmd,
                stats,
            )

        if enabled("cetk"):
            normalize_numbered_file(
                directory,
                files,
                CETK_NUMBERED_RE,
                "title.tik",
                args.overwrite,
                args.dry_run,
                stats.cetk,
                stats,
            )

        tmd_path = files.get("title.tmd")
        tik_path = files.get("title.tik")
        parsed_tmd: TMD | None = None
        tmd_error: Exception | None = None

        def get_tmd() -> TMD:
            nonlocal parsed_tmd, tmd_error
            if parsed_tmd is not None:
                return parsed_tmd
            if tmd_error is not None:
                raise tmd_error
            if tmd_path is None:
                raise ValueError("title.tmd is missing")

            try:
                parsed_tmd = parse_tmd(tmd_path)
            except Exception as exc:
                tmd_error = exc
                raise
            return parsed_tmd

        ticket_failed = False

        if enabled("tik") and tmd_path is not None:
            if tik_path is not None:
                stats.tik_existing += 1
            else:
                try:
                    tmd = get_tmd()
                    key_type, title_key = detect_title_key(files, tmd)
                    ticket = build_ticket(tmd, title_key)
                    target = directory / "title.tik"

                    if not args.dry_run:
                        target.write_bytes(ticket)
                    files["title.tik"] = target
                    tik_path = target
                    stats.tik_generated += 1
                    logging.debug(
                        "%s -> generated title.tik with key type %d",
                        directory,
                        key_type,
                    )
                except Exception as exc:
                    stats.tik_failed += 1
                    ticket_failed = True
                    record_problem(stats, directory, f"title.tik generation failed: {exc}")

        if enabled("cert"):
            cert_path = files.get("title.cert")

            if cert_path is not None and not args.overwrite:
                stats.cert_existing += 1
            elif tmd_path is None or tik_path is None:
                # Empty/non-title directories are normal in a recursive batch.
                # Report an incomplete title only when some title metadata exists.
                if not ticket_failed and (tmd_path is not None or tik_path is not None):
                    missing = "title.tmd" if tmd_path is None else "title.tik"
                    stats.cert_failed += 1
                    record_problem(
                        stats,
                        directory,
                        f"title.cert generation skipped: {missing} is missing",
                    )
            else:
                try:
                    certificate = build_title_cert(get_tmd())
                    target = directory / "title.cert"
                    if not args.dry_run:
                        target.write_bytes(certificate)
                    files["title.cert"] = target
                    stats.cert_generated += 1
                except Exception as exc:
                    stats.cert_failed += 1
                    record_problem(stats, directory, f"title.cert generation failed: {exc}")
    finally:
        if title_directory:
            if len(stats.problems) > problems_before:
                stats.titles_failed += 1
            elif stats.change_count() > changes_before:
                stats.titles_updated += 1
            else:
                stats.titles_unchanged += 1


# ---------------------------------------------------------------------------
# CLI / output
# ---------------------------------------------------------------------------

def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="WUPify: simple offline batch conversion for No-Intro Wii U CDN folders"
    )
    parser.add_argument(
        "--path",
        type=Path,
        default=Path("."),
        help="base directory (default: current directory)",
    )
    parser.add_argument("--recursive", action="store_true", help="include subdirectories")
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="replace existing title.tmd/title.tik from numbered files and regenerate title.cert",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="show what would be done without changing files",
    )

    only = parser.add_mutually_exclusive_group()
    only.add_argument(
        "--only-app",
        dest="only",
        action="store_const",
        const="app",
        help="only add .app extensions",
    )
    only.add_argument(
        "--only-tmd",
        dest="only",
        action="store_const",
        const="tmd",
        help="only select tmd.N",
    )
    only.add_argument(
        "--only-cetk",
        dest="only",
        action="store_const",
        const="cetk",
        help="only select cetk.N",
    )
    only.add_argument(
        "--only-tik-gen",
        dest="only",
        action="store_const",
        const="tik",
        help="only generate missing title.tik",
    )
    only.add_argument(
        "--only-cert",
        dest="only",
        action="store_const",
        const="cert",
        help="only generate title.cert",
    )

    parser.add_argument("-v", "--verbose", action="store_true", help="show debug details")
    return parser.parse_args(argv)


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s | %(message)s")


def print_summary(stats: Stats, args: argparse.Namespace) -> None:
    dry_run = args.dry_run
    partial = args.only is not None

    title = "WUPify - DRY RUN" if dry_run else "WUPify"
    width = 34
    print("\n" + f" {title} ".center(width, "="))
    print()
    def count(label: str, value: int) -> None:
        print(f"{label:<20}{value}")

    count("Titles found:", stats.titles_found)
    count("Would update:" if dry_run else "Updated:", stats.titles_updated)
    count("Unchanged:" if partial else "Already ready:", stats.titles_unchanged)
    count("Problems:" if dry_run else "Failed:", stats.titles_failed)

    if args.only is None or args.only == "app":
        print()
        label = "Content files to rename:" if dry_run else "Content files renamed:"
        print(f"{label} {stats.app_renamed}")

    unique_problems: list[tuple[Path, str]] = []
    seen: set[tuple[str, str]] = set()
    for directory, reason in stats.problems:
        key = (str(directory.resolve()), reason)
        if key not in seen:
            seen.add(key)
            unique_problems.append((directory, reason))

    if unique_problems:
        print("\nProblems:")
        for directory, reason in unique_problems:
            print(f"- {directory} -> {reason}")
    elif dry_run:
        print("\nNo problems found. No files were changed.")
    else:
        print("\nAll titles processed successfully.")

    print("=" * width)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    setup_logging(args.verbose)

    base = args.path.resolve()
    if not base.is_dir():
        logging.error("Base path is not a directory: %s", base)
        return 2

    logging.info("Scanning %s%s", base, " recursively" if args.recursive else "")
    if args.dry_run:
        logging.info("Dry-run mode: no files will be changed")

    stats = Stats()
    try:
        for directory, files in iter_directory_files(base, args.recursive):
            process_directory(directory, files, args, stats)
    except KeyboardInterrupt:
        logging.error("Interrupted")
        return 130

    print_summary(stats, args)
    return 1 if stats.problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
