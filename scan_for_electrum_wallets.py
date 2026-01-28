#!/usr/bin/env python3
"""
Electrum wallet file finder (cleartext + encrypted + possibly corrupted).

What it does
- Recursively scans a directory you provide.
- Detects:
  * Encrypted Electrum wallet files (magic bytes: BIE1 / BIE2)
  * Cleartext Electrum wallet files (JSON or very old Python-literal dict format)
  * “Possible/corrupted” wallet files (strong Electrum-looking strings but parsing fails)
- Prints progress: scanned count + percentage.
- Prints each find as it is discovered.
- Writes a sorted report to a .txt file (most likely first).

Notes on detection
- Encrypted Electrum wallet files start with b'BIE1' or b'BIE2'.
- Cleartext wallets are generally JSON dictionaries containing keys like:
  'seed_version', 'wallet_type', 'keystore(s)', 'use_encryption', 'transactions', etc.
- Very old wallets might be parseable via ast.literal_eval() if not valid JSON.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import sys
import time
import warnings

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


# ---------------------------- Data model ----------------------------

@dataclass(order=True)
class Finding:
    # Sort primarily by score descending, then by path
    sort_index: Tuple[int, str] = field(init=False, repr=False)
    score: int
    kind: str  # CONFIRMED / LIKELY / POSSIBLE
    subtype: str  # encrypted-cleartext-oldformat-etc
    path: Path
    size_bytes: int
    mtime_epoch: float
    details: Dict[str, str] = field(default_factory=dict)
    reasons: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        # negative score for descending sort with dataclass(order=True)
        self.sort_index = (-self.score, str(self.path))


# ---------------------------- Heuristics ----------------------------

ELECTRUM_PATH_HINTS = [
    # common electrum wallet directories (various OS / packaging)
    "/.electrum/wallets/",
    "\\electrum\\wallets\\",
    "/electrum/wallets/",
    "/library/application support/electrum/wallets/",
    "/appdata/roaming/electrum/wallets/",
    "/.var/app/org.electrum.electrum/.electrum/wallets/",
]

FILENAME_HINTS = {
    "default_wallet": 10,
    "electrum.dat": 8,
    "wallet": 4,
}

EXT_HINTS = {
    ".dat": 3,
    ".json": 2,
    ".wallet": 2,
    ".bak": 1,
}

# Keys commonly seen in Electrum wallet dicts (across versions)
STRONG_KEYS = {
    "seed_version",
    "wallet_type",
    "use_encryption",
    "keystore",
    "keystores",
    "master_public_key",
    "master_public_keys",
    "accounts",
    "transactions",
    "addr_history",
    "imported_keys",
    "xpub",
    "xprv",
}

# Strings to look for when parsing fails but file looks Electrum-ish
ELECTRUM_MARKERS = [
    '"seed_version"',
    "'seed_version'",
    '"wallet_type"',
    "'wallet_type'",
    '"use_encryption"',
    "'use_encryption'",
    '"keystore"',
    "'keystore'",
    '"keystores"',
    "'keystores'",
    '"master_public_key"',
    "'master_public_key'",
    '"addr_history"',
    "'addr_history'",
    '"transactions"',
    "'transactions'",
    "electrum",
]


# ---------------------------- Helpers ----------------------------

def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Recursively find Electrum wallet files (cleartext + encrypted + possible/corrupted)."
    )
    p.add_argument(
        "directory",
        help="Root directory to scan",
    )
    p.add_argument(
        "-o",
        "--output",
        default=None,
        help="Output report .txt file path (default: electrum_wallet_scan_<timestamp>.txt in current dir)",
    )
    p.add_argument(
        "--max-size-mb",
        type=int,
        default=50,
        help="Skip files larger than this size in MB (default: 50). Electrum wallets are typically small.",
    )
    p.add_argument(
        "--follow-symlinks",
        action="store_true",
        help="Follow symlinks during directory traversal (default: off).",
    )
    p.add_argument(
        "--progress-every",
        type=int,
        default=250,
        help="Print progress every N scanned files (default: 250).",
    )
    return p.parse_args(argv)


def is_probably_electrum_path(path: Path) -> bool:
    low = str(path).lower().replace(os.sep, "/")
    # also consider Windows-style slashes by checking both patterns
    return any(hint in low or hint in low.replace("/", "\\") for hint in ELECTRUM_PATH_HINTS)


def path_score_boost(path: Path) -> Tuple[int, List[str]]:
    score = 0
    reasons: List[str] = []

    low_name = path.name.lower()
    for fname, pts in FILENAME_HINTS.items():
        if low_name == fname or low_name.startswith(fname + "."):
            score += pts
            reasons.append(f"filename hint: {fname}(+{pts})")

    ext = path.suffix.lower()
    if ext in EXT_HINTS:
        score += EXT_HINTS[ext]
        reasons.append(f"extension hint: {ext}(+{EXT_HINTS[ext]})")

    if is_probably_electrum_path(path):
        score += 15
        reasons.append("path looks like Electrum wallets dir(+15)")

    return score, reasons


def detect_encrypted_magic(data: bytes) -> Optional[str]:
    if len(data) < 4:
        return None
    magic = data[:4]
    if magic == b"BIE1":
        return "BIE1"
    if magic == b"BIE2":
        return "BIE2"
    return None


def try_parse_wallet_dict(text: str) -> Tuple[Optional[Dict], Optional[str]]:
    # Returns (dict, parser_used) or (None, None)
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj, "json"
    except Exception:
        pass

    # Older wallets might be Python-literal dicts.
    # Some may contain strings with backslashes like "C:\my\path" which triggers SyntaxWarning.
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            obj = ast.literal_eval(text)
        if isinstance(obj, dict):
            return obj, "ast.literal_eval"
    except Exception:
        pass

    return None, None


def classify_wallet_dict(d: Dict) -> Tuple[int, str, Dict[str, str], List[str]]:
    """
    Returns: (base_score, subtype, safe_details, reasons)
    """
    reasons: List[str] = []
    safe_details: Dict[str, str] = {}

    found_keys = sorted(k for k in d.keys() if isinstance(k, str) and k in STRONG_KEYS)
    if found_keys:
        reasons.append(f"found keys: {', '.join(found_keys[:10])}" + ("..." if len(found_keys) > 10 else ""))

    seed_version = d.get("seed_version")
    wallet_type = d.get("wallet_type")
    use_encryption = d.get("use_encryption")

    if isinstance(seed_version, int):
        safe_details["seed_version"] = str(seed_version)
    if isinstance(wallet_type, str):
        safe_details["wallet_type"] = wallet_type
    if isinstance(use_encryption, bool):
        safe_details["use_encryption"] = str(use_encryption)

    # Scoring
    score = 0
    subtype = "cleartext-unknown"

    strong = 0
    if isinstance(seed_version, int):
        strong += 1
    if isinstance(wallet_type, str):
        strong += 1
    if any(k in d for k in ("keystore", "keystores", "accounts", "transactions", "addr_history", "master_public_key", "master_public_keys")):
        strong += 1

    # classify
    if strong >= 2:
        score = 110
        subtype = "cleartext-wallet"
        reasons.append("wallet dict matches Electrum structure (strong>=2)")
    elif strong == 1 and found_keys:
        score = 80
        subtype = "cleartext-likely"
        reasons.append("wallet dict has some Electrum indicators")
    elif found_keys:
        score = 60
        subtype = "cleartext-possible"
        reasons.append("wallet dict has weak Electrum indicators")
    else:
        score = 0
        subtype = "not-electrum"

    # Old-style wallet hint
    if wallet_type == "old":
        score += 10
        subtype = "cleartext-old-wallet"
        reasons.append("wallet_type == 'old' (+10)")

    return score, subtype, safe_details, reasons


def marker_score(text: str) -> Tuple[int, List[str]]:
    low = text.lower()
    hits = []
    for m in ELECTRUM_MARKERS:
        if m.lower() in low:
            hits.append(m)
    # score by number of distinct marker hits
    score = min(55, 10 * len(hits))
    reasons = []
    if hits:
        reasons.append(f"contains Electrum marker strings: {', '.join(hits[:6])}" + ("..." if len(hits) > 6 else ""))
    return score, reasons


def safe_stat(path: Path) -> Optional[os.stat_result]:
    try:
        return path.stat()
    except Exception:
        return None


def scan_file(path: Path, max_bytes: int) -> Optional[Finding]:
    st = safe_stat(path)
    if st is None or not path.is_file():
        return None

    size = st.st_size
    mtime = st.st_mtime

    # skip huge files (wallets are typically tiny)
    if size > max_bytes:
        return None

    try:
        data = path.read_bytes()
    except Exception:
        return None

    # 1) Encrypted wallets (BIE1 / BIE2)
    magic = detect_encrypted_magic(data)
    path_boost, path_reasons = path_score_boost(path)
    if magic is not None:
        # basic sanity: encrypted format has more than just 4 bytes
        base = 120 if len(data) >= 70 else 100
        score = base + path_boost
        subtype = "encrypted-userpw" if magic == "BIE1" else "encrypted-xpubpw"
        details = {"encryption_magic": magic}
        reasons = [f"encrypted Electrum wallet magic {magic}"] + path_reasons
        kind = "CONFIRMED" if base >= 120 else "LIKELY"
        return Finding(
            score=score,
            kind=kind,
            subtype=subtype,
            path=path,
            size_bytes=size,
            mtime_epoch=mtime,
            details=details,
            reasons=reasons,
        )

    # 2) Cleartext (JSON or old python-literal dict)
    # Try strict UTF-8 decode first; if it fails, we'll only do marker scan with replacement.
    text_strict: Optional[str]
    try:
        text_strict = data.decode("utf-8")
    except UnicodeDecodeError:
        text_strict = None

    if text_strict is not None:
        d, parser_used = try_parse_wallet_dict(text_strict)
        if d is not None:
            base_score, subtype, safe_details, reasons = classify_wallet_dict(d)
            if base_score > 0:
                score = base_score + path_boost
                safe_details["parsed_with"] = parser_used or "unknown"
                kind = "CONFIRMED" if base_score >= 100 else "LIKELY"
                return Finding(
                    score=score,
                    kind=kind,
                    subtype=subtype,
                    path=path,
                    size_bytes=size,
                    mtime_epoch=mtime,
                    details=safe_details,
                    reasons=reasons + path_reasons,
                )

    # 3) Possible/corrupted: marker scan (even if decode failed)
    text_loose = data.decode("utf-8", errors="replace")
    mscore, mreasons = marker_score(text_loose)
    if mscore > 0:
        score = 40 + mscore + path_boost
        kind = "POSSIBLE"
        subtype = "corrupted-or-nonstandard"
        reasons = ["parsing failed but file looks Electrum-like"] + mreasons + path_reasons
        return Finding(
            score=score,
            kind=kind,
            subtype=subtype,
            path=path,
            size_bytes=size,
            mtime_epoch=mtime,
            details={},
            reasons=reasons,
        )

    return None


def count_files(root: Path, follow_symlinks: bool) -> int:
    total = 0
    for _, _, files in os.walk(root, followlinks=follow_symlinks):
        total += len(files)
    return total


def iter_paths(root: Path, follow_symlinks: bool) -> Iterable[Path]:
    for dirpath, _, filenames in os.walk(root, followlinks=follow_symlinks):
        base = Path(dirpath)
        for fn in filenames:
            yield base / fn


def fmt_time(epoch: float) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epoch))
    except Exception:
        return str(epoch)


def print_finding(f: Finding) -> None:
    print(f"\n[{f.kind}] score={f.score} subtype={f.subtype}\n  {f.path}")
    print(f"  size={f.size_bytes} bytes  mtime={fmt_time(f.mtime_epoch)}")
    if f.details:
        for k, v in f.details.items():
            print(f"  {k}: {v}")
    if f.reasons:
        for r in f.reasons[:8]:
            print(f"  - {r}")
        if len(f.reasons) > 8:
            print("  - ...")


def write_report(out_path: Path, findings: List[Finding], scanned: int, total: int, root: Path) -> None:
    findings_sorted = sorted(findings)

    lines: List[str] = []
    lines.append("Electrum wallet scan report")
    lines.append("=" * 80)
    lines.append(f"Root scanned : {root}")
    lines.append(f"Scanned files: {scanned} / {total}")
    lines.append(f"Generated   : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}")
    lines.append("")

    def section(title: str, items: List[Finding]) -> None:
        lines.append(title)
        lines.append("-" * 80)
        if not items:
            lines.append("(none)\n")
            return
        for f in items:
            lines.append(f"[{f.kind}] score={f.score} subtype={f.subtype}")
            lines.append(f"path : {f.path}")
            lines.append(f"size : {f.size_bytes} bytes")
            lines.append(f"mtime: {fmt_time(f.mtime_epoch)}")
            if f.details:
                for k, v in f.details.items():
                    lines.append(f"{k}: {v}")
            if f.reasons:
                lines.append("reasons:")
                for r in f.reasons:
                    lines.append(f"  - {r}")
            lines.append("")
        lines.append("")

    confirmed = [f for f in findings_sorted if f.kind == "CONFIRMED"]
    likely = [f for f in findings_sorted if f.kind == "LIKELY"]
    possible = [f for f in findings_sorted if f.kind == "POSSIBLE"]

    section("CONFIRMED (very likely Electrum wallets)", confirmed)
    section("LIKELY (strong indicators)", likely)
    section("POSSIBLE / CORRUPTED (looks Electrum-like but parsing failed)", possible)

    out_path.write_text("\n".join(lines), encoding="utf-8")


# ---------------------------- Main ----------------------------

def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)

    root = Path(args.directory).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        print(f"Error: not a directory: {root}", file=sys.stderr)
        return 2

    max_bytes = int(args.max_size_mb) * 1024 * 1024

    out_path = Path(args.output).expanduser().resolve() if args.output else Path.cwd() / (
        f"electrum_wallet_scan_{time.strftime('%Y%m%d_%H%M%S')}.txt"
    )

    print(f"Scanning: {root}")
    print(f"Max file size: {args.max_size_mb} MB")
    print(f"Output report: {out_path}")
    print("Counting files...")

    total = count_files(root, follow_symlinks=args.follow_symlinks)
    if total == 0:
        print("No files found under the provided directory.")
        return 0

    findings: List[Finding] = []
    scanned = 0
    last_progress_print = 0

    try:
        for p in iter_paths(root, follow_symlinks=args.follow_symlinks):
            scanned += 1

            f = scan_file(p, max_bytes=max_bytes)
            if f is not None:
                findings.append(f)
                print_finding(f)

            # periodic progress update
            if scanned - last_progress_print >= args.progress_every or scanned == total:
                pct = (scanned / total) * 100.0
                print(f"\rProgress: {pct:6.2f}%  scanned {scanned}/{total}", end="", flush=True)
                last_progress_print = scanned

        print()  # newline after progress

    except KeyboardInterrupt:
        print("\nInterrupted by user. Writing report with partial results...")

    # Always write report
    write_report(out_path, findings, scanned, total, root)

    # Summary
    confirmed = sum(1 for f in findings if f.kind == "CONFIRMED")
    likely = sum(1 for f in findings if f.kind == "LIKELY")
    possible = sum(1 for f in findings if f.kind == "POSSIBLE")

    print(f"\nDone. Findings: CONFIRMED={confirmed}, LIKELY={likely}, POSSIBLE={possible}")
    print(f"Report written to: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
