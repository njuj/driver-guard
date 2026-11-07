"""Judging drivers: what each one is, whether it is a known weapon, and what about it is out of place."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from . import pe
from .lol import Catalogue, Entry

SEVERITIES = ["critical", "high", "medium", "low", "info"]


@dataclass
class Finding:
    severity: str
    title: str
    detail: str = ""


@dataclass
class Driver:
    path: str
    service: str = ""
    display: str = ""
    state: str = ""                 # Running | Stopped | "" (a file given on the command line)
    start: str = ""
    loaded: bool = False            # in the kernel's module list (administrator only)
    exists: bool = False
    hashes: dict | None = None
    auth: str | None = None
    sig: dict | None = None
    match: tuple[Entry, str] | None = None
    findings: list[Finding] = field(default_factory=list)

    @property
    def running(self) -> bool:
        return self.loaded or self.state == "Running"

    @property
    def filename(self) -> str:
        return re.split(r"[\\/]", self.path)[-1]

    @property
    def worst(self) -> str:
        return min((f.severity for f in self.findings), key=SEVERITIES.index, default="")


def read(d: Driver, catalogue: Catalogue | None) -> None:
    try:
        data = open(d.path, "rb").read()
    except OSError as e:
        d.exists = os.path.exists(d.path)
        if d.exists:
            d.findings.append(Finding("info", "could not read the file", str(e)))
        return
    d.exists = True
    d.hashes = pe.file_hashes(data)
    try:
        d.auth = pe.authentihash(data)
    except pe.PEError:
        d.auth = None
    if catalogue:
        d.match = catalogue.by_hash(d.hashes, d.auth)


def _location(path: str) -> str | None:
    p = path.lower().replace("/", "\\")
    if re.search(r"\\(temp|tmp|downloads|desktop)\\", p) or re.match(r"^[a-z]:\\users\\", p):
        return "high"
    if re.match(r"^[a-z]:\\programdata\\", p):
        return "medium"
    return None


def judge(d: Driver, catalogue: Catalogue | None) -> None:
    f = d.findings
    where = "loaded right now" if d.running else ("installed, not running" if d.service else "on disk")
    if d.match:
        entry, how = d.match
        if entry.category.lower().startswith("malicious"):
            f.append(Finding("critical", f"MALICIOUS driver (LOLDrivers: {entry.names[0] if entry.names else entry.id})",
                             f"{how}; {where}. This file is malware, not a buggy driver. {entry.link}"))
        else:
            use = entry.usecase or "abused by attackers"
            f.append(Finding("high" if d.running else "medium",
                             f"known vulnerable driver: {use}",
                             f"{how}; {where}. Any program on this PC can use it to reach the kernel: "
                             f"kill antivirus, hide, read passwords from memory. {entry.link}"))
    elif catalogue and d.exists:
        same = catalogue.by_name(d.filename)
        if same:
            windows_own = "CN=Microsoft Windows," in ((d.sig or {}).get("signer") or "") + ","
            f.append(Finding("info" if windows_own else "low",
                             "same file name as a known vulnerable driver, but not a listed build",
                             f"most likely a fixed version: keep the program that installed it updated; {same.link}"))

    if d.sig and not d.match:
        status, signer = d.sig.get("status", ""), d.sig.get("signer", "")
        if status == "NotSigned":
            f.append(Finding("high" if d.running else "medium", "not signed",
                             "Windows refuses unsigned drivers unless signing checks were weakened"))
        elif status == "HashMismatch":
            f.append(Finding("high", "signature does not match the file", "the file was changed after signing"))
        elif status and status != "Valid":
            f.append(Finding("low", f"signature not trusted ({status})", signer))

    if d.exists:
        risk = _location(d.path)
        if risk:
            f.append(Finding(risk, "driver kept in a folder ordinary programs can write to",
                             "any program can swap this file, and drivers belong in Windows\\System32\\drivers "
                             "or the driver store"))
        stem, _, ext = d.filename.rpartition(".")
        if ext.lower() not in ("sys", "dll"):
            f.append(Finding("low", f"driver file without a .sys extension (.{ext or 'none'})"))
        elif re.fullmatch(r"[0-9a-f]{8,}", stem.lower()):
            f.append(Finding("low", "random-looking file name"))
    elif d.service:
        if d.running:
            f.append(Finding("high", "running, but its file is gone",
                             "a driver that deletes itself after loading is a rootkit habit"))
        elif d.start not in ("Disabled",) and d.path:
            f.append(Finding("info", "service left behind by an uninstalled program", d.path))


def hardening(h: dict) -> list[Finding]:
    out = []
    if h.get("blocklist", "").startswith("off"):
        out.append(Finding("medium", "Microsoft's vulnerable driver blocklist is off",
                           "Windows Security → Device security → Core isolation → "
                           "Microsoft Vulnerable Driver Blocklist"))
    if h.get("memory_integrity") == "off":
        out.append(Finding("info", "memory integrity (HVCI) is off",
                           "with it on, Windows enforces the blocklist and blocks many kernel exploits; "
                           "Core isolation → Memory integrity (some old drivers stop it from turning on)"))
    return out


def scan_files(paths: list[str]) -> list[Driver]:
    out = []
    for p in paths:
        if os.path.isdir(p):
            for root, _, files in os.walk(p):
                out += [Driver(os.path.join(root, n)) for n in sorted(files)
                        if n.lower().endswith((".sys", ".bin", ".dat", ".tmp")) or "." not in n]
        else:
            out.append(Driver(p))
    return out


def run(drivers: list[Driver], catalogue: Catalogue | None, signatures: dict | None) -> list[Driver]:
    for d in drivers:
        read(d, catalogue)
        if signatures is not None:
            d.sig = signatures.get(d.path.lower())
        judge(d, catalogue)
    return drivers
