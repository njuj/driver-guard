"""The LOLDrivers catalogue (loldrivers.io): drivers known to be vulnerable or malicious, by file hash
and Authenticode hash. The 36 MB catalogue is reduced to a small hash index kept in the user's cache."""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

URL = "https://www.loldrivers.io/api/drivers.json"


@dataclass
class Entry:
    id: str
    category: str              # "vulnerable driver" | "malicious"
    names: list[str]
    usecase: str
    description: str
    mitre: str
    verified: bool

    @property
    def link(self) -> str:
        return f"https://www.loldrivers.io/drivers/{self.id}/"


def cache_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") if sys.platform == "win32" else os.environ.get("XDG_CACHE_HOME")
    return Path(base or Path.home() / ".cache") / "driver-guard"


def build_index(catalogue: list) -> dict:
    entries, hashes, names = {}, {}, {}
    for e in catalogue:
        cmds = e.get("Commands") or {}
        if isinstance(cmds, list):
            cmds = cmds[0] if cmds else {}
        entries[e["Id"]] = {
            "category": e.get("Category", ""), "names": [t for t in e.get("Tags") or [] if t],
            "usecase": (cmds.get("Usecase") or "").strip(), "description": (cmds.get("Description") or "").strip()[:300],
            "mitre": e.get("MitreID") or "", "verified": str(e.get("Verified", "")).upper() == "TRUE"}
        for s in e.get("KnownVulnerableSamples") or []:
            for key in ("MD5", "SHA1", "SHA256"):
                if s.get(key):
                    hashes[s[key].lower()] = e["Id"]
            for key, value in (s.get("Authentihash") or {}).items():
                if value:
                    hashes["auth:" + value.lower()] = e["Id"]
        for t in entries[e["Id"]]["names"]:
            names.setdefault(t.lower(), e["Id"])
    return {"built": time.time(), "entries": entries, "hashes": hashes, "names": names}


class Catalogue:
    def __init__(self, index: dict):
        self.index = index
        self.entries = {k: Entry(k, **v) for k, v in index["entries"].items()}

    @property
    def age_days(self) -> float:
        return (time.time() - self.index.get("built", 0)) / 86400

    def by_hash(self, hashes: dict[str, str], auth: str | None) -> tuple[Entry, str] | None:
        for kind in ("sha256", "sha1", "md5"):
            hit = self.index["hashes"].get(hashes[kind])
            if hit:
                return self.entries[hit], f"{kind.upper()} match"
        if auth:
            hit = self.index["hashes"].get("auth:" + auth)
            if hit:
                return self.entries[hit], "Authenticode-hash match (same code, different signature or padding)"
        return None

    def by_name(self, filename: str) -> Entry | None:
        hit = self.index["names"].get(filename.lower())
        return self.entries[hit] if hit else None

    def __len__(self) -> int:
        return len(self.entries)


def download(timeout: float = 120) -> list:
    req = urllib.request.Request(URL, headers={"User-Agent": "driver-guard"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def load(path: Path | None = None, update: bool = False, offline: bool = False, log=print) -> Catalogue | None:
    """A catalogue from a given drivers.json, else the cached index (fetched when missing or asked)."""
    if path:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return Catalogue(data if "hashes" in data else build_index(data))
    cached = cache_dir() / "loldrivers-index.json"
    if cached.exists() and not update:
        try:
            return Catalogue(json.loads(cached.read_text(encoding="utf-8")))
        except (OSError, ValueError, KeyError):
            pass
    if offline:
        return None
    log("fetching the LOLDrivers catalogue (loldrivers.io, about 36 MB, once) ...")
    index = build_index(download())
    cached.parent.mkdir(parents=True, exist_ok=True)
    cached.write_text(json.dumps(index), encoding="utf-8")
    return Catalogue(index)
