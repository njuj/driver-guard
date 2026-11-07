"""driver-guard: find kernel drivers on this PC that attackers use to switch off antivirus."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

from . import __version__, analyze, lol, windows
from .analyze import SEVERITIES, Driver

COLOR = {"critical": "\033[1;97;41m", "high": "\033[1;91m", "medium": "\033[1;93m", "low": "\033[96m",
         "info": "\033[90m", "dim": "\033[90m", "bold": "\033[1m", "": ""}


def _console_utf8():
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    if sys.platform == "win32":
        os.system("")                                   # turns on ANSI colours in the classic console


def live() -> tuple[list[Driver], dict, bool]:
    drivers = {}
    for s in windows.services():
        if s.path:
            drivers.setdefault(s.path.lower(), Driver(s.path, s.name, s.display, s.state, s.start))
    loaded = windows.loaded_modules()
    for p in loaded or []:
        d = drivers.setdefault(p.lower(), Driver(p, state="Running"))
        d.loaded = True
    return list(drivers.values()), windows.hardening(), loaded is not None


def to_json(drivers, hard, extra) -> str:
    def one(d: Driver):
        return {"path": d.path, "service": d.service, "state": d.state or None, "running": d.running,
                "exists": d.exists, "hashes": d.hashes, "authentihash": d.auth, "signature": d.sig,
                "loldrivers": {"id": d.match[0].id, "category": d.match[0].category, "how": d.match[1],
                               "usecase": d.match[0].usecase, "link": d.match[0].link} if d.match else None,
                "findings": [f.__dict__ for f in d.findings]}
    return json.dumps({"tool": "driver-guard", "version": __version__, "hardening": hard,
                       "system_findings": [f.__dict__ for f in extra], "drivers": [one(d) for d in drivers]},
                      indent=2)


def render(drivers, hard, extra, catalogue, admin, shown, color=True) -> str:
    c = (lambda k: COLOR[k]) if color else (lambda k: "")
    r = "\033[0m" if color else ""
    out = []
    running = sum(d.running for d in drivers if d.service or d.loaded)
    head = f" driver-guard {__version__}  ·  {len(drivers)} drivers"
    if any(d.service for d in drivers):
        head += f" ({running} running)"
    if catalogue:
        head += f"  ·  LOLDrivers {len(catalogue)} entries, {catalogue.age_days:.0f} days old"
    else:
        head += "  ·  no LOLDrivers catalogue (run with --update)"
    out += [f"{c('bold')}{head}{r}"]
    if hard:
        out.append(f" {c('dim')}vulnerable driver blocklist: {hard['blocklist']}  ·  memory integrity: "
                   f"{hard['memory_integrity']}{r}")
    if hard and not admin:
        out.append(f" {c('dim')}not administrator: drivers loaded without a service entry are not listed{r}")
    out.append("")
    hits = [d for d in drivers if d.findings and SEVERITIES.index(d.worst) <= shown]
    hits.sort(key=lambda d: (SEVERITIES.index(d.worst), not d.running, d.filename.lower()))
    for d in hits:
        sev = d.worst
        state = []
        if d.service:
            state.append(f"service {d.service}")
        if d.running:
            state.append("running")
        elif d.service:
            state.append(f"stopped, start: {d.start.lower()}")
        out.append(f" {c(sev)}{sev.upper():8}{r} {c('bold')}{d.filename}{r}  {c('dim')}{', '.join(state)}{r}")
        out.append(f"          {d.path}")
        for f in d.findings:
            if SEVERITIES.index(f.severity) > shown:
                continue
            out.append(f"          {c(f.severity)}•{r} {f.title}")
            if f.detail:
                out.append(f"            {c('dim')}{f.detail}{r}")
        if d.sig:
            who = re.search(r"CN=(\"[^\"]+\"|[^,]+)", d.sig.get("signer") or "")
            bits = [x for x in (d.sig.get("company"), d.sig.get("product"), d.sig.get("version")) if x]
            if who:
                bits.append(f"signed by {who.group(1).strip(chr(34))}")
            if bits:
                out.append(f"            {c('dim')}{' · '.join(bits)}{r}")
        out.append("")
    for f in extra:
        if SEVERITIES.index(f.severity) <= shown:
            out.append(f" {c(f.severity)}{f.severity.upper():8}{r} {f.title}")
            out.append(f"            {c('dim')}{f.detail}{r}")
    if extra:
        out.append("")
    counts = {s: sum(d.worst == s for d in drivers) for s in SEVERITIES[:4]}
    if not any(counts.values()):
        out.append(f" {c('bold')}no known vulnerable or malicious drivers, nothing out of place{r}")
    else:
        out.append(" " + "  ".join(f"{c(s)}{n} {s}{r}" for s, n in counts.items() if n))
        if any(d.match for d in drivers):
            out += ["",
                    f" {c('bold')}WHAT TO DO{r}",
                    "   • uninstall the program that installed it (Apps → Installed apps), or update it to a",
                    "     version that no longer ships the vulnerable driver",
                    "   • then turn on Windows Security → Device security → Core isolation → Microsoft Vulnerable",
                    "     Driver Blocklist (and Memory integrity), so it cannot be loaded again",
                    "   • a MALICIOUS match means this PC is compromised: back up your files and reinstall Windows"]
    return "\n".join(out)


def main(argv=None) -> int:
    _console_utf8()
    ap = argparse.ArgumentParser(prog="driver-guard", description=__doc__)
    ap.add_argument("paths", nargs="*", help="driver files or folders to check (default: this PC's drivers)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--all", action="store_true", help="also show informational findings")
    ap.add_argument("--update", action="store_true", help="download the latest LOLDrivers catalogue")
    ap.add_argument("--offline", action="store_true", help="never download; use the cached catalogue")
    ap.add_argument("--db", help="use this LOLDrivers drivers.json instead of the cache")
    ap.add_argument("--fail-on", choices=SEVERITIES[:4], default="high",
                    help="exit 1 when a finding at this level or worse exists (default: high)")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--version", action="version", version=__version__)
    a = ap.parse_args(argv)

    try:
        catalogue = lol.load(a.db, a.update, a.offline, log=lambda m: print(m, file=sys.stderr))
    except (OSError, ValueError) as e:
        print(f"driver-guard: could not get the LOLDrivers catalogue: {e}", file=sys.stderr)
        catalogue = None
    if catalogue is None:
        print("driver-guard: checking without LOLDrivers (signatures and locations only)", file=sys.stderr)

    if a.paths:
        missing = [p for p in a.paths if not os.path.exists(p)]
        if missing:
            print(f"driver-guard: not found: {', '.join(missing)}", file=sys.stderr)
            return 2
        drivers, hard, admin = analyze.scan_files(a.paths), {}, True
    elif sys.platform != "win32":
        print("driver-guard: checking this PC needs Windows; give driver files to check instead", file=sys.stderr)
        return 2
    else:
        drivers, hard, admin = live()
    sigs = windows.signatures([d.path for d in drivers if os.path.exists(d.path)]) if sys.platform == "win32" \
        else None
    analyze.run(drivers, catalogue, sigs)
    extra = analyze.hardening(hard)

    if a.json:
        print(to_json(drivers, hard, extra))
    else:
        shown = SEVERITIES.index("info" if a.all else "low")
        print(render(drivers, hard, extra, catalogue, admin, shown, color=not a.no_color and sys.stdout.isatty()))
    limit = SEVERITIES.index(a.fail_on)
    worst = [SEVERITIES.index(d.worst) for d in drivers if d.worst] + [SEVERITIES.index(f.severity) for f in extra]
    return 1 if worst and min(worst) <= limit else 0
