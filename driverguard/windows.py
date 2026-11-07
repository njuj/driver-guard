"""What Windows knows about its drivers: every kernel driver service and whether it runs, the list of
loaded modules (when running as administrator), Authenticode verdicts (embedded and catalog
signatures alike, from Windows itself), version information, and the two settings that decide whether
a known vulnerable driver can load at all."""

from __future__ import annotations

import ctypes
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass

SYSROOT = os.environ.get("SystemRoot", r"C:\Windows")


@dataclass
class Service:
    name: str
    display: str
    state: str          # Running | Stopped
    start: str          # Boot | System | Auto | Manual | Disabled
    raw_path: str
    path: str


def normalize(raw: str) -> str:
    """\\SystemRoot\\..., \\??\\C:\\..., system32\\drivers\\x.sys, quoted -> a plain Windows path."""
    p = raw.strip().strip('"')
    p = re.sub(r"^\\\?\?\\", "", p)
    p = re.sub(r"(?i)^(\\SystemRoot|%SystemRoot%|%windir%)\\", lambda m: SYSROOT + "\\", p)
    if re.match(r"(?i)^system32\\", p):
        p = SYSROOT + "\\" + p
    if re.match(r"(?i)^\\Windows\\", p):
        p = SYSROOT[:2] + p
    return p


def _powershell(script: str, stdin: str = "", timeout: float = 600) -> str:
    env = {k: v for k, v in os.environ.items() if k.upper() != "PSMODULEPATH"}   # pwsh 7's path breaks 5.1's modules
    env["DG_INPUT"] = stdin
    r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", "-"], input=script + "\n",
                       capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout,
                       env=env)
    return r.stdout


_SERVICES = r"""
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'
Get-CimInstance Win32_SystemDriver | ForEach-Object {
  [pscustomobject]@{ name = $_.Name; display = $_.DisplayName; state = $_.State; start = $_.StartMode; path = $_.PathName }
} | ConvertTo-Json -Compress
"""

_SIGNATURES = r"""
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'
$paths = $env:DG_INPUT | ConvertFrom-Json
$out = @{}
foreach ($p in $paths) {
  if (-not (Test-Path -LiteralPath $p)) { continue }
  $s = Get-AuthenticodeSignature -LiteralPath $p
  $v = (Get-Item -LiteralPath $p).VersionInfo
  $out[$p] = [pscustomobject]@{
    status = [string]$s.Status; type = [string]$s.SignatureType
    signer = if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { '' }
    issuer = if ($s.SignerCertificate) { $s.SignerCertificate.Issuer } else { '' }
    expires = if ($s.SignerCertificate) { $s.SignerCertificate.NotAfter.ToString('yyyy-MM-dd') } else { '' }
    company = $v.CompanyName; product = $v.ProductName; description = $v.FileDescription
    version = $v.FileVersion; original = $v.OriginalFilename
  }
}
$out | ConvertTo-Json -Compress -Depth 3
"""


def services() -> list[Service]:
    raw = _powershell(_SERVICES)
    try:
        items = json.loads(raw) if raw.strip() else []
    except ValueError:
        items = []
    if isinstance(items, dict):
        items = [items]
    return [Service(i.get("name") or "", i.get("display") or "", i.get("state") or "", i.get("start") or "",
                    i.get("path") or "", normalize(i.get("path") or "")) for i in items]


def signatures(paths: list[str]) -> dict[str, dict]:
    if not paths:
        return {}
    raw = _powershell(_SIGNATURES, json.dumps(sorted(set(paths))))
    try:
        found = json.loads(raw) if raw.strip() else {}
    except ValueError:
        return {}
    return {k.lower(): v for k, v in found.items()}


def loaded_modules() -> list[str] | None:
    """Every module in the kernel's address space; None when Windows hides the list (not administrator)."""
    if sys.platform != "win32":
        return None
    from ctypes import wintypes
    psapi = ctypes.WinDLL("psapi")
    psapi.EnumDeviceDrivers.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    psapi.GetDeviceDriverFileNameW.argtypes = [ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD]
    arr = (ctypes.c_void_p * 8192)()
    needed = wintypes.DWORD()
    if not psapi.EnumDeviceDrivers(arr, ctypes.sizeof(arr), ctypes.byref(needed)):
        return None
    n = min(needed.value // ctypes.sizeof(ctypes.c_void_p), len(arr))
    if not any(arr[i] for i in range(n)):
        return None                                     # addresses withheld: not elevated
    buf = ctypes.create_unicode_buffer(1024)
    out = []
    for i in range(n):
        if arr[i] and psapi.GetDeviceDriverFileNameW(arr[i], buf, 1024):
            out.append(normalize(buf.value))
    return out


def _reg(path: str, value: str):
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as k:
            return winreg.QueryValueEx(k, value)[0]
    except OSError:
        return None


def hardening() -> dict[str, str]:
    """Microsoft's vulnerable driver blocklist and memory integrity (HVCI), as configured."""
    if sys.platform != "win32":
        return {}
    blocklist = _reg(r"SYSTEM\CurrentControlSet\Control\CI\Config", "VulnerableDriverBlocklistEnable")
    hvci = _reg(r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled")
    build = int(_reg(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuildNumber") or 0)
    if blocklist is None:
        bl = "on (Windows default)" if build >= 22621 else "off (not enabled on this Windows build by default)"
    else:
        bl = "on" if blocklist else "off (turned off)"
    return {"blocklist": bl, "memory_integrity": "on" if hvci == 1 else "off", "build": str(build)}
