"""File hashes and the Authenticode hash of a driver.

The Authenticode hash ("authentihash") covers the PE image but not its signature or checksum, so it
stays the same when an attacker re-signs a known vulnerable driver with another certificate or
appends data to it: matching on it catches copies a plain file hash misses."""

from __future__ import annotations

import hashlib
import struct


class PEError(ValueError):
    pass


def file_hashes(data: bytes) -> dict[str, str]:
    return {"md5": hashlib.md5(data).hexdigest(), "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest()}


def authentihash(data: bytes, algo: str = "sha256") -> str:
    try:
        if data[:2] != b"MZ":
            raise PEError("not a PE file")
        lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[lfanew:lfanew + 4] != b"PE\0\0":
            raise PEError("no PE signature")
        nsec, opt_size = struct.unpack_from("<H", data, lfanew + 6)[0], struct.unpack_from("<H", data, lfanew + 20)[0]
        opt = lfanew + 24
        magic = struct.unpack_from("<H", data, opt)[0]
        if magic not in (0x10B, 0x20B):
            raise PEError("unknown optional header")
        checksum = opt + 64
        dirs = opt + (96 if magic == 0x10B else 112)
        secdir = dirs + 4 * 8
        size_of_headers = struct.unpack_from("<I", data, opt + 60)[0]
        cert_off, cert_size = struct.unpack_from("<II", data, secdir)
    except struct.error:
        raise PEError("truncated header") from None
    h = hashlib.new(algo)
    h.update(data[:checksum])
    h.update(data[checksum + 4:secdir])
    h.update(data[secdir + 8:size_of_headers])
    sections = []
    sec = opt + opt_size
    for i in range(nsec):
        try:
            rawsize, raw = struct.unpack_from("<II", data, sec + 40 * i + 16)
        except struct.error:
            raise PEError("truncated section table") from None
        if rawsize:
            sections.append((raw, rawsize))
    hashed = size_of_headers
    for raw, rawsize in sorted(sections):
        h.update(data[raw:raw + rawsize])
        hashed += rawsize
    end = len(data) - (cert_size if cert_off and cert_off + cert_size <= len(data) else 0)
    if end > hashed:
        h.update(data[hashed:end])                      # data after the sections, minus the certificate table
    return h.hexdigest()
