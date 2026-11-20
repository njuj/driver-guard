"""A minimal x64 driver image with a chosen import table and code: enough for the capability reader.
Nothing in it runs; it is never loaded."""

import struct


def make_driver(imports: list[str], code: bytes = b"\xc3", dll: str = "ntoskrnl.exe") -> bytes:
    text_rva, idata_rva, align = 0x1000, 0x2000, 0x200
    # import directory: one descriptor, a null one, the lookup table, hint/name entries, the DLL name
    n = len(imports)
    ilt = 40
    names = ilt + 8 * (n + 1)
    blob, offs = b"", []
    for name in imports:
        offs.append(names + len(blob))
        entry = b"\0\0" + name.encode() + b"\0"
        blob += entry + b"\0" * (len(entry) % 2)
    dll_off = names + len(blob)
    idata = struct.pack("<IIIII", idata_rva + ilt, 0, 0, idata_rva + dll_off, idata_rva + ilt) + b"\0" * 20
    idata += b"".join(struct.pack("<Q", idata_rva + o) for o in offs) + b"\0" * 8 + blob + dll.encode() + b"\0"

    def pad(b):
        return b + b"\0" * (-len(b) % align)
    code, idata = pad(code), pad(idata)
    dos = b"MZ" + b"\0" * 58 + struct.pack("<I", 0x40)
    coff = b"PE\0\0" + struct.pack("<HHIIIHH", 0x8664, 2, 0, 0, 0, 240, 0x22)
    dirs = bytearray(16 * 8)
    struct.pack_into("<II", dirs, 8, idata_rva, len(idata))
    opt = struct.pack("<HBBIIIIIQIIHHHHHHIIIIHHQQQQII", 0x20B, 14, 0, len(code), len(idata), 0, text_rva, text_rva,
                      0x140000000, 0x1000, align, 10, 0, 10, 0, 10, 0, 0, 0x3000, 0x400, 0, 1, 0x160,
                      0x40000, 0x1000, 0x100000, 0x1000, 0, 16) + bytes(dirs)
    sec = (struct.pack("<8sIIIIIIHHI", b".text", len(code), text_rva, len(code), 0x400, 0, 0, 0, 0, 0x60000020) +
           struct.pack("<8sIIIIIIHHI", b".idata", len(idata), idata_rva, len(idata), 0x400 + len(code), 0, 0, 0, 0, 0xC0000040))
    head = (dos + coff + opt + sec).ljust(0x400, b"\0")
    return head + code + idata
