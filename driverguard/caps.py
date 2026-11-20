"""What a driver can do, read from its import table and its code: the kernel primitives that make a
driver usable as a weapon, whether or not any catalogue lists it yet.

A vulnerable driver is dangerous when two things meet: it exposes a device that ordinary programs
can open, and behind that device sits a primitive an attacker wants (map physical memory, kill a
process, copy another process's memory, write CPU registers). Real BYOVD drivers (RTCore64,
gdrv, the "Terminator" AV killers) all have both; most drivers have neither."""

from __future__ import annotations

import struct

# import name -> (capability id, plain words)
IMPORTS = {
    "MmMapIoSpace": ("physmem", "map physical memory"),
    "MmMapIoSpaceEx": ("physmem", "map physical memory"),
    "MmCopyMemory": ("physmem", "map physical memory"),
    "MmGetPhysicalAddress": ("physmem", "map physical memory"),
    "ZwTerminateProcess": ("kill", "kill any process"),
    "NtTerminateProcess": ("kill", "kill any process"),
    "MmCopyVirtualMemory": ("vmem", "read and write other processes' memory"),
    "KeStackAttachProcess": ("vmem", "read and write other processes' memory"),
    "ZwWriteVirtualMemory": ("vmem", "read and write other processes' memory"),
    "READ_PORT_UCHAR": ("ports", "talk to hardware ports"),
    "WRITE_PORT_UCHAR": ("ports", "talk to hardware ports"),
    "WRITE_PORT_ULONG": ("ports", "talk to hardware ports"),
    "HalSetBusDataByOffset": ("ports", "talk to hardware ports"),
}
DEVICE = {"IoCreateSymbolicLink", "WdfDeviceCreateSymbolicLink"}       # reachable from user mode by a name
SECURE = {"IoCreateDeviceSecure", "WdmlibIoCreateDeviceSecure"}         # with an access list (SDDL)
PNP = {"IoRegisterDeviceInterface", "IoAttachDeviceToDeviceStack", "IoAttachDeviceToDeviceStackSafe",
       "PcInitializeAdapterDriver", "StorPortInitialize", "NdisMRegisterMiniportDriver"}
PHYS_DEVICE = "\\Device\\PhysicalMemory".encode("utf-16-le")
WEAPONS = {"physmem", "kill", "vmem", "cr"}     # what BYOVD tools use; a wrmsr byte pair alone is too common to count
WORDS = {"msr": "write CPU model-specific registers", "cr": "switch off kernel write protection (CR0)",
         "physmem": "map physical memory", "kill": "kill any process",
         "vmem": "read and write other processes' memory", "ports": "talk to hardware ports"}


class Caps:
    def __init__(self, imports: set[str], found: dict[str, str], device: bool, secure: bool):
        self.imports = imports
        self.found = found                        # capability id -> plain words
        self.device = device                      # a symbolic link: any program can open it by name
        self.secure = secure                      # the device was created with an access list

    @property
    def weapons(self) -> list[str]:
        return [w for w in WORDS if w in self.found and w in WEAPONS]

    @property
    def pnp(self) -> bool:
        """A hardware (Plug and Play) driver: user mode reaches it through a device interface whose access
        the device class controls, not through a name anyone can open. GPU and audio drivers map physical
        memory for good reasons; the BYOVD drivers measured (RTCore64, AsIO3, MsIo64, NTIOLib...) are all
        small legacy drivers that are not."""
        return bool(self.imports & PNP)

    @property
    def byovd(self) -> bool:
        return self.device and not self.secure and not self.pnp and bool(self.weapons)

    def describe(self) -> str:
        return ", ".join(WORDS[k] for k in WORDS if k in self.found)


def _sections(data: bytes, lfanew: int):
    nsec = struct.unpack_from("<H", data, lfanew + 6)[0]
    opt_size = struct.unpack_from("<H", data, lfanew + 20)[0]
    sec = lfanew + 24 + opt_size
    out = []
    for i in range(min(nsec, 96)):
        name, vsize, rva, rawsize, raw = struct.unpack_from("<8sIIII", data, sec + 40 * i)
        chars = struct.unpack_from("<I", data, sec + 40 * i + 36)[0]
        out.append((rva, max(vsize, rawsize), raw, rawsize, chars))
    return out


def _imports(data: bytes, lfanew: int, sections) -> set[str]:
    opt = lfanew + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    dirs = opt + (96 if magic == 0x10B else 112)
    imp_rva = struct.unpack_from("<I", data, dirs + 8)[0]
    wide = magic == 0x20B

    def off(rva: int) -> int | None:
        for srva, size, raw, rawsize, _ in sections:
            if srva <= rva < srva + size and rva - srva < rawsize:
                return raw + rva - srva
        return None

    def cstr(o: int) -> str:
        end = data.find(b"\0", o, o + 256)
        return data[o:end if end != -1 else o + 256].decode("latin-1")

    names: set[str] = set()
    d = off(imp_rva) if imp_rva else None
    for _ in range(64):                                           # descriptors, bounded
        if d is None or d + 20 > len(data):
            break
        oft, _, _, name_rva, ft = struct.unpack_from("<IIIII", data, d)
        if not (oft or name_rva or ft):
            break
        t = off(oft or ft)
        for _ in range(4096):                                     # thunks, bounded
            if t is None or t + (8 if wide else 4) > len(data):
                break
            v = struct.unpack_from("<Q" if wide else "<I", data, t)[0]
            if not v:
                break
            if not v >> (63 if wide else 31):                     # by name, not by ordinal
                h = off(v & 0x7FFFFFFF)
                if h is not None:
                    names.add(cstr(h + 2))
            t += 8 if wide else 4
        d += 20
    return names


def _code_patterns(data: bytes, sections) -> dict[str, str]:
    found = {}
    for _, _, raw, rawsize, chars in sections:
        if not chars & 0x20000000:                                # IMAGE_SCN_MEM_EXECUTE
            continue
        code = data[raw:raw + rawsize]
        if b"\x0f\x30" in code:                                   # wrmsr
            found["msr"] = WORDS["msr"]
        if any(b"\x0f\x22" + bytes([0xC0 + r]) in code for r in range(8)):   # mov cr0, reg
            found["cr"] = WORDS["cr"]
    return found


def capabilities(data: bytes) -> Caps | None:
    """None when the file is not a PE this parser can read; never raises on a damaged file."""
    try:
        if data[:2] != b"MZ":
            return None
        lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[lfanew:lfanew + 4] != b"PE\0\0":
            return None
        sections = _sections(data, lfanew)
        imports = _imports(data, lfanew, sections)
        found = _code_patterns(data, sections)
    except (struct.error, IndexError):
        return None
    for name in imports:
        if name in IMPORTS:
            cid, words = IMPORTS[name]
            found.setdefault(cid, words)
    if PHYS_DEVICE in data and "ZwOpenSection" in imports:
        found.setdefault("physmem", WORDS["physmem"])
    return Caps(imports, found, bool(imports & DEVICE), bool(imports & SECURE))
