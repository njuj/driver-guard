"""driver-guard against a made-up LOLDrivers catalogue and, on Windows, the real drivers of the
machine running the tests (Windows' own AppLocker hash is the reference for the Authenticode hash)."""

import contextlib
import io
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from driverguard import analyze, caps, cli, lol, pe, windows  # noqa: E402
sys.path.insert(0, str(Path(__file__).resolve().parent))
from drvbuild import make_driver  # noqa: E402
from driverguard.analyze import Driver  # noqa: E402

WIN = sys.platform == "win32"
SYSDRV = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers"


def fake_catalogue(**hashes) -> list:
    """LOLDrivers' own JSON layout, two entries."""
    return [
        {"Id": "aaaa-mal", "Category": "malicious", "Tags": ["evil.sys"], "MitreID": "T1543", "Verified": "TRUE",
         "Commands": {"Usecase": "Elevate privileges", "Description": "test"},
         "KnownVulnerableSamples": [{"SHA256": hashes.get("mal", "")}]},
        {"Id": "bbbb-vuln", "Category": "vulnerable driver", "Tags": ["oldtool.sys"], "MitreID": "T1068",
         "Verified": "TRUE", "Commands": [{"Usecase": "Terminate EDR processes", "Description": "test"}],
         "KnownVulnerableSamples": [{"MD5": hashes.get("md5", ""), "Authentihash": {"SHA256": hashes.get("auth", "")}}]},
    ]


def H(c):
    return {"md5": c * 32, "sha1": c * 40, "sha256": c * 64}


class CatalogueTest(unittest.TestCase):
    def setUp(self):
        self.cat = lol.Catalogue(lol.build_index(fake_catalogue(mal="a" * 64, md5="b" * 32, auth="c" * 64)))

    def test_lookups(self):
        self.assertEqual(self.cat.by_hash(H("a"), None)[0].id, "aaaa-mal")
        self.assertEqual(self.cat.by_hash(H("b"), None)[1], "MD5 match")
        hit = self.cat.by_hash(H("d"), "c" * 64)
        self.assertEqual(hit[0].usecase, "Terminate EDR processes")
        self.assertIn("Authenticode", hit[1])
        self.assertIsNone(self.cat.by_hash(H("d"), "e" * 64))
        self.assertEqual(self.cat.by_name("OldTool.SYS").id, "bbbb-vuln")

    def test_cached_index_round_trips(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "index.json"
            p.write_text(json.dumps(self.cat.index))
            self.assertEqual(len(lol.load(p)), 2)


class JudgeTest(unittest.TestCase):
    def setUp(self):
        self.cat = lol.Catalogue(lol.build_index(fake_catalogue(mal="a" * 64, md5="b" * 32)))

    def judged(self, path=r"C:\Windows\System32\drivers\x.sys", hashes="f", sig=None, **kw):
        d = Driver(path, exists=True, hashes=H(hashes), sig=sig or {"status": "Valid", "signer": "CN=Vendor"}, **kw)
        d.match = self.cat.by_hash(d.hashes, None)
        analyze.judge(d, self.cat)
        return d

    def test_malicious_is_critical_even_when_stopped(self):
        self.assertEqual(self.judged(hashes="a", service="x", state="Stopped").worst, "critical")

    def test_vulnerable_running_vs_installed(self):
        self.assertEqual(self.judged(hashes="b", service="x", state="Running").worst, "high")
        self.assertEqual(self.judged(hashes="b", service="x", state="Stopped").worst, "medium")

    def test_name_only(self):
        self.assertEqual(self.judged(r"C:\Windows\System32\drivers\oldtool.sys").worst, "low")
        own = self.judged(r"C:\Windows\System32\drivers\oldtool.sys",
                          sig={"status": "Valid", "signer": "CN=Microsoft Windows, O=Microsoft Corporation"})
        self.assertEqual(own.worst, "info")

    def test_signatures(self):
        self.assertEqual(self.judged(sig={"status": "NotSigned"}, state="Running").worst, "high")
        self.assertEqual(self.judged(sig={"status": "HashMismatch"}).worst, "high")
        self.assertEqual(self.judged().worst, "")

    def test_locations_and_names(self):
        self.assertEqual(self.judged(r"C:\Windows\Temp\t\a.sys").worst, "high")
        self.assertEqual(self.judged(r"C:\Users\me\AppData\Local\a.sys").worst, "high")
        self.assertEqual(self.judged(r"C:\ProgramData\Vendor\a.sys").worst, "medium")
        self.assertEqual(self.judged(r"C:\Program Files\Vendor\a.sys").worst, "")
        self.assertEqual(self.judged(r"C:\Windows\System32\drivers\Xq81nZ").worst, "low")
        self.assertEqual(self.judged(r"C:\Windows\System32\drivers\0a1b2c3d4e.sys").worst, "low")

    def test_missing_files(self):
        gone = Driver(r"C:\nowhere\r.sys", service="r", state="Running")
        analyze.judge(gone, self.cat)
        self.assertEqual(gone.worst, "high")
        left = Driver(r"C:\nowhere\r.sys", service="r", state="Stopped", start="Manual")
        analyze.judge(left, self.cat)
        self.assertEqual(left.worst, "info")

    def test_hardening(self):
        self.assertEqual([f.severity for f in analyze.hardening({"blocklist": "off (turned off)",
                                                                   "memory_integrity": "off"})], ["medium", "info"])
        self.assertEqual(analyze.hardening({"blocklist": "on", "memory_integrity": "on"}), [])


OPEN_DEVICE = ["IoCreateDevice", "IoCreateSymbolicLink"]


class CapabilityTest(unittest.TestCase):
    """What a driver can do, from its imports and code: unknown BYOVD drivers without a catalogue."""

    def caps(self, imports, code=b"\xc3"):
        return caps.capabilities(make_driver(imports, code))

    def judged(self, data, sig=None, state="Running", hashes="f"):
        with tempfile.TemporaryDirectory() as t:
            path = Path(t) / "iotool.sys"
            path.write_bytes(data)
            d = Driver(str(path), service="iotool", state=state)
            analyze.read(d, None)
        d.path = r"C:\Windows\System32\drivers\iotool.sys"         # judged where drivers belong
        d.sig = sig or {"status": "Valid", "signer": "CN=Some Vendor"}
        analyze.judge(d, None)
        return d

    def test_open_device_with_a_weapon_is_a_byovd_candidate(self):
        for imp, word in (("MmMapIoSpace", "map physical memory"), ("ZwTerminateProcess", "kill any process"),
                          ("MmCopyVirtualMemory", "read and write other processes' memory")):
            d = self.judged(make_driver(OPEN_DEVICE + [imp]))
            self.assertEqual(d.worst, "medium", imp)
            self.assertIn(word, d.findings[0].title)
        stopped = self.judged(make_driver(OPEN_DEVICE + ["MmMapIoSpace"]), state="Stopped")
        self.assertEqual(stopped.worst, "low")

    def test_cr0_write_found_in_code(self):
        c = self.caps(OPEN_DEVICE, b"\x48\x89\xc8\x0f\x22\xc0\xc3")              # mov rax, rcx; mov cr0, rax
        self.assertEqual(c.weapons, ["cr"])
        self.assertTrue(c.byovd)

    def test_what_is_not_a_candidate(self):
        self.assertFalse(self.caps(["IoCreateDevice", "MmMapIoSpace"]).byovd)                       # no name to open
        self.assertFalse(self.caps(["IoCreateDeviceSecure", "IoCreateSymbolicLink", "MmMapIoSpace"]).byovd)  # ACL
        self.assertFalse(self.caps(OPEN_DEVICE + ["MmMapIoSpace", "IoRegisterDeviceInterface"]).byovd)  # PnP hardware
        self.assertFalse(self.caps(OPEN_DEVICE + ["ExAllocatePool2"]).byovd)                         # nothing to abuse
        self.assertFalse(self.caps(OPEN_DEVICE, b"\x0f\x30\xc3").byovd)                          # wrmsr bytes alone
        own = self.judged(make_driver(OPEN_DEVICE + ["MmMapIoSpace"]),
                          sig={"status": "Valid", "signer": "CN=Microsoft Windows, O=Microsoft Corporation"})
        self.assertEqual(own.worst, "")

    def test_catalogue_match_says_what_it_can_do(self):
        data = make_driver(OPEN_DEVICE + ["ZwTerminateProcess"])
        cat = lol.Catalogue(lol.build_index(fake_catalogue(md5=pe.file_hashes(data)["md5"])))
        with tempfile.TemporaryDirectory() as t:
            path = Path(t) / "killer.sys"
            path.write_bytes(data)
            d = Driver(str(path), service="k", state="Running")
            analyze.read(d, cat)
        d.path = r"C:\Windows\System32\drivers\killer.sys"
        analyze.judge(d, cat)
        self.assertEqual(len(d.findings), 1)                    # the catalogue verdict, not a second candidate
        self.assertIn("It can: kill any process", d.findings[0].detail)

    def test_unlisted_build_of_a_listed_name_still_shaped_like_a_weapon(self):
        data = make_driver(OPEN_DEVICE + ["MmMapIoSpace"])
        cat = lol.Catalogue(lol.build_index(fake_catalogue()))                     # lists "oldtool.sys" by name only
        with tempfile.TemporaryDirectory() as t:
            path = Path(t) / "oldtool.sys"
            path.write_bytes(data)
            d = Driver(str(path), service="o", state="Running")
            analyze.read(d, cat)
        d.path = r"C:\Windows\System32\drivers\oldtool.sys"
        analyze.judge(d, cat)
        self.assertEqual([x.severity for x in d.findings], ["medium"])             # one finding, not "probably fixed"
        self.assertIn("earlier one with the same name is a known weapon", d.findings[0].detail)

    def test_damaged_files_never_raise(self):
        import random
        good = make_driver(OPEN_DEVICE + ["MmMapIoSpace"])
        rnd = random.Random(7)
        for _ in range(400):
            data = bytearray(good[:rnd.randrange(len(good))]) if rnd.random() < .3 else bytearray(good)
            for _ in range(rnd.randrange(1, 12)):
                if data:
                    data[rnd.randrange(len(data))] = rnd.randrange(256)
            caps.capabilities(bytes(data))                        # must return, whatever the bytes

    @unittest.skipUnless(WIN, "Windows only")
    def test_windows_own_drivers_parse(self):
        parsed = [caps.capabilities(p.read_bytes()) for p in sorted(SYSDRV.glob("*.sys"))[:60]]
        self.assertTrue(parsed and all(c is not None and c.imports for c in parsed))


class NormalizeTest(unittest.TestCase):
    def test_service_path_forms(self):
        root = windows.SYSROOT
        cases = {r"\SystemRoot\System32\drivers\a.sys": root + r"\System32\drivers\a.sys",
                 r"System32\drivers\a.sys": root + r"\System32\drivers\a.sys",
                 r"\??\C:\Tools\a.sys": r"C:\Tools\a.sys",
                 r'"C:\Program Files\V\a.sys"': r"C:\Program Files\V\a.sys",
                 r"%windir%\a.sys": root + r"\a.sys"}
        for raw, want in cases.items():
            self.assertEqual(windows.normalize(raw), want, raw)


class CliTest(unittest.TestCase):
    def test_folder_scan_finds_a_listed_file(self):
        with tempfile.TemporaryDirectory() as t:
            sample = Path(t) / "drivers" / "oldtool.sys"
            sample.parent.mkdir()
            sample.write_bytes(b"not a real driver, only its hash matters here")
            db = Path(t) / "drivers.json"
            db.write_text(json.dumps(fake_catalogue(md5=pe.file_hashes(sample.read_bytes())["md5"])))
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                code = cli.main([str(sample.parent), "--db", str(db), "--json", "--fail-on", "medium"])
            report = json.loads(out.getvalue())
            self.assertEqual(code, 1)
            self.assertEqual(report["drivers"][0]["loldrivers"]["id"], "bbbb-vuln")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main([str(Path(t) / "missing"), "--db", str(db)]), 2)


@unittest.skipUnless(WIN, "Windows only")
class WindowsTest(unittest.TestCase):
    def applocker(self, path):
        r = subprocess.run(["powershell", "-NoProfile", "-Command",
                            f"(Get-AppLockerFileInformation -Path '{path}').Hash.HashDataString"],
                           capture_output=True, text=True)
        return r.stdout.strip().lower().removeprefix("0x")

    def test_authentihash_equals_windows(self):
        for name in ("tcpip.sys", "ntfs.sys", "null.sys"):
            p = SYSDRV / name
            if p.exists():
                with self.subTest(name):
                    self.assertEqual(pe.authentihash(p.read_bytes()), self.applocker(p))

    def test_authentihash_ignores_checksum_and_certificate(self):
        data = bytearray((SYSDRV / "tcpip.sys").read_bytes())
        base = pe.authentihash(bytes(data))
        lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        opt = lfanew + 24
        data[opt + 64] ^= 0xFF                                         # checksum
        self.assertEqual(pe.authentihash(bytes(data)), base)
        cert_off, cert_size = struct.unpack_from("<II", data, opt + 112 + 32)
        if cert_size:
            data[cert_off + cert_size - 1] ^= 0xFF                     # inside the signature blob
            self.assertEqual(pe.authentihash(bytes(data)), base)
        data[0x400] ^= 0xFF                                             # code
        self.assertNotEqual(pe.authentihash(bytes(data)), base)
        with self.assertRaises(pe.PEError):
            pe.authentihash(b"MZ" + bytes(10))

    def test_live_inventory(self):
        svcs = windows.services()
        self.assertGreater(len(svcs), 50)
        self.assertTrue(any(s.name.lower() == "tcpip" and s.state == "Running" for s in svcs))
        sig = windows.signatures([str(SYSDRV / "tcpip.sys")])
        self.assertEqual(next(iter(sig.values()))["status"], "Valid")
        self.assertIn(windows.hardening()["memory_integrity"], ("on", "off"))


if __name__ == "__main__":
    unittest.main()
