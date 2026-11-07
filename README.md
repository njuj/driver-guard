# driver-guard

**Find the kernel drivers on your PC that attackers use to switch off antivirus.**

Ransomware gangs and RAT operators don't need their own kernel exploit. They drop a legitimately signed
but vulnerable driver (an old overclocking tool, a hardware monitor, an anti-cheat) and use it to kill
the antivirus, hide processes or read passwords from memory. This is "bring your own vulnerable driver",
and those drivers are often already on the PC, installed by a tuning utility years ago.

`driver-guard` lists every kernel driver Windows knows about and checks each one against
[LOLDrivers](https://www.loldrivers.io), the community catalogue of 700+ vulnerable and malicious
drivers. It also flags what is out of place even when no catalogue knows it yet.

```
$ driver-guard

 driver-guard 0.1.0  ·  435 drivers (161 running)  ·  LOLDrivers 713 entries, 0 days old
 vulnerable driver blocklist: on  ·  memory integrity: on

 HIGH     cpuz159_x64.sys  service cpuz159, running
          C:\WINDOWS\temp\cpuz159\cpuz159_x64.sys
          • driver kept in a folder ordinary programs can write to
            CPUID · CPUID service · signed by Microsoft Windows Hardware Compatibility Publisher

 MEDIUM   CjYqchq39  service cpuz162, stopped, start: disabled
          C:\ProgramData\CPUID Software\sdk\CjYqchq39
          • driver kept in a folder ordinary programs can write to
          • driver file without a .sys extension (.CjYqchq39)

 LOW      RTCore64.sys  service RTCore64, running
          C:\Program Files (x86)\MSI Afterburner\RTCore64.sys
          • same file name as a known vulnerable driver, but not a listed build
```

(A real run on the author's PC: the listed tools ship fixed builds, but one still runs its driver from
a world-writable folder.)

## What it checks

| Check | Why it matters |
|---|---|
| **LOLDrivers by file hash** (SHA-256, SHA-1, MD5) | the exact file is a known weapon |
| **LOLDrivers by Authenticode hash** | the hash Windows itself uses: it ignores the signature and checksum, so a known driver re-signed or padded by an attacker still matches |
| Malicious vs vulnerable | a malicious match is malware on your PC; a vulnerable one is a door any program can use |
| Running or only installed | a loaded vulnerable driver is usable right now |
| Same name, different build | usually a fixed version; reported so you keep it updated |
| Signature (Windows' own verdict, catalog-signed files too) | unsigned or altered drivers |
| Location | a driver in Temp, a user folder or ProgramData can be swapped by any program |
| Odd names | no `.sys` extension, random hex names: how some tools and droppers hide drivers |
| Running driver whose file is gone | rootkits delete their file after loading |
| Blocklist and memory integrity | whether Windows would refuse a known vulnerable driver at all |

The Authenticode hash is computed by `driver-guard` itself and tested against Windows'
`Get-AppLockerFileInformation` on real system drivers.

## Use

```
driver-guard                       # every driver on this PC
driver-guard C:\suspicious\        # driver files or folders (works on Linux and macOS too)
driver-guard --json                # machine-readable
driver-guard --all                 # also informational findings
driver-guard --update              # refresh the LOLDrivers catalogue
driver-guard --offline             # never download
driver-guard --db drivers.json     # a LOLDrivers drivers.json you already have
```

Exit codes: `0` nothing at `--fail-on` level (default `high`) or worse, `1` found, `2` could not run.
The catalogue (about 36 MB) is downloaded once and kept as a small index in
`%LOCALAPPDATA%\driver-guard`.

Run it as administrator to also see drivers loaded without a service entry; without it, everything
registered as a service is still checked.

```
pip install git+https://github.com/njuj/driver-guard
```

or `python -m driverguard` from a clone. Python 3.10+, no dependencies.

## If it finds something

- **Vulnerable driver:** uninstall or update the program that installed it, then turn on
  Windows Security → Device security → Core isolation → *Microsoft Vulnerable Driver Blocklist*
  (and *Memory integrity*).
- **Malicious driver:** the PC is compromised. Back up your files and reinstall Windows.

`driver-guard` changes nothing on the system: it only reads.

## Tests

```
python -m unittest discover -s tests -t . -v
```

Catalogue lookups and every rule are tested against a made-up catalogue; on Windows the Authenticode
hash is checked against Windows' own on real drivers, and the live inventory is read.

## License

MIT
