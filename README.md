# AIC8800 wireless dongle — reverse engineering

Reverse-engineering notes and analysis for the AICSemi AIC8800D80 USB
Wi-Fi 6 + Bluetooth dongle (Temu). Covers the Windows installer, the
RISC-V firmware blobs, the Linux driver stack, and the USB host→device
protocol.

## Device

| Field | Value |
|---|---|
| Chip | AICSemi AIC8800D80 |
| USB | `a69c:8d81` (also `368b:8d81`), serial `20220103` |
| Also | `1111:1111` Pandora FLASH disk (label `WiF6-driver`) with the Windows installer |
| Driver source | [rtk94/aic8800d80-clone-dongle](https://github.com/rtk94/aic8800d80-clone-dongle) (fork of shenmintao/aic8800d80) |
| Local clone | `~/audit-p5/aic8800d80` |

## What we found

- **Windows installer** (`Wifi6_install.exe`) is an **InstallShield stub**
  (DVCLAL + PACKAGEINFO resources), unsigned (no Authenticode in the PE),
  with a 2.84 MB compressed overlay. It unpacks under Wine to two kernel
  drivers: a KMDF firmware loader (`aicloadfw.sys`, forked from
  Microsoft's **OSRUSBFX2 sample**) and an NDIS 6 miniport
  (`aicusbwifi.sys`). Driver v6.40.32.216 (Aug 31 2024), git `f7c1be8`.
- **Firmware** `fmacfw_8800d80_u02.bin` (358 KB) is a **RISC-V 32-bit LE
  bare-metal RTOS** image (RivieraWaves `ke_task` layer), build
  `la Dec 05 2025 19:45:42 - g586bc1e8`. Container magic `WFFW` at
  offset 0x20. Handles MAC state machines: scan, join, rate control,
  block-ack, TWT, radio measurement.
- **RF firmware** `lmacfw_rf_8800d80_u02.bin` (278 KB) is also RISC-V, with
  a calibration CLI (eFuse, RSSI, PAPR, xtal, notch, SRRC, FSS, temp
  compensation, USB VID/PID flash config).
- **USB protocol**: vendor-specific bulk OUT (EP 0x01) with 20-byte
  command headers (`14041100 00000000 0b040100 <addr> <len>`) and
  1028-byte data chunks; fmacfw verified in the captured stream.
- **Windows ↔ Linux**: both stacks share the RivieraWaves `rwnx_*` API.
  Linux driver is host-side only (sends `*_req`/`*_cfm` messages);
  firmware owns the MAC state machines. `TASK_*` enums are the shared
  vocabulary.

## Findings, by pass

| Pass | Notes |
|---|---|
| 1 — Inventory + static RE | [notes/01-inventory.md](notes/01-inventory.md) — device ID, installer structure, firmware WFFW header, kernel module inventory |
| 2 — Wine / usbmon / Ghidra | [notes/02-wine-usbmon-ghidra.md](notes/02-wine-usbmon-ghidra.md) — installer unpack, firmware-load capture (2988 pkts), fmacfw RISC-V analysis (100+ functions) |
| 3 — lmacfw / decode / compare | [notes/03-lmacfw-usbmon-compare.md](notes/03-lmacfw-usbmon-compare.md) — RF calibration CLI, bulk payload decode, Windows↔Linux driver compare |
| 4 — Windows Ghidra | [notes/04-windows-ghidra.md](notes/04-windows-ghidra.md) — NDIS driver source path/build, KMDF loader sample origin, usbmon stream deep dive |
| 5 — Full decompile / cross-ref | [notes/05-full-decompile-crossref.md](notes/05-full-decompile-crossref.md) — REA PE imports (imphashes), 1,227 + 161 decompiled functions, Linux↔firmware architecture, lmacfw load path |

Supporting docs:

- [docs/firmware-format.md](docs/firmware-format.md) — WFFW container structure
- [docs/usb-protocol.md](docs/usb-protocol.md) — host→device bulk transfer format

Analysis scripts:

- [ghidra_scripts/AnalyzeFirmware.java](ghidra_scripts/AnalyzeFirmware.java) — function inventory + decompile + string refs
- [ghidra_scripts/FullDecompile.java](ghidra_scripts/FullDecompile.java) — full decompile export

## Targets (gitignored — hashes only)

| File | Size | SHA-256 |
|---|---|---|
| `targets/Wifi6_install.exe` | 3,640,241 | `82d338c49f8fa0f8f76df57c8bbddcf25179aaa17b63e85d13ae28a144752465` |
| `targets/fmacfw_8800d80_u02.bin` | 358,072 | `23f2bed2ac0e8f7bda8f36df7defd30d9b928c97867f6f0f01f28d89dd78d670` |
| `targets/lmacfw_rf_8800d80_u02.bin` | 278,000 | `5abae35d6718d031f93ae8287d008b6b9ee9504c47dd212239907e30c006bba8` |
| `targets/aic8800_fdrv.ko` | 24,938,080 | `8ac9ec89540a3d4e3d2ef90672caa384df7728f2b2349d5a3a9eda6a3669a550` |
| `targets/aic_load_fw.ko` | 3,930,128 | `36097f3a853459dcd6234d98e75b03df34827d4660fd4c41ca7a1d662635da72` |
| `targets/aic_zlp_quirk.ko` | 368,000 | `cef1e8874ea9107975c3a5bb9d3d1ed73ce12b108ecb2f3ccb10956069c6e2d5` |
| `targets/aicloadfw.sys` | 1,095,832 | `5d3bfb5a87626f14c3f1cb2a4e70ec5872030740bc2223b54b649e0fb07fa62d` |
| `targets/aicusbwifi.sys` | 1,097,904 | `4c9da7bf2235c1d5e965f2b7c7ad56455053102a8854c2bbbf8bc8561907a65a` |
| `targets/aicloadfw.inf` | 5,0K | `2d6ff86b64f8fdbd49b572e30131d5f6e09798f04f9077b03777d16d895bc8a3` |
| `targets/aicusbwifi.inf` | 8.8K | `bafb523b618fa3c2166ac000b6c3b7a2c68c24e5e1a34cf1b8ac80a31469cbdb` |

Do not redistribute original binaries. This repo records structure,
hashes, and analysis only.

## Layout

```
├── README.md                    # This file
├── LICENSE                      # MIT
├── docs/
│   ├── firmware-format.md       # WFFW container structure
│   └── usb-protocol.md          # Bulk transfer command format
├── notes/                       # Per-pass findings (01–05)
├── ghidra_scripts/              # Ghidra headless analysis scripts
└── targets/                     # Analysis targets (gitignored)
```

## Toolchain

- REA (artifact-graph + .NET static providers) — PE imports/resources/certificates, kernel module metadata
- Ghidra 12.1.4 (`/opt/ghidra_12.1.4_PUBLIC`) — RISC-V 32-bit LE + x86 32-bit decompilation
- Wine 10.0 — InstallShield unpack
- tshark 4.4.19 — usbmon capture + analysis
