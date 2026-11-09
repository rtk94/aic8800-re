# First pass — inventory and static RE (2026-11-08)

## Device under test

- AICSemi AIC8800D80 USB Wi-Fi 6 + BT dongle, USB `a69c:8d81` (also seen as
  `368b:8d81`), serial `20220103`, high-speed 480M, bus-powered 500mA.
- 3 interfaces: BT (0,1), vendor (2). BT bound to `btusb`, vendor to
  `aic8800_fdrv`.
- Bundled Windows installer flash disk: USB `1111:1111` Pandora FLASH,
  label `WiF6-driver`, `/dev/sdd1` VFAT 7.8MB containing `Wifi6_install.exe`
  (3.6MB) + `Autorun.inf`. Mounted read-only at `/tmp/wifi6` during analysis;
  do not use the upstream `1111:1111` udev mode-switch rule on it — that rule
  sends SCSI commands to any `1111:1111` device and disables this disk.

## Targets (in `targets/`, gitignored; hashes in README/detector below)

| File | Size | SHA-256 |
|---|---|---|
| `Wifi6_install.exe` | 3,640,241 | `82d338c49f8fa0f8f76df57c8bbddcf25179aaa17b63e85d13ae28a144752465` |
| `fmacfw_8800d80_u02.bin` | 358,072 | `23f2bed2ac0e8f7bda8f36df7defd30d9b928c97867f6f0f01f28d89dd78d670` |
| `lmacfw_rf_8800d80_u02.bin` | 278,000 | `5abae35d6718d031f93ae8287d008b6b9ee9504c47dd212239907e30c006bba8` |
| `aic8800_fdrv.ko` | 24,938,080 | `8ac9ec89540a3d4e3d2ef90672caa384df7728f2b2349d5a3a9eda6a3669a550` |
| `aic_load_fw.ko` | 3,930,128 | `36097f3a853459dcd6234d98e75b03df34827d4660fd4c41ca7a1d662635da72` |
| `aic_zlp_quirk.ko` | 368,000 | `cef1e8874ea9107975c3a5bb9d3d1ed73ce12b108ecb2f3ccb10956069c6e2d5` |

Kernel modules were built from `~/audit-p5/aic8800d80` against
`6.12.115+deb13.1-amd64` headers (full stack: `drivers/aic8800` top Makefile;
building `aic8800_fdrv` alone fails at modpost — symbols come from
`aic_load_fw`).

## REA evidence

- `open_binary` on `Wifi6_install.exe` → PE x86 (validated only).
- `inspect_pe_imports` (ev `ev_430384c48065831709b6752babf7ff37e783a618259f1a55b55ea9ac31a26e3f`):
  PE32, 146 imports from kernel32/user32/comctl32/oleaut32/advapi32 only —
  stock Windows, no custom DLLs, no direct `DeviceIoControl` import.
  imphash `40ab50289f7ef5fae60801f88d4541fc`.
- `inspect_pe_resources` (ev `ev_65c52014b3cfd5225c80752f12ca96e1ec6c4515a3cbc164c855da3f5720cc9b`):
  InstallShield layout — RCDATA `DVCLAL` + `PACKAGEINFO` (784B), string table
  4086–4096, icon, version. This is an InstallShield setup stub.
- `inspect_pe_certificates` (ev `ev_5d1de8c109b2cb002f40f2c93fdb11c1868ac2470a3260211f49e5a41e7078d4`):
  `IMAGE_DIRECTORY_ENTRY_SECURITY` absent — no Authenticode signature in the
  PE. (Not proof of absence in catalog/overlay sense.)
- `inspect_artifact` (ev `ev_52992f213401cbd57a1105c1d3777fe17d6e9d69b1e1f42810425a0ed5cd7880`):
  single-node graph, root bytes only.
- `extract_artifact` on the PE → unsupported (no PE extraction reader).
- `inspect_firmware_regions` → unavailable: needs `REA_BINWALK_COMMAND` on the
  server; binwalk not installed.
- `inspect_kernel_module` fdrv (ev `ev_bc923b80e8f5d8b47cb90ec2073b813812618d0bd9d69c120c91b7da7299a948`)
  and load_fw (ev `ev_e83fabc8b8d4fb81ab7b723684b9f00f99919c34ab92bec63ffd8a92c0f3c2e6`):
  .modinfo author "Copyright(c) 2015-2017 RivieraWaves RivieraWaves S.A.S",
  version 6.4.3.0, "RivieraWaves 11nac driver for Linux cfg80211"; fdrv declares
  90+ `firmware=` entries spanning all chip variants (aic8800, aic8800D80,
  D80N, D80X2, DC, DLN).

### REA session limitation

The connected REA server exposes only `rea-artifact-graph` (inspect/extract
artifact) + `rea-dotnet-static` providers — no Ghidra native provider and no
binwalk provider. Deep disassembly of the firmware or the installer code is
therefore **not** available through REA in this session. Firmware notes below
are from direct hex/strings analysis, not REA Evidence.

## Windows installer (`Wifi6_install.exe`)

- PE sections end at 0xc3400; **2,840,497-byte overlay** follows, head bytes
  `7a6c621a 5d00 0080 …` — the InstallShield compressed data stream.
- `unshield` (installed during this pass) rejects it: "Failed to open as an
  InstallShield Cabinet File" — InstallShield 2015+ stream, not a legacy
  cabinet. No embedded .sys/.bin/.inf recovered statically.
- Extraction route (not yet run): run under Wine (`WINEPREFIX` scratch) with a
  `Windows` desktop, or capture the installer's USB/driver activity. Treat
  the image as untrusted — it is unsigned.

## Firmware (`fmacfw_8800d80_u02.bin`, 358,072 B)

- Header: ASCII magic `WFFW` at offset 0x20 (also in `lmacfw_rf`), preceded by
  a short section/offset table whose entries look like load addresses in the
  `0x0013xxxx` range. First 8 bytes differ between fmacfw and lmacfw
  (sizes/types).
- Bare-metal RTOS image: strings show `wifimain!` entry task, `Dummy_Handler`,
  `_start_stack`, `ptr_bss`, `lmacsh`, `hosttype=%d, asic_ver=0x%x`,
  `dfs on/off %d`, `Init vcore Volt: %dmV`, `aic>` shell.
- RivieraWaves SDK task layer: `ke_task_local`, `ke_state_get(TASK_*)`,
  `KE_BUILD_ID`, task set `TASK_SM` (station mgmt), `TASK_MM` (MAC mgmt),
  `TASK_SCAN`, `TASK_APM` (AP mode), `TASK_BAM`. State machines visible as
  strings: `SM_JOINING`, `SM_DISCONNECTING`, `SM_FT_OVER_AIR`,
  `SCAN_WAIT_BEACON_PROBE_RSP`, `APM_BCN_SETTING`, `BAM_DELETE`.
- String `assoc req: 8800d40 vht ie` and `8800d40 ht vht param` — firmware
  handles the 8800d40 variant internally (VHT IE construction), even though
  the host driver reports D80.
- No build-date/version string recovered by `strings` in this pass.

## Next probes (not run)

1. Wine-run `Wifi6_install.exe` in a scratch prefix to unpack the InstallShield
   stream; inventory the resulting .sys/.inf/.bin set and hash-compare its
   firmware against the Linux-repo blobs.
2. `open_binary` with `format=raw-binary` on the firmware for a RISC-V
   disassembly attempt (needs a native provider in the REA session —
   currently absent; use Ghidra directly, 12.1.4 at `/opt/ghidra_12.1.4_PUBLIC`).
3. usbmon capture of the vendor-interface (If2) firmware-download sequence
   when `aic_load_fw` probes; filter to the dongle before publishing
   (raw bus captures contain every device).
