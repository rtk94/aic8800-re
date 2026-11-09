# Fourth pass — Windows driver Ghidra RE, usbmon stream analysis (2026-11-08)

## Ghidra `aicusbwifi.sys` (NDIS 6 miniport driver, x86 32-bit)

- **Source path**: `E:\code\8820\windows_driver_8820\WifiDriverWindows\native\myusbwifi\Mp_main.c`
- **Build**: `AIC USB WiFi Driver built on Aug 31 2024 at 18:54:18`
- **Git**: `2024-08-31 18:46:24 +0800 f7c1be8`
- NDIS miniport structure visible in strings:
  - `DriverEntry` → `NdisMRegisterMiniportDriver`
  - `MPHalt` — miniport halt with pending sends/receives checks
  - `DriverUnload`
  - `WdfDriverCreate failed`
  - `#1 Port[%d]=%p`, `#2 Port[%d]=%p, type %d`
  - `Waiting 2 more seconds for all Miniport Ref Count to go to zero`
  - `MPHalt: This is probably an issue with the miniport driver.`
- `NDIS Version %d.%d` — version negotiation string

## Ghidra `aicloadfw.sys` (KMDF firmware loader, x86 32-bit)

- **Framework**: Forked from Microsoft's **OSRUSBFX2 driver sample** (strings:
  `OSRUSBFX2 Driver Sample - Driver Framework Edition.`,
  `===== Driver Sample - Driver Framework Edition.`)
- **Build**: `Aug 24 2024`, `17:21:17`
- Key WDF/USB APIs:
  - `WdfUsbTargetDeviceCreateWithParameters`
  - `SelectInterfaces failed 0x%x`
  - `OsrFxEvtDeviceAdd` / `EvtDevicePrepareHardware`
  - `WdfDeviceCreate failed`
- This is a **sample-derived loader**, not a from-scratch KMDF driver — the
  `bin upload` logic is layered on top of the OSR FX2 scaffolding.

## usbmon stream analysis (deep dive)

- Bulk OUT total: 423,000 bytes across 560 packets (device 19, EP 0x01)
- **fmacfw found in stream**: starting bytes `001c1a00ad0112002d951300...`
  (fmacfw file header, before WFFW at file offset 32) at stream offset ~55816
  (after ~55 KB of init/patch/ADID uploads)
- fmacfw matches for 992 bytes then diverges — the stream interleaves
  firmware segments with per-packet 20-byte command headers, so a raw
  `find()` only matches the first contiguous chunk.
- **lmacfw NOT found** in bulk OUT stream. Possible causes:
  1. Loaded via a different device address (device re-enumerated 18→19→20;
     lmacfw may go to a different endpoint or during a different phase)
  2. Sent on device 20 (the 20 KB IN transfers on EP 0x81 are likely the
     main firmware readback or a different transfer)
  3. Compressed or transformed before transfer

## Repo status

- 4 RE passes completed: inventory, Wine/USB/Ghidra, RF/usbmon/decode, Windows Ghidra
- All findings in `notes/01`–`notes/04`
- Remaining open items (if desired):
  1. Full decompile of `aicusbwifi.sys` function bodies (not just string inventory)
  2. `open_binary` on `aicloadfw.sys` for import analysis
  3. Cross-reference Linux `rwnx_*` source with firmware `ke_task` handlers
  4. Trace lmacfw load path (device 20 EP 0x81 transfers)
