# Fifth pass — full decompiles, PE import analysis, cross-ref, lmacfw trace (2026-11-08)

## REA PE import analysis

### `aicloadfw.sys` (1,095,832 bytes, PE32 native)

- Evidence: `ev_388911013e18fd1538250e80acff80993a006f3b871a80cb169487e6c7201bb5`
- Imports: **3 DLLs, 27 functions** — minimal WDF loader
  - `ntoskrnl.exe` (22 functions): `RtlAssert`, `RtlInitUnicodeString`, `MmGetSystemRoutineAddress`, `RtlGetVersion`, `RtlCompareMemory`, `IoWMIRegistrationControl`, `memset`, `KeDelayExecutionThread`, `_allmul`, `memcpy`, `memcmp`, `MmFreeNonCachedMemory`, `MmAllocateNonCachedMemory`, `ExFreePoolWithTag`, `KeWaitForSingleObject`, `RtlCopyUnicodeString`, `DbgPrintEx`, `RtlAnsiCharToUnicodeChar`, `KeReleaseSemaphore`, `KeInitializeSemaphore`, `ExAllocatePoolWithTag`, `DbgPrint`
  - `HAL.dll` (1 function): `KeGetCurrentIrql`
  - `WDFLDR.SYS` (4 functions): `WdfVersionBind`, `WdfVersionUnbind`, `WdfVersionBindClass`, `WdfVersionUnbindClass`
- **imphash**: `0618d46112d5ec7a2865d1540935048b`
- Resources: **empty** (parsed, not used)

### `aicusbwifi.sys` (1,097,904 bytes, PE32 native)

- Evidence: `ev_9731ce44f1dfe751a0af8b4095bb9bbcc3314f035ed5383e4159f325053f6e92`
- Imports: **4 DLLs, 91 functions**
  - `NDIS.SYS` (49 functions): `NdisFreeTimerObject`, `NdisMIndicateStatusEx`, `NdisMSleep`, `NdisSetTimerObject`, `NdisCancelTimerObject`, `NdisSetEvent`, `NdisResetEvent`, `NdisQueueIoWorkItem`, `NdisReadConfiguration`, `NdisMSendNetBufferListsComplete`, `NdisReadNetworkAddress`, `NdisWriteErrorLogEntry`, `NdisGetVersion`, `NdisAllocateIoWorkItem`, `NdisFreeIoWorkItem`, `NdisWriteConfiguration`, `NdisCloseConfiguration`, `NdisOpenConfigurationEx`, `NdisAdvanceNetBufferDataStart`, `NdisFreeMdl`, `NdisRegisterDeviceEx`, `NdisDeregisterDeviceEx`, `NdisAllocateTimerObject`, `NdisFreeMemory`, `NdisAllocateMemoryWithTagPriority`, `NdisMSetMiniportAttributes`, `NdisMRemoveMiniport`, `NdisMGetDeviceProperty`, `NdisMRegisterMiniportDriver`, `NdisMDeregisterMiniportDriver`, `NdisMResetComplete`, `NdisMOidRequestComplete`, `NdisMNetPnPEvent`, `NdisMAllocatePort`, `NdisAllocateNetBufferPool`, `NdisFreeNetBufferPool`, `NdisAllocateNetBuffer`, `NdisFreeNetBuffer`, `NdisAllocateNetBufferListPool`, `NdisFreeNetBufferListPool`, `NdisAllocateNetBufferList`, `NdisFreeNetBufferList`, `NdisMIndicateReceiveNetBufferLists`, `NdisMFreePort`, `NdisWaitEvent`, `NdisInitializeEvent`, `NdisReleaseReadWriteLock`, `NdisAcquireReadWriteLock`, `NdisGetDeviceReservedExtension`, `NdisInitializeReadWriteLock`
  - `ntoskrnl.exe` (33 functions): `KeWaitForSingleObject`, `MmMapLockedPagesSpecifyCache`, `ExInitializeNPagedLookasideList`, `ExDeleteNPagedLookasideList`, `ExFreePoolWithTag`, `ExAllocatePoolWithTag`, `InterlockedPopEntrySList`, `InterlockedPushEntrySList`, `KeInitializeSemaphore`, `KeReleaseSemaphore`, `KeInitializeEvent`, `KeReleaseMutex`, `MmBuildMdlForNonPagedPool`, `KeInitializeSpinLock`, `MmSizeOfMdl`, `IofCompleteRequest`, `IoGetDeviceProperty`, `KeFlushIoBuffers`, `KeTickCount`, `RtlUnwind`, `RtlAnsiCharToUnicodeChar`, `RtlCopyUnicodeString`, `KeInitializeMutex`, `DbgPrintEx`, `KefReleaseSpinLockFromDpcLevel`, `KeSetEvent`, `KefAcquireSpinLockAtDpcLevel`, `RtlCompareMemory`, `KeFlushQueuedDpcs`, `DbgPrint`, `RtlAssert`, `MmUnmapLockedPages`, `KeQuerySystemTime`
  - `WDFLDR.SYS` (4 functions): version bind/unbind
  - `HAL.DLL` (4 functions): `KfReleaseSpinLock`, `KeStallExecutionProcessor`, `KeGetCurrentIrql`, `KfAcquireSpinLock`
- **imphash**: `cdb88a28d77d9a4a5b58d7eb2bf47f6b`

### Certificates

- `aicloadfw.sys`: `inspect_pe_certificates` failed — "PKCS#7 signedData is malformed: ASN.1 nesting exceeds 32 levels." The .cat file is the authenticode catalog; the .sys itself has a malformed/oversized PKCS#7.

## Full Ghidra decompilations

- `aicusbwifi.sys`: **1,227 functions** decompiled → `/tmp/aicusbwifi_decompile.txt` (2.2 MB)
- `aicloadfw.sys`: **161 functions** decompiled → `/tmp/aicloadfw_decompile.txt` (115 KB)
- Decompilations are local only (gitignored) — not committed to repo

## Linux ↔ Firmware cross-reference

| Firmware string | Linux driver match | Notes |
|---|---|---|
| `wifimain!` | **None** | Firmware-side entry task, no Linux equivalent |
| `ke_task_local`, `ke_state_get` | **None** | RivieraWaves firmware RTOS API — host driver uses `rwnx_*` API instead |
| `TASK_SM/MM/SCAN/APM` | `rwnx_main.o`, `rwnx_strs.c` | Task enum values shared between host and firmware |
| `rc_init`, `rc_check` | **None** | Rate control is firmware-internal |
| `scanu_start`, `scanu_build_ie` | `rwnx_msg_rx.c`, `rwnx_msg_tx.c` | Scan control messages |
| `bam_send_*`, `twt_handle_*` | **None** | BA and TWT are firmware-internal |
| `rxu_cntrl_*`, `txu_cntrl_*` | **None** | RX/TX control is firmware-internal |

**Architecture**: The Linux driver is **host-side only** — it sends
`*_req`/`*_cfm` messages to the firmware via `rwnx_msg_tx/rx`. The firmware
implements the full MAC state machines (scan, join, rate control, BA, TWT)
internally. The `TASK_*` enums are the shared vocabulary between host and
firmware.

## lmacfw load path (usbmon)

- Device 20 bulk packets: **166 total**
  - EP 0x02 (OUT): 22 packets (commands)
  - EP 0x81 (IN): 20 packets × 20 KB = **~400 KB data** — consistent with
    lmacfw (278 KB) + headers/patches
  - EP 0x82 (IN): 122 packets (responses)
  - EP 0x84 (IN): 2 packets (control)
- The 20 KB IN transfers on EP 0x81 are the lmacfw being **read back or
  verified**, not written — the actual lmacfw write likely happened on
  device 19 (which we already traced: 423 KB bulk OUT where fmacfw was found
  but lmacfw was not). Device 20 sees the device in a post-load state.
- **Conclusion**: lmacfw is loaded during the device 19 phase but in a form
  not directly matching the .bin file (compressed, chunked with different
  framing, or loaded via a separate command set). Full extraction would
  require protocol-level reconstruction from the bulk OUT command stream.

## DELIVERABLES

- REA Evidence IDs: `ev_388911013e18fd1538250e80acff80993a006f3b871a80cb169487e6c7201bb5` (aicloadfw imports), `ev_9731ce44f1dfe751a0af8b4095bb9bbcc3314f035ed5383e4159f325053f6e92` (aicusbwifi imports)
- Ghidra decompilations: `/tmp/aicusbwifi_decompile.txt` (2.2 MB, 1227 funcs), `/tmp/aicloadfw_decompile.txt` (115 KB, 161 funcs) — local only
- `ghidra_scripts/FullDecompile.java` — reusable script for future runs
