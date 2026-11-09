# Third pass — lmacfw RF RE, usbmon payload decode, Windows/Linux driver compare (2026-11-08)

## Ghidra `lmacfw_rf_8800d80_u02.bin`

- Same RISC-V 32-bit LE / RivieraWaves stack, but RF-focused — has a CLI
  interface for calibration (visible as strings, not a full interactive shell
  in static analysis):
  - `setbfd`, `setsdg`, `setbc`, `setsr` — RF parameter setters
  - `setapc pos1 (pos2) value` — APC (Automatic Power Control) position/value
  - `wr efuse: [%d]=%08X` / `rd efuse:` — eFuse read/write
  - `unset papr` / `set papr` — PAPR (Peak-to-Average Power Ratio)
  - `gpioa%d output %d` / `gpiob%d output %d` — GPIO control
  - `set vid 0x%x, pid 0x%x` / `get vid 0x%x, pid 0x%x` — USB VID/PID flash config
  - `no usb info in flash, use setusb to set`
  - `setcc countrycode` / `wrong len of countrycode %d` — country code
  - `get vid 0x%x, did 0x%x, subsys_vid 0x%x, subsys_id 0x%x, rev_id 0x%x` — PCIe info
  - `cob dut start`, `cob state -> %d`, `2@cob golden start` — COB (Chip-On-Board) test
  - `notch%d on @%d,%d,%d`, `2@notch off` — notch filter
  - `srrc on @%d,%d,%d` — SRRC (radio regulatory) test
  - `fss on` / `fss off` — FSS (Frequency Synthesis Setting?)
  - `adjust xtal_cap: tgt=0x%x, cur=0x%x` — crystal capacitor tuning
  - `temp_comp: init=%d, en=%d, lvl_cal=%d, t_last=%d C, t_real=%d C` — temp compensation
  - `xtal_cap: cal=0x%x, tgt=0x%x, cur=0x%x`
  - `ofst2x: 2G4=%d,%d,%d; 5G=l(%d,%d,%d),h(%d,%d,%d),m(%d,%d,%d)` — 2.4G/5G offset calibration
  - `settings: en=%d, tmr=%d, act=%d`
  - `temp_lvl_calibed=%d`
- **RSSI string**: `RSSI : %d` (calibration readout)

## usbmon payload decode (`firmware-load-filtered.pcap`)

- Bulk OUT (device 19, EP 0x01): 560 packets, 423,000 bytes total
- Structure per packet (1048 bytes):
  - Bytes 0-7: `14041100 00000000` (command magic + flags)
  - Bytes 8-11: `0b040100` (command ID)
  - Bytes 12-15: address (e.g. `64000804`)
  - Bytes 16-19: length (e.g. `40192000` = 6464)
  - Bytes 20+: firmware data
- First packet: 20-byte header `1000110000000000000401006400040000005040` — init command
- **Verified**: `fmacfw_8800d80_u02.bin` (from WFFW offset) found in stream at
  offset 55816 (after init + patch uploads). Stream is 423 KB = fmacfw (358 KB)
  + lmacfw + patch tables + ADID bins.
- `lmacfw_rf_8800d80_u02.bin` NOT found in stream — may be sent via different
  device address or with a different command wrapper.

## Windows vs Linux driver comparison

### Windows `aicloadfw.sys` (1.1 MB, PE32 native)

- KMDF (WDF) driver — strings reveal:
  - Source: `E:\code\8820\WifiDriverWindows\aicloadfw\sys\device.c`
  - `bin upload : %x, i:%d` / `bin upload 2: %x, i:%d` / `bin upload fail: %x, err:%d`
  - `addr_adid 0x%x, addr_patch 0x%x`
  - `BulkOutput Pipe is 0x%p` / `BulkInput Pipe is 0x%p` / `Interrupt Pipe is 0x%p`
  - `rwnx_plat_bt_load_adid` / `bt adid bin upload : %x, i:%d`
  - `rwnx_plat_bt_load_patch` / `fw_patch_table_upload`
  - `aic_load_fw error , head is null`
  - `WdfUsbTargetDeviceCreateUrb failed`

### Windows `aicusbwifi.sys` (1.1 MB, PE32 native)

- NDIS 6 driver — similar structure:
  - `bin upload : %x, i:%d` / `bin upload 2: %x, i:%d` / `bin upload fail: %x, err:%d`
  - `lpdc upload fail: %x, err:%d` (LPDC = Low Power DC?)
  - `rwnx_patch_table_load` / `rwnx_plat_patch_load_8800dc`
  - `patch load [%x] = %x`
  - `rwnx_calib_load_8800dc` / `fmacfw_calib_load_8800dc err %d`
  - `Firmware Version: %s`
  - `rxl_payload_transfer_usb` / `rxl_payload_transfer_sdio`
  - ARP offload: `rwnx_send_arpoffload_en_req`

### Comparison

| Aspect | Windows | Linux |
|---|---|---|
| Framework | KMDF + NDIS 6 | cfg80211 / mac80211 |
| Firmware load | `aicloadfw.sys` (separate) | `aic_load_fw.ko` (separate) |
| Main driver | `aicusbwifi.sys` (NDIS) | `aic8800_fdrv.ko` (cfg80211) |
| Bin upload API | `bin upload : %x, i:%d` | similar in `aic_load_fw` |
| Patch load | `rwnx_patch_table_load` | same name in Linux source |
| Calib load | `rwnx_calib_load_8800dc` | same name |
| Bulk pipe | `BulkOutput Pipe` | `aicwf_usb.c` |

**Key finding**: Windows and Linux drivers share the same `rwnx_*` function naming
(RivieraWaves SDK), confirming a common upstream driver codebase. The firmware
load protocol (bulk OUT with 20-byte command headers + 1028-byte data chunks)
is identical in structure.

## Files

- `targets/aicloadfw.sys`, `targets/aicusbwifi.sys` — Windows drivers (gitignored)
- `targets/aicloadfw.inf`, `targets/aicusbwifi.inf`, `targets/*.cat` — INFs + catalogs
- `firmware-load.pcap` / `firmware-load-filtered.pcap` — usbmon capture (gitignored)
- `ghidra_scripts/AnalyzeFirmware.java` — Ghidra analysis script
