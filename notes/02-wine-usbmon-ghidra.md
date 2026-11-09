# Second pass — Windows installer unpack, usbmon firmware-load capture, Ghidra firmware RE (2026-11-08)

## Windows installer unpack

- Ran `Wifi6_install.exe` in Wine (win32 prefix) → extracted to
  `~/aic8800-re/wine-prefix/drive_c/Program Files/Wifi6 802.11ax USB Adapter/`
- Driver files (win10_x86):
  - `aicloadfw.sys` (1.1 MB) — firmware loader, SHA256 `5d3bfb5a87626f14c3f1cb2a4e70ec5872030740bc2223b54b649e0fb07fa62d`
  - `aicusbwifi.sys` (1.1 MB) — main NDIS Wi-Fi driver, SHA256 `4c9da7bf2235c1d5e965f2b7c7ad56455053102a8854c2bbbf8bc8561907a65a`
  - `aicloadfw.inf` / `aicusbwifi.inf` — INF files with USB IDs
  - `.cat` files — WHQL catalog signatures

### INF file key data (`aicusbwifi.inf`)

- Driver version: `6.40.32.216` dated `08/31/2024`
- Provider: `AIC` (display name `iGrentech`)
- Supported USB IDs (partial):
  - `USB\VID_A69C&PID_8d81&MI_02` (our device)
  - `USB\VID_368b&PID_8d81&MI_02`
  - `USB\VID_2357&PID_014E` (TP-Link)
  - `USB\VID_2357&PID_014B` (Mercury)
  - `USB\VID_2357&PID_014F` (FAST)
  - `USB\VID_2604&PID_001F` / `0020` (Tenda)
  - `USB\VID_A69C&PID_88DC/DD/DE` (88DC variants)
  - `USB\VID_368B&PID_88DF`
  - `USB\VID_2604&PID_0013/0014`
  - `USB\VID_2357&PID_0147`
- OtaKey: `da681918c11078801e432552b70bd4a95fad9b6d` (OTA update key)

## usbmon firmware-load capture

- Captured on `usbmon5` (bus 5, device re-enumerated as addresses 18→19→20)
- File: `firmware-load.pcap` (2988 packets, 709 KB, 23.3 s)
- Filtered to device only: `firmware-load-filtered.pcap` (2848 packets, 695 KB)
- Three enumeration phases visible:
  1. Device 18: initial descriptor fetch (GET DESCRIPTOR DEVICE/CONFIG)
  2. Device 19: bulk OUT on EP 0x01 (1048-byte chunks), bulk IN on EP 0x82 (3712-byte responses) — firmware download
  3. Device 20: bulk IN on EP 0x81 (20 KB transfers) — main firmware binary transfer
- Key observation: firmware sent via vendor-specific bulk OUT EP 0x01 (interface 2), responses on EP 0x82; main payload comes back on EP 0x81 (20 KB × ~30 transfers = ~600 KB total, matching firmware size)

## Ghidra firmware analysis (`fmacfw_8800d80_u02.bin`)

- Raw binary imported as RISC-V 32-bit LE (RivieraWaves toolchain)
- Auto-analysis: 100+ functions identified
- Build string: **`la Dec 05 2025 19:45:42 - g586bc1e8`** (build date + git commit)
- Key function categories:
  - **Scan/Join**: `scanu_start`, `scanu_build_ie`, `scanu_confirm`, `scanu_join_req_handler`, `join:%s,%d,bw=%d`
  - **Rate control**: `rc_init`, `rc_check`, `rc_update_counters`, `rc_update_bw_nss_max`, `rc_check_rate_config`
  - **Block Ack**: `mm_ba_add_cfm_handler`, `bam_send_air_action_frame`, `bam_send_mm_ba_del_req`
  - **RX/TX control**: `rxu_cntrl_*` (prepare, mic_check, defrag_alloc, reord_fwd, reord_check, spurious_check), `txu_cntrl_*` (sechdr_len_compute, umacdesc_mgmt_prep, sec_hdr_append, push)
  - **TWT**: `twt_save_ind_req_type`, `twt_handle_setup_frame`, `twt_handle_action_frame`
  - **Rate adaptation**: `rc_ss->rate_map` HT/VHT/HE MCS map handling, BW/NSS/preamble/SGI logic
  - **RM (Radio Measurement)**: `rm_process_next_req_handler`, `rm_parse_beacon_request`, `rm_add_bcn_report`
- Strings reveal RivieraWaves task layer: `TASK_SM`, `TASK_MM`, `TASK_SCAN`, `TASK_APM`, `TASK_BAM`, state machines `SM_JOINING`, `SCAN_WAIT_BEACON_PROBE_RSP`, `APM_BCN_SETTING`

## Next steps (not yet done)

1. **Ghidra on `lmacfw_rf_8800d80_u02.bin`** — lower MAC / RF firmware, likely also RISC-V
2. **Compare Windows `aicloadfw.sys` vs Linux `aic_load_fw.ko`** — firmware load protocol
3. **Decode usbmon bulk payload** — extract actual firmware chunks from capture, verify against `fmacfw_8800d80_u02.bin`
4. **Analyze `aicusbwifi.sys`** — NDIS driver internals (Ghidra PE analysis)