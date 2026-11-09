# AIC8800 firmware — analysis summary

## Container: WFFW

Both `fmacfw_8800d80_u02.bin` and `lmacfw_rf_8800d80_u02.bin` share the same
container: a small header with ASCII magic **`WFFW`** at offset 0x20.

### Header layout

```
Offset  Size  Description
0x00    8     Sizes/types (differ per image)
0x08    ~0x18  Address table (0x0013xxxx range — load addresses)
0x20    4     "WFFW" magic
0x28    …     Further header words (05 02 12 00 repeats)
```

The first 8 bytes differ between fmacfw and lmacfw:

```
fmacfw:  00 1c 1a 00 ad 01 12 00
lmacfw:  00 00 1a 00 ad 01 12 00
```

The code/data payload follows the header.

### Not yet established

- Full section layout (needs binwalk / `REA_BINWALK_COMMAND`)
- Entry point (Ghidra raw-binary assumes 0; actual entry unknown)
- Compression/encryption status of individual sections
- Relationship between the header address table and the flashed segments

## RTOS: RivieraWaves `ke_task` layer

Strings in both blobs reveal a bare-metal RTOS built on RivieraWaves' task
framework:

- `ke_task_local`, `ke_state_get(TASK_*)`, `KE_BUILD_ID`, `ke_task_schedule`,
  `ke_task_handler_get`
- Task set: `TASK_SM` (station management), `TASK_MM` (MAC management),
  `TASK_SCAN`, `TASK_APM` (AP mode), `TASK_BAM` (Block Ack management)
- State machines visible as strings:
  `SM_JOINING`, `SM_DISCONNECTING`, `SM_FT_OVER_AIR`,
  `SCAN_WAIT_BEACON_PROBE_RSP`, `SCAN_WAIT_CHANNEL`,
  `APM_BCN_SETTING`, `APM_BSS_PARAM_SETTING`, `BAM_DELETE`
- Entry: `wifimain!` (task name), `Dummy_Handler`, `_start_stack`, `ptr_bss`
- Boot: `hosttype=%d, asic_ver=0x%x` (ASI C version probe)
- Shell: `aic>` (serial debug shell)
- Clocks: `dfs on/off %d`, `Init vcore Volt: %dmV, reg=0x%x`

## fmacfw (MAC firmware) — Ghidra

- **CPU**: RISC-V 32-bit LE (Ghidra `RISCV:LE:32:default`)
- **Build**: `la Dec 05 2025 19:45:42 - g586bc1e8`
- **Functions**: 100+ identified by Ghidra auto-analysis
- Categories:
  - Scan/join: `scanu_start`, `scanu_build_ie`, `scanu_confirm`,
    `scanu_join_req_handler`, `join:%s,%d,bw=%d`
  - Rate control: `rc_init`, `rc_check`, `rc_update_counters`,
    `rc_update_bw_nss_max`, `rc_check_rate_config`
  - Block Ack: `mm_ba_add_cfm_handler`, `bam_send_air_action_frame`,
    `bam_send_mm_ba_del_req`
  - RX/TX: `rxu_cntrl_*` (prepare, mic_check, defrag_alloc, reord_*),
    `txu_cntrl_*` (sechdr_len_compute, umacdesc_mgmt_prep, sec_hdr_append)
  - TWT: `twt_save_ind_req_type`, `twt_handle_setup_frame`,
    `twt_handle_action_frame`
  - Radio Measurement: `rm_process_next_req_handler`,
    `rm_parse_beacon_request`, `rm_add_bcn_report`
  - 802.11ac/ax specifics: `assoc req: 8800d40 vht ie`,
    `8800d40 ht vht param`, MCS/BW/NSS/PREAMBLE/SGI maps

## lmacfw (RF firmware) — Ghidra

- **CPU**: RISC-V 32-bit LE (same toolchain)
- **Role**: RF calibration and factory test. Exposes a CLI over the
  firmware (strings, not a full interactive shell in static analysis):
  - `setbfd`, `setsdg`, `setbc`, `setsr` — RF parameters
  - `setapc pos1 (pos2) value` — automatic power control
  - `wr efuse: [%d]=%08X` / `rd efuse:` — eFuse access
  - `set papr` / `unset papr` — peak-to-average power ratio
  - `gpioa%d output %d` / `gpiob%d output %d` — GPIO
  - `set vid 0x%x, pid 0x%x` — USB VID/PID flash
  - `no usb info in flash, use setusb to set`
  - `setcc countrycode` — country code
  - `get vid 0x%x, did 0x%x, subsys_vid 0x%x, subsys_id 0x%x` — PCIe info
  - `cob dut start`, `cob state -> %d`, `2@cob golden start` — COB test
  - `notch%d on @%d,%d,%d` — notch filter
  - `srrc on @%d,%d,%d` — SRRC regulatory test
  - `fss on` / `fss off` — frequency synthesis ?
  - `adjust xtal_cap: tgt=0x%x, cur=0x%x` — crystal cap tuning
  - `temp_comp: init=%d, en=%d, lvl_cal=%d, t_last=%d C, t_real=%d C`
  - `xtal_cap: cal=0x%x, tgt=0x%x, cur=0x%x`
  - `ofst2x: 2G4=%d,%d,%d; 5G=l(%d,%d,%d),h(%d,%d,%d),m(%d,%d,%d)`
  - `settings: en=%d, tmr=%d, act=%d`
  - `temp_lvl_calibed=%d`
  - `RSSI : %d` — calibration readout

## Linux ↔ firmware vocabulary

| Firmware (ke_task) | Linux (rwnx) | Side |
|---|---|---|
| `ke_task_local`, `ke_state_get` | — | Firmware-internal RTOS |
| `TASK_SM/MM/SCAN/APM` | `TASK_SM/MM/SCAN/APM` | **Shared enum** |
| `rc_*` (rate control) | — | Firmware-internal |
| `scanu_*` (scan) | `rwnx_msg_rx/tx` (messages) | Host ↔ firmware messages |
| `bam_*`, `twt_*`, `rxu_*`, `txu_*` | — | Firmware-internal |

Host driver sends `*_req`/`*_cfm` messages; firmware implements the state
machines. `TASK_*` is the contract.

Do not redistribute firmware blobs. This repo records structure and hashes
only.
