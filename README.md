# AIC8800 wireless dongle — reverse engineering

Target: AICSemi AIC8800D80 USB Wi-Fi 6 + Bluetooth dongle (Temu), USB
`a69c:8d81` (also `368b:8d81`), serial `20220103`. Live on Bus 005.

Driver source / installer: `rtk94/aic8800d80-clone-dongle` (fork of
shenmintao/aic8800d80) — local clone `~/audit-p5/aic8800d80`.

## Layout

- `targets/` — analysis targets (gitignored originals; hashes below)
- `notes/` — REA findings with Evidence IDs
- `docs/` — protocol / firmware writeups

## Targets

| File | SHA-256 | Source |
|---|---|---|
| `targets/Wifi6_install.exe` | `82d338c49f8fa0f8f76df57c8bbddcf25179aaa17b63e85d13ae28a144752465` | `1111:1111` Pandora FLASH disk (label `WiF6-driver`) on the dongle |
| `targets/fmacfw_8800d80_u02.bin` | see `notes/` | `fw/aic8800D80/` in driver repo |
| `targets/lmacfw_rf_8800d80_u02.bin` | see `notes/` | `fw/aic8800D80/` in driver repo |

Do not redistribute original binaries — committed docs carry hashes and
descriptors only.
