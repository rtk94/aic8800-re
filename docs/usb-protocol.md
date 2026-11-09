# AIC8800 USB host→device protocol

## Device endpoints

```
Interface 0    Bluetooth (Wireless class)
  EP 3 IN      Interrupt (64 B)
  EP 4 IN      Bulk (512 B)
  EP 4 OUT     Bulk (512 B)

Interface 1    Bluetooth (continued)
Interface 2    Vendor Specific (0xff)
  EP 2 OUT     Bulk — host→device (firmware upload, commands)
  EP 2 IN      Bulk — device→host (responses)
```

From `lsusb -v -d a69c:8d81`. The vendor interface (2) is used for
firmware download.

## Bulk transfer format (observed in usbmon capture)

Captured on `usbmon5` (bus 5) during `modprobe` reload. Device
re-enumerated three times (addresses 18 → 19 → 20).

### Command packets (host → device, bulk OUT)

Per-packet structure **1048 bytes**:

```
Offset  Size  Field
0x00    8     Magic + flags: 14 04 11 00 00 00 00 00
0x08    4     Command ID: 0b 04 01 00
0x0C    4     Address: 64 00 08 04 (varies)
0x10    4     Length: 40 19 20 00 (0x201940 = 2101056? — varies per chunk)
0x14    …     Data payload (firmware chunk)
```

First packet is a 20-byte init command:

```
10 00 11 00 00 00 00 00 00 04 01 00 64 00 04 00 00 00 50 40
```

### Sequence

1. **Init** (device 18): descriptor fetch, interface setup
2. **Firmware download** (device 19): bulk OUT EP 0x01 (1048-byte chunks),
   560 packets = 423,000 bytes total. fmacfw found in stream after ~55 KB
   of init/patch/ADID uploads. Bulk IN EP 0x82 (3712-byte responses).
3. **Post-load** (device 20): bulk IN EP 0x81, 20 × 20 KB transfers
   (~400 KB) — lmacfw load/verify phase.

### Verification

- `fmacfw_8800d80_u02.bin` (from WFFW offset) found in the bulk OUT stream.
  Raw `find()` matches the first 992 bytes then diverges (interleaved
  command headers).
- `lmacfw_rf_8800d80_u02.bin` not found in bulk OUT — loaded during device
  20 phase in a different form (see pass 5 notes).

## Windows bulk pipes

From `aicloadfw.sys` strings:

```
BulkOutput Pipe is 0x%p
BulkInput Pipe is 0x%p
Interrupt Pipe is 0x%p
```

The KMDF loader (OSRUSBFX2-derived) uses `WdfUsbTargetDeviceCreateWithParameters`
and `SelectInterfaces` to set up these pipes, then streams firmware with
`bin upload : %x, i:%d` logging.

## Findings files

- `firmware-load.pcap` — full capture (2988 packets, 709 KB, gitignored)
- `firmware-load-filtered.pcap` — device-only (2848 packets, 695 KB, gitignored)
- pcap hashes: see notes/02-wine-usbmon-ghidra.md
