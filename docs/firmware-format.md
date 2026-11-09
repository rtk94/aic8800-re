# AIC8800 firmware blob format (preliminary)

Both `fmacfw_8800d80_u02.bin` and `lmacfw_rf_8800d80_u02.bin` share the same
container: a small header with ASCII magic **`WFFW`** at offset 0x20, then
zero-padding to 0x28, followed by repeating 4-byte address-ish values in the
`0x00xxxxxx` range (load-image addresses).

Observed (offsets are file offsets):

```
0x00  <8 bytes>            sizes/types differ per image
0x08  0x0013xxxx …        table of addresses, ~0x30 bytes
0x20  57 46 46 57         "WFFW"
0x28  05 02 12 00 …       repeats / further header words
```

The code/data payload follows; string evidence points to a bare-metal RTOS
(RivieraWaves `ke_task` layer) running on the AIC8800 RISC-V core. Full
section layout not yet established — needs binwalk (`REA_BINWALK_COMMAND`)
or a Ghidra raw-binary session, neither available in the current REA server.

Do not redistribute firmware blobs. This repo records structure and hashes
only.
