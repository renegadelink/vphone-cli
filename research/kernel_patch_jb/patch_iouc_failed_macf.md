# A5 `patch_iouc_failed_macf`

## Patch Goal

Bypass the shared IOUserClient MACF deny gate that emits:

- `IOUC AppleAPFSUserClient failed MACF ...`
- `IOUC AppleSEPUserClient failed MACF ...`

This gate blocks `mount-phase-1` and `data-protection` (`seputil`) in current JB boot logs.

## Binary Targets (vphone600 research kernel)

- Anchor string: `"failed MACF"`
- Candidate function selected by anchor xref + IOUC co-reference:
  - function start: `0xfffffe000825b0c0`
- Patch points:
  - `0xfffffe000825b0c4`
  - `0xfffffe000825b0c8`

## Patch-Site / Byte-Level Change

- At `fn + 0x4`:
  - before: stack-frame setup (`stp ...`)
  - after: `mov x0, xzr`
- At `fn + 0x8`:
  - before: stack-frame setup (`stp ...`)
  - after: `retab`

Result: function returns success immediately while preserving entry `PACIBSP`.

## Pseudocode (Before)

```c
int iouc_macf_gate(...) {
    // iterate policy callbacks, run MACF checks
    // on deny: log "failed MACF" and return non-zero error
    ...
}
```

## Pseudocode (After)

```c
int iouc_macf_gate(...) {
    return 0;
}
```

## Why This Patch Was Added

- Extending sandbox hooks to cover `ops[201..210]` was not sufficient.
- Runtime still showed both:
  - `IOUC AppleAPFSUserClient failed MACF in process pid 4, mount`
  - `IOUC AppleSEPUserClient failed MACF in process pid 6, seputil`
- This indicates deny can still occur through centralized IOUC MACF gate flow beyond per-policy sandbox hook stubs.

## Patch Metadata

- Primary patcher module:
  - `scripts/patchers/kernel_jb_patch_iouc_macf.py`
- JB scheduler status:
  - enabled in default `_DEFAULT_METHODS` as `patch_iouc_failed_macf`

## Validation (static, local)

- Method emitted 2 writes on current kernel:
  - `0x012570C4` `mov x0,xzr [IOUC MACF gate low-risk]`
  - `0x012570C8` `retab [IOUC MACF gate low-risk]`

## XNU Reference Cross-Validation (2026-03-06)

What XNU confirms:

- The exact IOUC deny logs exist in open-source path:
  - `IOUC %s failed MACF in process %s`
  - `IOUC %s failed sandbox in process %s`
  - source: `iokit/Kernel/IOUserClient.cpp`
- MACF gate condition is wired as:
  - `mac_iokit_check_open(...) != 0` -> emit `failed MACF` log
  - source: `iokit/Kernel/IOUserClient.cpp`
- MACF bridge function exists and dispatches policy checks:
  - `mac_iokit_check_open` -> `MAC_CHECK(iokit_check_open, ...)`
  - source: `security/mac_iokit.c` and `security/mac_policy.h`

What still requires IDA/runtime evidence:

- The exact patched function start/address and branch location for this kernel build.
- Class-specific runtime instances (`AppleAPFSUserClient`, `AppleSEPUserClient`) that appear in boot logs.

Interpretation:

- This patch has strong source-level support for mechanism (shared IOUC MACF gate),
  while concrete hit-point selection remains IDA-authoritative per-kernel.

## Runtime Validation Pending

Need full flow validation after patch install:

1. `make fw_patch_jb`
2. restore
3. `make cfw_install_jb`
4. `make boot`

Expected improvement:

- no `IOUC ... failed MACF` for APFS/SEP user clients
- `data-protection` should progress past `seputil` timeout path.
