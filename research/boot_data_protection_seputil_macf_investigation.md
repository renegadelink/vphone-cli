# Data-Protection Panic Investigation (2026-03-05)

## Symptom

On JB boot, system reaches `launchd` boot tasks but then panics with:

- `Boot task failed: data-protection - exited due to exit(60)`
- repeated host-side retries:
  - `[control] vsock: ... Connection reset by peer, retrying...`
- and critical kernel log:
  - `IOUC AppleSEPUserClient failed MACF in process pid 6, seputil`

## What This Confirms

This is not an early-kernel boot hang. The failure occurs in userspace boot task `data-protection`, where `seputil` cannot pass MACF/IOKit authorization to open SEP user client paths.

## Static Root-Cause Trace (kernelcache.research.vphone600)

Using local disassembly on the current vphone600 research kernel:

1. `failed MACF` log string xref resolves to IOKit MAC dispatch function at:
   - function start VA: `0xFFFFFE000825B0C0`
2. The deny path emits `failed MACF` after policy callback dispatch.
3. Callback slot used in this path is:
   - `policy->ops + 0x648` => index `201`
4. Current sandbox-extended patch set (before this fix) did not include `ops[201..210]`.
5. Sandbox ops table for this kernel has non-null handlers at:
   - `201..210` (`0xFFFFFE00093A654C` ... `0xFFFFFE00093A598C`)

Interpretation: IOKit MAC hooks remained active and could deny `AppleSEPUserClient` access, matching runtime `IOUC ... failed MACF`.

## Mitigation Implemented

### 1) Kernel patcher extension

Updated:

- `scripts/patchers/kernel_jb_patch_sandbox_extended.py`

Added hook indices:

- `201..210` as `iokit_check_201` ... `iokit_check_210`

Patch action per entry remains:

- `mov x0,#0`
- `ret`

### 2) Documentation updates

Updated:

- `research/kernel_patch_jb/patch_sandbox_hooks_extended.md`
- `research/00_patch_comparison_all_variants.md`

## Local Validation (static)

Ran `patch_sandbox_hooks_extended()` against current `kernelcache.research.vphone600`:

- before extension: `52` writes (`26` hooks)
- after extension: `72` writes (`36` hooks)

New emitted entries include:

- `_hook_iokit_check_201` ... `_hook_iokit_check_210`

## Runtime Validation Pending

Not yet executed in this turn. Required E2E confirmation:

1. `make fw_patch_jb`
2. restore flow (so patched kernel is installed)
3. `make cfw_install_jb`
4. `make boot`
5. verify disappearance of:
   - `IOUC AppleSEPUserClient failed MACF ... seputil`
   - `Boot task failed: data-protection - exited due to exit(60)`

## Notes

- Canonical `mpo_iokit_*` names for these indices are not fully symbol-resolved in local KC symbols; index-based labeling is used intentionally to avoid incorrect naming.

## 2026-03-06 Follow-up (still failing after ops[201..210] extension)

Observed runtime still reports:

- `IOUC AppleAPFSUserClient failed MACF in process pid 4, mount`
- `IOUC AppleSEPUserClient failed MACF in process pid 6, seputil`

So per-policy sandbox hook stubs alone are insufficient on this path.

### Additional Mitigation Added

Introduced a dedicated JB patch:

- `patch_iouc_failed_macf` in `scripts/patchers/kernel_jb_patch_iouc_macf.py`

Method:

- Anchor on `"failed MACF"` xref.
- Resolve centralized IOUC MACF gate function.
- Apply low-risk early return at `fn+4/fn+8`:
  - `mov x0, xzr`
  - `retab`

Current static hit on this kernel:

- function start: `0xfffffe000825b0c0`
- patched:
  - `0xfffffe000825b0c4`
  - `0xfffffe000825b0c8`

Related doc:

- `research/kernel_patch_jb/patch_iouc_failed_macf.md`
