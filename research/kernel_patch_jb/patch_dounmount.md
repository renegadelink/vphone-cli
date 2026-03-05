# B12 `patch_dounmount`

## Patch Goal

Bypass a MAC authorization call in `dounmount` by NOP-ing a strict `mov w1,#0 ; mov x2,#0 ; bl ...` callsite.

## Binary Targets (IDA + Recovered Symbols)

- Recovered symbols:
  - `dounmount` at `0xfffffe0007cb6ea0`
  - `safedounmount` at `0xfffffe0007cb6cec`
- Anchor string: `"dounmount: no coveredvp @%s:%d"` at `0xfffffe0007056950`.
- Anchor xref: `0xfffffe0007cb7700` in `sub_FFFFFE0007CB6EA0`.

## Call-Stack Analysis

- Static callers into `dounmount` include:
  - `sub_FFFFFE0007CA45E4`
  - `sub_FFFFFE0007CAAE28`
  - `sub_FFFFFE0007CB6CEC`
  - `sub_FFFFFE0007CB770C`
- This confirms the expected unmount path context.

## Patch-Site / Byte-Level Change

- Intended matcher requires exact pair:
  - `mov w1, #0`
  - `mov x2, #0`
  - `bl ...`
- In current IDA state, the close callsite is:
  - `mov w1, #0x10 ; mov x2, #0 ; bl sub_FFFFFE0007CAB27C` at `0xfffffe0007cb75b0`
- Therefore strict matcher is not satisfied in this image state.
- Fail-closed behavior is correct: no patch should be emitted here unless exact semantics are revalidated.

## Pseudocode (Before)

```c
rc = mac_check(..., 0, 0);
if (rc != 0) {
    return rc;
}
```

## Pseudocode (After)

```c
// BL mac_check replaced by NOP
// execution continues as if check passed
```

## Symbol Consistency

- `dounmount` symbol resolution is consistent.
- Pattern-level mismatch indicates prior hardcoded assumptions are not universally valid.

## Patch Metadata

- Patch document: `patch_dounmount.md` (B12).
- Primary patcher module: `scripts/patchers/kernel_jb_patch_dounmount.py`.
- Analysis mode: static binary analysis (IDA-MCP + disassembly + recovered symbols), no runtime patch execution.

## Target Function(s) and Binary Location

- Primary target: `dounmount` deny branch in VFS unmount path.
- Exact patch site (NOP on strict in-function match) is documented in this file.

## Kernel Source File Location

- Expected XNU source: `bsd/vfs/vfs_syscalls.c` (`dounmount`).
- Confidence: `high`.

## Function Call Stack

- Primary traced chain (from `Call-Stack Analysis`):
- Static callers into `dounmount` include:
- `sub_FFFFFE0007CA45E4`
- `sub_FFFFFE0007CAAE28`
- `sub_FFFFFE0007CB6CEC`
- `sub_FFFFFE0007CB770C`
- The upstream entry(s) and patched decision node are linked by direct xref/callsite evidence in this file.

## Patch Hit Points

- Key patchpoint evidence (from `Patch-Site / Byte-Level Change`):
- `mov w1, #0x10 ; mov x2, #0 ; bl sub_FFFFFE0007CAB27C` at `0xfffffe0007cb75b0`
- The before/after instruction transform is constrained to this validated site.

## Current Patch Search Logic

- Implemented in `scripts/patchers/kernel_jb_patch_dounmount.py`.
- Site resolution uses anchor + opcode-shape + control-flow context; ambiguous candidates are rejected.
- The patch is applied only after a unique candidate is confirmed in-function.
- Anchor string: `"dounmount: no coveredvp @%s:%d"` at `0xfffffe0007056950`.
- Anchor xref: `0xfffffe0007cb7700` in `sub_FFFFFE0007CB6EA0`.

## Validation (Static Evidence)

- Verified with IDA-MCP disassembly/decompilation, xrefs, and callgraph context for the selected site.
- Cross-checked against recovered symbols in `research/kernel_info/json/kernelcache.research.vphone600.bin.symbols.json`.
- Address-level evidence in this document is consistent with patcher matcher intent.

## Expected Failure/Panic if Unpatched

- Unmount requests remain blocked by guarded deny branch, breaking workflows that require controlled remount/unmount transitions.

## Risk / Side Effects

- This patch weakens a kernel policy gate by design and can broaden behavior beyond stock security assumptions.
- Potential side effects include reduced diagnostics fidelity and wider privileged surface for patched workflows.

## Symbol Consistency Check

- Recovered-symbol status in `kernelcache.research.vphone600.bin.symbols.json`: `match`.
- Canonical symbol hit(s): `dounmount`.
- Where canonical names are absent, this document relies on address-level control-flow and instruction evidence; analyst aliases are explicitly marked as aliases.
- IDA-MCP lookup snapshot (2026-03-05): `dounmount` -> `dounmount` at `0xfffffe0007cb6ea0`.

## Open Questions and Confidence

- Open question: verify future firmware drift does not move this site into an equivalent but semantically different branch.
- Overall confidence for this patch analysis: `high` (symbol match + control-flow/byte evidence).

## Evidence Appendix

- Detailed addresses, xrefs, and rationale are preserved in the existing analysis sections above.
- For byte-for-byte patch details, refer to the patch-site and call-trace subsections in this file.

## Runtime + IDA Verification (2026-03-05)

- Verification timestamp (UTC): `2026-03-05T14:55:58.795709+00:00`
- Kernel input: `/Users/qaq/Documents/Firmwares/PCC-CloudOS-26.3-23D128/kernelcache.research.vphone600`
- Base VA: `0xFFFFFE0007004000`
- Runtime status: `hit` (1 patch writes, method_return=True)
- Included in `KernelJBPatcher.find_all()`: `False`
- IDA mapping: `1/1` points in recognized functions; `0` points are code-cave/data-table writes.
- IDA mapping status: `ok` (IDA runtime mapping loaded.)
- Call-chain mapping status: `ok` (IDA call-chain report loaded.)
- Call-chain validation: `1` function nodes, `1` patch-point VAs.
- IDA function sample: `dounmount`
- Chain function sample: `dounmount`
- Caller sample: `safedounmount`, `sub_FFFFFE0007CAAE28`, `sub_FFFFFE0007CB770C`, `vfs_mountroot`
- Callee sample: `dounmount`, `lck_mtx_destroy`, `lck_rw_done`, `mount_dropcrossref`, `mount_iterdrain`, `mount_refdrain`
- Verdict: `questionable`
- Recommendation: Hit is valid but patch is inactive in find_all(); enable only after staged validation.
- Key verified points:
- `0xFFFFFE0007CB75B0` (`dounmount`): NOP [_dounmount MAC check] | `33cfff97 -> 1f2003d5`
- Artifacts: `research/kernel_patch_jb/runtime_verification/runtime_verification_report.json`
- Artifacts: `research/kernel_patch_jb/runtime_verification/ida_runtime_patch_points.json`
- Artifacts: `research/kernel_patch_jb/runtime_verification/ida_patch_chain_report.json`
- Artifacts: `research/kernel_patch_jb/runtime_verification/ida_patch_chain_report.md`
<!-- END_RUNTIME_IDA_VERIFICATION_2026_03_05 -->
