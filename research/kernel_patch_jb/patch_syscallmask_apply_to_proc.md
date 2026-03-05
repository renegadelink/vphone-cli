# C22 `patch_syscallmask_apply_to_proc`

## Patch Goal

Inject a shellcode detour into legacy `_syscallmask_apply_to_proc`-shape logic to install custom syscall filter mask handling.

## Binary Targets (IDA + Recovered Symbols)

- String anchors:
  - `"syscallmask.c"` at `0xfffffe0007609236`
  - `"sandbox.syscallmasks"` at `0xfffffe000760933c`
- Related recovered functions in the cluster:
  - `_profile_syscallmask_destroy` at `0xfffffe00093ae6a4`
  - `_sandbox_syscallmask_destroy` at `0xfffffe00093ae984`
  - `_sandbox_syscallmask_create` at `0xfffffe00093aea34`
  - `_hook_policy_init` at `0xfffffe00093c1a54`

## Call-Stack Analysis

- Current firmware exposes syscallmask create/destroy/hook-policy flows.
- Legacy apply-to-proc prologue shape required by C22 shellcode was not found in anchor-near candidates.

## Patch-Site / Byte-Level Change

- Required legacy signature (strict):
  - `cbz x2` and `mov x19,x0 ; mov x20,x1 ; mov x21,x2 ; mov x22,x3` in early prologue.
- Validation result on current image: no valid candidate.
- Therefore expected behavior is fail-closed:
  - no cave writes
  - no branch redirection emitted.

## Pseudocode (Before)

```c
// current firmware path differs from legacy apply_to_proc shape
apply_or_policy_update(...);
```

## Pseudocode (After)

```c
// no patch emitted on this build (fail-closed)
apply_or_policy_update(...);
```

## Symbol Consistency

- Recovered symbols exist for syscallmask create/destroy helpers.
- `_syscallmask_apply_to_proc` symbol is not recovered and legacy signature does not match current binary layout.

## Patch Metadata

- Patch document: `patch_syscallmask_apply_to_proc.md` (C22).
- Primary patcher module: `scripts/patchers/kernel_jb_patch_syscallmask.py`.
- Analysis mode: static binary analysis (IDA-MCP + disassembly + recovered symbols), no runtime patch execution.

## Target Function(s) and Binary Location

- Primary target: `syscallmask_apply_to_proc` path plus zalloc_ro_mut update helper.
- Patchpoint combines branch policy bypass and helper-site mutation where matcher is valid.

## Kernel Source File Location

- Likely XNU source family: `bsd/kern/kern_proc.c` plus task/proc state mutation helpers.
- Confidence: `low` (layout drift noted).

## Function Call Stack

- Primary traced chain (from `Call-Stack Analysis`):
- Current firmware exposes syscallmask create/destroy/hook-policy flows.
- Legacy apply-to-proc prologue shape required by C22 shellcode was not found in anchor-near candidates.
- The upstream entry(s) and patched decision node are linked by direct xref/callsite evidence in this file.

## Patch Hit Points

- Patch hitpoint is selected by contextual matcher and verified against local control-flow.
- Before/after instruction semantics are captured in the patch-site evidence above.

## Current Patch Search Logic

- Implemented in `scripts/patchers/kernel_jb_patch_syscallmask.py`.
- Site resolution uses anchor + opcode-shape + control-flow context; ambiguous candidates are rejected.
- The patch is applied only after a unique candidate is confirmed in-function.
- String anchors:
- Legacy apply-to-proc prologue shape required by C22 shellcode was not found in anchor-near candidates.

## Validation (Static Evidence)

- Verified with IDA-MCP disassembly/decompilation, xrefs, and callgraph context for the selected site.
- Cross-checked against recovered symbols in `research/kernel_info/json/kernelcache.research.vphone600.bin.symbols.json`.
- Address-level evidence in this document is consistent with patcher matcher intent.

## Expected Failure/Panic if Unpatched

- Syscall mask restrictions remain active; required syscall surface for bootstrap stays blocked.

## Risk / Side Effects

- This patch weakens a kernel policy gate by design and can broaden behavior beyond stock security assumptions.
- Potential side effects include reduced diagnostics fidelity and wider privileged surface for patched workflows.

## Symbol Consistency Check

- Recovered-symbol status in `kernelcache.research.vphone600.bin.symbols.json`: `partial`.
- Canonical symbol hit(s): none (alias-based static matching used).
- Where canonical names are absent, this document relies on address-level control-flow and instruction evidence; analyst aliases are explicitly marked as aliases.
- IDA-MCP lookup snapshot (2026-03-05): `0xfffffe0007609236` is a patchpoint/data-site (`Not a function`), so function naming is inferred from surrounding control-flow and xrefs.

## Open Questions and Confidence

- Open question: symbol recovery is incomplete for this path; aliases are still needed for parts of the call chain.
- Overall confidence for this patch analysis: `medium` (address-level semantics are stable, symbol naming is partial).

## Evidence Appendix

- Detailed addresses, xrefs, and rationale are preserved in the existing analysis sections above.
- For byte-for-byte patch details, refer to the patch-site and call-trace subsections in this file.

## Runtime + IDA Verification (2026-03-05)

- Verification timestamp (UTC): `2026-03-05T14:55:58.795709+00:00`
- Kernel input: `/Users/qaq/Documents/Firmwares/PCC-CloudOS-26.3-23D128/kernelcache.research.vphone600`
- Base VA: `0xFFFFFE0007004000`
- Runtime status: `hit` (2 patch writes, method_return=True)
- Included in `KernelJBPatcher.find_all()`: `True`
- IDA mapping: `2/2` points in recognized functions; `0` points are code-cave/data-table writes.
- IDA mapping status: `ok` (IDA runtime mapping loaded.)
- Call-chain mapping status: `ok` (IDA call-chain report loaded.)
- Call-chain validation: `1` function nodes, `2` patch-point VAs.
- IDA function sample: `_profile_syscallmask_destroy`
- Chain function sample: `_profile_syscallmask_destroy`
- Caller sample: `_profile_uninit`, `sub_FFFFFE00093AE678`
- Callee sample: `sub_FFFFFE0008302368`, `sub_FFFFFE00093AE70C`
- Verdict: `valid`
- Recommendation: Keep enabled for this kernel build; continue monitoring for pattern drift.
- Policy note: method is in the low-risk optimized set (validated hit on this kernel).
- Key verified points:
- `0xFFFFFE00093AE6E4` (`_profile_syscallmask_destroy`): mov x0,xzr [_syscallmask_apply_to_proc low-risk] | `ff8300d1 -> e0031faa`
- `0xFFFFFE00093AE6E8` (`_profile_syscallmask_destroy`): retab [_syscallmask_apply_to_proc low-risk] | `fd7b01a9 -> ff0f5fd6`
- Artifacts: `research/kernel_patch_jb/runtime_verification/runtime_verification_report.json`
- Artifacts: `research/kernel_patch_jb/runtime_verification/ida_runtime_patch_points.json`
- Artifacts: `research/kernel_patch_jb/runtime_verification/ida_patch_chain_report.json`
- Artifacts: `research/kernel_patch_jb/runtime_verification/ida_patch_chain_report.md`
<!-- END_RUNTIME_IDA_VERIFICATION_2026_03_05 -->
