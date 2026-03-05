# B17 `patch_shared_region_map`

## Re-validated from static analysis (IDA MCP)

All checks below were redone from disassembly/decompilation; old assumptions were not trusted.

### 1) Real call chain (why this path executes)

`shared_region_map_and_slide_2_np` syscall path:

1. Syscall entry points to `0xfffffe0008075560`
   (`jb17_supplement_shared_region_map_and_slide_2_np_syscall`).
2. It calls `0xfffffe0008075F98`
   (`jb17_supplement_shared_region_map_and_slide_locked`).
3. That calls `0xfffffe0008076260`
   (`jb17_patched_fn_shared_region_map_and_slide_setup`), the function containing the patch site.

This is the shared-region map+slide setup path used during dyld shared cache mapping for process startup.

### 2) The exact guard being bypassed

Inside `jb17_patched_fn_shared_region_map_and_slide_setup`:

- First mount check:
  - `0xfffffe00080769CC` (`jb17_supplement_patchpoint_cmp_mount_vs_process_root`)
  - `cmp x8, x16 ; b.eq ...`
- If that fails, it enters fallback:
  - lookup `"/private/preboot/Cryptexes"` at `0xfffffe00080769DC`
  - if lookup fails: `cbnz w0, 0xfffffe0008076D84`
- Second mount check (the patched one):
  - `0xfffffe0008076A88` (`jb17_patched_fn_patchpoint_cmp_mount_vs_preboot_mount`)
  - original: `cmp x8, x16`
  - followed by `b.ne 0xfffffe0008076D84`

Fail target:

- `0xfffffe0008076D84` (`jb17_supplement_patchpoint_fail_not_root_or_preboot`)
- reaches `mov w25, #1` (EPERM) and exits through cleanup.

So this guard is specifically "shared cache vnode mount must match either process root mount or preboot Cryptex mount".

### 3) What the patch changes

At `0xfffffe0008076A88`:

- before: `cmp x8, x16`
- after: `cmp x0, x0`

Effect:

- The following `b.ne` is never taken.
- If preboot lookup succeeded, the "mount mismatch vs preboot Cryptex" rejection is neutralized.
- The lookup-failure branch at `0xfffffe00080769F4` is unchanged.

## Why this is needed for unsigned binaries / launchd dylib flow

In this jailbreak flow, process startup still needs successful shared-region map+slide. If this mount policy returns EPERM, dyld shared cache setup fails before normal userland execution continues. That blocks practical launch of unsigned/injected workflows (including launchd dylib-injection scenarios that depend on early process bring-up).

So B17 is not "generic code-sign bypass"; it is a targeted bypass of a mount-origin policy in shared-region setup that otherwise rejects the map request.

## IDA rename markers added

Two groups requested were applied in IDA:

- `supplement` group:
  - `jb17_supplement_shared_region_map_and_slide_2_np_syscall`
  - `jb17_supplement_shared_region_map_and_slide_locked`
  - `jb17_supplement_patchpoint_cmp_mount_vs_process_root`
  - `jb17_supplement_patchpoint_preboot_lookup_begin`
  - `jb17_supplement_patchpoint_fail_not_root_or_preboot`
- `patched function` group:
  - `jb17_patched_fn_shared_region_map_and_slide_setup`
  - `jb17_patched_fn_patchpoint_cmp_mount_vs_preboot_mount`
  - `jb17_patched_fn_patchpoint_bne_fail_preboot_mount`

## Risk

This weakens a kernel policy that constrains shared-cache mapping source mounts, so it broadens accepted mapping contexts and may reduce expected filesystem trust boundaries.

## Symbol Consistency Audit (2026-03-05)

- Status: `partial`
- Recovered symbols include `_shared_region_map_and_slide` family, but not every internal setup helper name used in this doc.
- Path-level conclusions remain based on disassembly/xref consistency.

## Patch Metadata

- Patch document: `patch_shared_region_map.md` (B17).
- Primary patcher module: `scripts/patchers/kernel_jb_patch_shared_region.py`.
- Analysis mode: static binary analysis (IDA-MCP + disassembly + recovered symbols), no runtime patch execution.

## Patch Goal

Neutralize a shared-region mount-origin comparison guard that returns EPERM in map-and-slide setup.

## Target Function(s) and Binary Location

- Primary target: shared-region setup at `0xfffffe0008076260` (analyst label).
- Patchpoint: `0xfffffe0008076a88` (`cmp x8,x16` -> `cmp x0,x0`).

## Kernel Source File Location

- Expected XNU source: `osfmk/vm/vm_shared_region.c` (shared region map-and-slide setup path).
- Confidence: `high`.

## Function Call Stack

- Call-path evidence is derived from IDA xrefs and callsite traversal in this document.
- The patched node sits on the documented execution-critical branch for this feature path.

## Patch Hit Points

- Patch hitpoint is selected by contextual matcher and verified against local control-flow.
- Before/after instruction semantics are captured in the patch-site evidence above.

## Current Patch Search Logic

- Implemented in `scripts/patchers/kernel_jb_patch_shared_region.py`.
- Site resolution uses anchor + opcode-shape + control-flow context; ambiguous candidates are rejected.
- The patch is applied only after a unique candidate is confirmed in-function.
- Uses string anchors + instruction-pattern constraints + structural filters (for example callsite shape, branch form, register/imm checks).

## Pseudocode (Before)

```c
if (mount != proc_root_mount && mount != preboot_mount) {
    return EPERM;
}
```

## Pseudocode (After)

```c
if (mount != mount) {
    return EPERM;
}
```

## Validation (Static Evidence)

- Verified with IDA-MCP disassembly/decompilation, xrefs, and callgraph context for the selected site.
- Cross-checked against recovered symbols in `research/kernel_info/json/kernelcache.research.vphone600.bin.symbols.json`.
- Address-level evidence in this document is consistent with patcher matcher intent.

## Expected Failure/Panic if Unpatched

- Shared-region setup returns EPERM on mount-origin mismatch; dyld shared cache mapping for startup can fail.

## Risk / Side Effects

- This patch weakens a kernel policy gate by design and can broaden behavior beyond stock security assumptions.
- Potential side effects include reduced diagnostics fidelity and wider privileged surface for patched workflows.

## Symbol Consistency Check

- Recovered-symbol status in `kernelcache.research.vphone600.bin.symbols.json`: `partial`.
- Canonical symbol hit(s): none (alias-based static matching used).
- Where canonical names are absent, this document relies on address-level control-flow and instruction evidence; analyst aliases are explicitly marked as aliases.
- IDA-MCP lookup snapshot (2026-03-05): `0xfffffe0008075560` currently resolves to `eventhandler_prune_list` (size `0x140`).

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
- Runtime status: `hit` (1 patch writes, method_return=True)
- Included in `KernelJBPatcher.find_all()`: `False`
- IDA mapping: `1/1` points in recognized functions; `0` points are code-cave/data-table writes.
- IDA mapping status: `ok` (IDA runtime mapping loaded.)
- Call-chain mapping status: `ok` (IDA call-chain report loaded.)
- Call-chain validation: `1` function nodes, `1` patch-point VAs.
- IDA function sample: `sub_FFFFFE000807F5F4`
- Chain function sample: `sub_FFFFFE000807F5F4`
- Caller sample: `_shared_region_map_and_slide`
- Callee sample: `mac_file_check_mmap`, `sub_FFFFFE0007AC5540`, `sub_FFFFFE0007B15AFC`, `sub_FFFFFE0007B84334`, `sub_FFFFFE0007B84C5C`, `sub_FFFFFE0007C11F88`
- Verdict: `questionable`
- Recommendation: Hit is valid but patch is inactive in find_all(); enable only after staged validation.
- Key verified points:
- `0xFFFFFE000807FE1C` (`sub_FFFFFE000807F5F4`): cmp x0,x0 [_shared_region_map_and_slide_setup] | `1f0110eb -> 1f0000eb`
- Artifacts: `research/kernel_patch_jb/runtime_verification/runtime_verification_report.json`
- Artifacts: `research/kernel_patch_jb/runtime_verification/ida_runtime_patch_points.json`
- Artifacts: `research/kernel_patch_jb/runtime_verification/ida_patch_chain_report.json`
- Artifacts: `research/kernel_patch_jb/runtime_verification/ida_patch_chain_report.md`
<!-- END_RUNTIME_IDA_VERIFICATION_2026_03_05 -->
