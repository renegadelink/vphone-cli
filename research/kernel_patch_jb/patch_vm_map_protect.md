# B10 `patch_vm_map_protect`

## Patch Goal

Bypass a high-bit protection guard by converting a `TBNZ` check into unconditional `B`.

## Binary Targets (IDA + Recovered Symbols)

- Recovered symbol: `vm_map_protect` at `0xfffffe0007bd08d8`.
- Anchor string: `"vm_map_protect(%p,0x%llx,0x%llx) new=0x%x wired=%x @%s:%d"` at `0xfffffe0007049e44`.
- Anchor xref: `0xfffffe0007bd0efc` in `vm_map_protect`.

## Call-Stack Analysis

Representative static callers of `vm_map_protect` include:

- `sub_FFFFFE0007AF3968`
- `sub_FFFFFE0007B90928`
- `sub_FFFFFE0007B9F844`
- `sub_FFFFFE0007FD6EB0`
- additional VM/subsystem callsites

## Patch-Site / Byte-Level Change

- Selected guard site: `0xfffffe0007bd09a8`
- Before:
  - bytes: `78 24 00 B7`
  - asm: `TBNZ X24, #0x20, loc_FFFFFE0007BD0E34`
- After:
  - bytes: `23 01 00 14`
  - asm: `B #0x48C` (to same target)

## Pseudocode (Before)

```c
if (test_bit(flags, 0x20)) {
    goto guarded_path;
}
```

## Pseudocode (After)

```c
goto guarded_path;   // unconditional
```

## Symbol Consistency

- Recovered symbol name and patch context are consistent.

## Patch Metadata

- Patch document: `patch_vm_map_protect.md` (B10).
- Primary patcher module: `scripts/patchers/kernel_jb_patch_vm_protect.py`.
- Analysis mode: static binary analysis (IDA-MCP + disassembly + recovered symbols), no runtime patch execution.

## Target Function(s) and Binary Location

- Primary target: recovered symbol `vm_map_protect`.
- Patchpoint: `0xfffffe0007bd09a8` (`tbnz` -> unconditional `b`).

## Kernel Source File Location

- Expected XNU source: `osfmk/vm/vm_user.c` (`vm_map_protect`).
- Confidence: `high`.

## Function Call Stack

- Primary traced chain (from `Call-Stack Analysis`):
- Representative static callers of `vm_map_protect` include:
- `sub_FFFFFE0007AF3968`
- `sub_FFFFFE0007B90928`
- `sub_FFFFFE0007B9F844`
- `sub_FFFFFE0007FD6EB0`
- The upstream entry(s) and patched decision node are linked by direct xref/callsite evidence in this file.

## Patch Hit Points

- Key patchpoint evidence (from `Patch-Site / Byte-Level Change`):
- Selected guard site: `0xfffffe0007bd09a8`
- Before:
- bytes: `78 24 00 B7`
- asm: `TBNZ X24, #0x20, loc_FFFFFE0007BD0E34`
- After:
- bytes: `23 01 00 14`
- The before/after instruction transform is constrained to this validated site.

## Current Patch Search Logic

- Implemented in `scripts/patchers/kernel_jb_patch_vm_protect.py`.
- Site resolution uses anchor + opcode-shape + control-flow context; ambiguous candidates are rejected.
- The patch is applied only after a unique candidate is confirmed in-function.
- Anchor string: `"vm_map_protect(%p,0x%llx,0x%llx) new=0x%x wired=%x @%s:%d"` at `0xfffffe0007049e44`.
- Anchor xref: `0xfffffe0007bd0efc` in `vm_map_protect`.

## Validation (Static Evidence)

- Verified with IDA-MCP disassembly/decompilation, xrefs, and callgraph context for the selected site.
- Cross-checked against recovered symbols in `research/kernel_info/json/kernelcache.research.vphone600.bin.symbols.json`.
- Address-level evidence in this document is consistent with patcher matcher intent.

## Expected Failure/Panic if Unpatched

- High-bit protect guard keeps enforcing restrictive branch, causing vm_protect denial in jailbreak memory workflows.

## Risk / Side Effects

- This patch weakens a kernel policy gate by design and can broaden behavior beyond stock security assumptions.
- Potential side effects include reduced diagnostics fidelity and wider privileged surface for patched workflows.

## Symbol Consistency Check

- Recovered-symbol status in `kernelcache.research.vphone600.bin.symbols.json`: `match`.
- Canonical symbol hit(s): `vm_map_protect`.
- Where canonical names are absent, this document relies on address-level control-flow and instruction evidence; analyst aliases are explicitly marked as aliases.
- IDA-MCP lookup snapshot (2026-03-05): `vm_map_protect` -> `vm_map_protect` at `0xfffffe0007bd08d8`.

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
- IDA function sample: `vm_map_protect`
- Chain function sample: `vm_map_protect`
- Caller sample: `_Xmach_vm_protect`, `_Xprotect`, `__ZN27IOGuardPageMemoryDescriptor5doMapEP7_vm_mapPyjyy`, `mach_vm_protect_trap`, `mprotect`, `setrlimit`
- Callee sample: `lck_rw_done`, `pmap_protect_options`, `sub_FFFFFE0007B1D788`, `sub_FFFFFE0007B1EBF0`, `sub_FFFFFE0007B840E0`, `sub_FFFFFE0007B84C5C`
- Verdict: `questionable`
- Recommendation: Hit is valid but patch is inactive in find_all(); enable only after staged validation.
- Key verified points:
- `0xFFFFFE0007BD09A8` (`vm_map_protect`): b #0x48C [_vm_map_protect] | `782400b7 -> 23010014`
- Artifacts: `research/kernel_patch_jb/runtime_verification/runtime_verification_report.json`
- Artifacts: `research/kernel_patch_jb/runtime_verification/ida_runtime_patch_points.json`
- Artifacts: `research/kernel_patch_jb/runtime_verification/ida_patch_chain_report.json`
- Artifacts: `research/kernel_patch_jb/runtime_verification/ida_patch_chain_report.md`
<!-- END_RUNTIME_IDA_VERIFICATION_2026_03_05 -->
