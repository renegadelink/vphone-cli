# B9 `patch_vm_fault_enter_prepare`

## Patch Goal

NOP a strict state/permission check site in `vm_fault_enter_prepare` identified by the `BL -> LDRB [..,#0x2c] -> TBZ/TBNZ` fingerprint.

## Binary Targets (IDA + Recovered Symbols)

- Recovered symbol: `vm_fault_enter_prepare` at `0xfffffe0007bb8818`.
- Anchor string: `"vm_fault_enter_prepare"` at `0xfffffe0007048ec8`.
- String xrefs in this function: `0xfffffe0007bb88c4`, `0xfffffe0007bb944c`.

## Call-Stack Analysis

Representative static callers:

- `vm_fault_internal` (`0xfffffe0007bb6ef0`) -> calls `vm_fault_enter_prepare`.
- `sub_FFFFFE0007BB8294` (`0xfffffe0007bb8350`) -> calls `vm_fault_enter_prepare`.

This confirms B9 is in the central page-fault preparation path.

## Patch-Site / Byte-Level Change

Unique strict matcher hit in `vm_fault_enter_prepare`:

- `0xfffffe0007bb898c`: `BL sub_FFFFFE0007C4B7DC`
- `0xfffffe0007bb8990`: `LDRB W8, [X20,#0x2C]`
- `0xfffffe0007bb8994`: `TBZ W8, #5, loc_FFFFFE0007BB89C4`

Patch operation:

- NOP the BL at `0xfffffe0007bb898c`.

Bytes:

- before: `94 4B 02 94` (`BL ...`)
- after: `1F 20 03 D5` (`NOP`)

## Pseudocode (Before)

```c
state_check();
flag = map->state_byte;
if ((flag & BIT5) == 0) {
    goto fast_path;
}
```

## Pseudocode (After)

```c
// state_check() skipped
flag = map->state_byte;
if ((flag & BIT5) == 0) {
    goto fast_path;
}
```

## Why This Matters

`vm_fault_enter_prepare` is part of runtime page-fault handling, so this patch affects execution-time memory validation behavior, not just execve-time checks.

## Symbol Consistency Audit (2026-03-05)

- Status: `match`
- Recovered symbol, anchor strings, and strict patch fingerprint all align on the same function.

## Patch Metadata

- Patch document: `patch_vm_fault_enter_prepare.md` (B9).
- Primary patcher module: `scripts/patchers/kernel_jb_patch_vm_fault.py`.
- Analysis mode: static binary analysis (IDA-MCP + disassembly + recovered symbols), no runtime patch execution.

## Target Function(s) and Binary Location

- Primary target: recovered symbol `vm_fault_enter_prepare`.
- Patchpoint: deny/fault guard branch NOP-ed at the validated in-function site.

## Kernel Source File Location

- Expected XNU source: `osfmk/vm/vm_fault.c`.
- Confidence: `high`.

## Function Call Stack

- Primary traced chain (from `Call-Stack Analysis`):
- Representative static callers:
- `vm_fault_internal` (`0xfffffe0007bb6ef0`) -> calls `vm_fault_enter_prepare`.
- `sub_FFFFFE0007BB8294` (`0xfffffe0007bb8350`) -> calls `vm_fault_enter_prepare`.
- This confirms B9 is in the central page-fault preparation path.
- The upstream entry(s) and patched decision node are linked by direct xref/callsite evidence in this file.

## Patch Hit Points

- Key patchpoint evidence (from `Patch-Site / Byte-Level Change`):
- `0xfffffe0007bb898c`: `BL sub_FFFFFE0007C4B7DC`
- `0xfffffe0007bb8990`: `LDRB W8, [X20,#0x2C]`
- `0xfffffe0007bb8994`: `TBZ W8, #5, loc_FFFFFE0007BB89C4`
- NOP the BL at `0xfffffe0007bb898c`.
- Bytes:
- before: `94 4B 02 94` (`BL ...`)
- The before/after instruction transform is constrained to this validated site.

## Current Patch Search Logic

- Implemented in `scripts/patchers/kernel_jb_patch_vm_fault.py`.
- Site resolution uses anchor + opcode-shape + control-flow context; ambiguous candidates are rejected.
- The patch is applied only after a unique candidate is confirmed in-function.
- Anchor string: `"vm_fault_enter_prepare"` at `0xfffffe0007048ec8`.
- Recovered symbol, anchor strings, and strict patch fingerprint all align on the same function.

## Validation (Static Evidence)

- Verified with IDA-MCP disassembly/decompilation, xrefs, and callgraph context for the selected site.
- Cross-checked against recovered symbols in `research/kernel_info/json/kernelcache.research.vphone600.bin.symbols.json`.
- Address-level evidence in this document is consistent with patcher matcher intent.

## Expected Failure/Panic if Unpatched

- VM fault guard remains active and can block memory mappings/transitions required during modified execution flows.

## Risk / Side Effects

- This patch weakens a kernel policy gate by design and can broaden behavior beyond stock security assumptions.
- Potential side effects include reduced diagnostics fidelity and wider privileged surface for patched workflows.

## Symbol Consistency Check

- Recovered-symbol status in `kernelcache.research.vphone600.bin.symbols.json`: `match`.
- Canonical symbol hit(s): `vm_fault_enter_prepare`.
- Where canonical names are absent, this document relies on address-level control-flow and instruction evidence; analyst aliases are explicitly marked as aliases.
- IDA-MCP lookup snapshot (2026-03-05): `vm_fault_enter_prepare` -> `vm_fault_enter_prepare` at `0xfffffe0007bb8818`.

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
- IDA function sample: `vm_fault_enter_prepare`
- Chain function sample: `vm_fault_enter_prepare`
- Caller sample: `sub_FFFFFE0007BB8294`, `vm_fault_internal`
- Callee sample: `__strncpy_chk`, `kfree_ext`, `lck_rw_done`, `sub_FFFFFE0007B15AFC`, `sub_FFFFFE0007B546BC`, `sub_FFFFFE0007B840E0`
- Verdict: `questionable`
- Recommendation: Hit is valid but patch is inactive in find_all(); enable only after staged validation.
- Key verified points:
- `0xFFFFFE0007BB898C` (`vm_fault_enter_prepare`): NOP [_vm_fault_enter_prepare] | `944b0294 -> 1f2003d5`
- Artifacts: `research/kernel_patch_jb/runtime_verification/runtime_verification_report.json`
- Artifacts: `research/kernel_patch_jb/runtime_verification/ida_runtime_patch_points.json`
- Artifacts: `research/kernel_patch_jb/runtime_verification/ida_patch_chain_report.json`
- Artifacts: `research/kernel_patch_jb/runtime_verification/ida_patch_chain_report.md`
<!-- END_RUNTIME_IDA_VERIFICATION_2026_03_05 -->
