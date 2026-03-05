# B15 `patch_task_for_pid`

## Patch Goal

Suppress one `proc_ro` security-state copy in task-for-pid flow by NOP-ing the second `ldr w?, [x?, #0x490]` pair.

## Binary Targets (IDA + Recovered Symbols)

- Recovered symbol related to API path:
  - `task_for_pid_trap` at `0xfffffe0007fd12dc`
- Heuristic-resolved patch function (unique under strict matcher):
  - `0xfffffe000800cffc`
- Patch site:
  - `0xfffffe000800d120` (`LDR W8, [X20,#0x490]`)
- Data-table reference to this function:
  - `0xfffffe00077424a8` (indirect dispatch/table-style use)

## Call-Stack Analysis

- This path is mostly table/dispatch-driven, with sparse direct BL callers.
- The selected function uniquely matched:
  - > =2 `ldr #0x490 + str #0xc` pairs
  - > =2 `ldadda`
  - `movk ..., #0xc8a2`
  - high-caller BL target profile

## Patch-Site / Byte-Level Change

- Patch site: `0xfffffe000800d120`
- Before:
  - bytes: `88 92 44 B9`
  - asm: `LDR W8, [X20,#0x490]`
- After:
  - bytes: `1F 20 03 D5`
  - asm: `NOP`

## Pseudocode (Before)

```c
dst->security = src->proc_ro_security;   // second copy point
```

## Pseudocode (After)

```c
// second security copy removed
```

## Symbol Consistency

- `task_for_pid_trap` symbol exists, but strict patch-site matcher resolves a different helper routine.
- This mismatch is explicitly tracked and should remain under verification.

## Patch Metadata

- Patch document: `patch_task_for_pid.md` (B15).
- Primary patcher module: `scripts/patchers/kernel_jb_patch_task_for_pid.py`.
- Analysis mode: static binary analysis (IDA-MCP + disassembly + recovered symbols), no runtime patch execution.

## Target Function(s) and Binary Location

- Primary target: task-for-pid security helper in `task_for_pid_trap` path (matcher-resolved helper).
- Patchpoint: second `ldr #0x490` security copy point -> `nop`.

## Kernel Source File Location

- Expected XNU source: `osfmk/kern/task.c` (`task_for_pid_trap` and helper authorization flow).
- Confidence: `high`.

## Function Call Stack

- Primary traced chain (from `Call-Stack Analysis`):
- This path is mostly table/dispatch-driven, with sparse direct BL callers.
- The selected function uniquely matched:
- > =2 `ldr #0x490 + str #0xc` pairs
- > =2 `ldadda`
- `movk ..., #0xc8a2`
- The upstream entry(s) and patched decision node are linked by direct xref/callsite evidence in this file.

## Patch Hit Points

- Key patchpoint evidence (from `Patch-Site / Byte-Level Change`):
- Patch site: `0xfffffe000800d120`
- Before:
- bytes: `88 92 44 B9`
- asm: `LDR W8, [X20,#0x490]`
- After:
- bytes: `1F 20 03 D5`
- The before/after instruction transform is constrained to this validated site.

## Current Patch Search Logic

- Implemented in `scripts/patchers/kernel_jb_patch_task_for_pid.py`.
- Site resolution uses anchor + opcode-shape + control-flow context; ambiguous candidates are rejected.
- The patch is applied only after a unique candidate is confirmed in-function.
- Uses string anchors + instruction-pattern constraints + structural filters (for example callsite shape, branch form, register/imm checks).

## Validation (Static Evidence)

- Verified with IDA-MCP disassembly/decompilation, xrefs, and callgraph context for the selected site.
- Cross-checked against recovered symbols in `research/kernel_info/json/kernelcache.research.vphone600.bin.symbols.json`.
- Address-level evidence in this document is consistent with patcher matcher intent.

## Expected Failure/Panic if Unpatched

- task_for_pid helper retains proc security copy/check logic that denies task port acquisition.

## Risk / Side Effects

- This patch weakens a kernel policy gate by design and can broaden behavior beyond stock security assumptions.
- Potential side effects include reduced diagnostics fidelity and wider privileged surface for patched workflows.

## Symbol Consistency Check

- Recovered-symbol status in `kernelcache.research.vphone600.bin.symbols.json`: `match`.
- Canonical symbol hit(s): `task_for_pid_trap`.
- Where canonical names are absent, this document relies on address-level control-flow and instruction evidence; analyst aliases are explicitly marked as aliases.
- IDA-MCP lookup snapshot (2026-03-05): querying `task_for_pid_trap` resolves to `proc_ro_ref_task` at `0xfffffe0007fd12dc`; this is treated as a naming alias/mismatch risk while address semantics stay valid.

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
- IDA function sample: `sub_FFFFFE000800CFFC`
- Chain function sample: `sub_FFFFFE000800CFFC`
- Caller sample: none
- Callee sample: `kfree_ext`, `sub_FFFFFE0007B15AFC`, `sub_FFFFFE0007B1F20C`, `sub_FFFFFE0007B1F444`, `sub_FFFFFE0007FE91CC`, `sub_FFFFFE000800CFFC`
- Verdict: `questionable`
- Recommendation: Hit is valid but patch is inactive in find_all(); enable only after staged validation.
- Key verified points:
- `0xFFFFFE000800D120` (`sub_FFFFFE000800CFFC`): NOP [_task_for_pid proc_ro copy] | `889244b9 -> 1f2003d5`
- Artifacts: `research/kernel_patch_jb/runtime_verification/runtime_verification_report.json`
- Artifacts: `research/kernel_patch_jb/runtime_verification/ida_runtime_patch_points.json`
- Artifacts: `research/kernel_patch_jb/runtime_verification/ida_patch_chain_report.json`
- Artifacts: `research/kernel_patch_jb/runtime_verification/ida_patch_chain_report.md`
<!-- END_RUNTIME_IDA_VERIFICATION_2026_03_05 -->
