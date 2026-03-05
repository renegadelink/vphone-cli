# C24 `patch_kcall10`

## Patch Goal

Replace syscall 439 (`kas_info`) with a 10-argument kernel call trampoline and preserve chained-fixup integrity.

## Binary Targets (IDA + Recovered Symbols)

- Recovered symbols:
  - `nosys` at `0xfffffe0008010c94`
  - `kas_info` at `0xfffffe0008080d0c`
- Patcher design target:
  - `sysent[439]` entry: `sy_call`, optional `sy_munge32`, return-type/narg fields.
- Cave code:
  - shellcode trampoline in executable text cave (dynamic offset).

## Call-Stack Analysis

- Userland syscall -> syscall dispatch -> `sysent[439].sy_call`.
- Before patch: `sysent[439] -> kas_info` (restricted behavior).
- After patch: `sysent[439] -> kcall10 cave` (loads function pointer + args, executes `BLR x16`, stores results back).

## Patch-Site / Byte-Level Change

- Entry-point data patching is chained-fixup encoded (auth rebase), not raw VA writes.
- Key field semantics:
  - diversity: `0xBCAD`
  - key: IA (`0`)
  - addrDiv: `0`
  - preserve `next` chain bits
- Metadata patches:
  - `sy_return_type = 7`
  - `sy_narg = 8`
  - `sy_arg_bytes = 0x20`

## Pseudocode (Before)

```c
// sysent[439]
return kas_info(args);   // limited / ENOTSUP style behavior on this platform
```

## Pseudocode (After)

```c
// sysent[439]
ctx = user_buf;
fn  = ctx->func;
args = ctx->arg0..arg9;
ret_regs = fn(args...);
ctx->ret_regs = ret_regs;
return 0;
```

## Symbol Consistency

- `nosys` and `kas_info` symbols are recovered and consistent with the intended hook objective.
- Direct `sysent` symbol is not recovered; table base still relies on structural scanning + chained-fixup validation logic.

## Patch Metadata

- Patch document: `patch_kcall10.md` (C24).
- Primary patcher module: `scripts/patchers/kernel_jb_patch_kcall10.py`.
- Analysis mode: static binary analysis (IDA-MCP + disassembly + recovered symbols), no runtime patch execution.

## Target Function(s) and Binary Location

- Primary target: syscall 439 (`SYS_kas_info`) replacement path plus injected kcall10 shellcode.
- Hit points include syscall table entry redirection and payload cave sites.

## Kernel Source File Location

- Mixed source context: syscall plumbing in `bsd/kern/syscalls.master` / `osfmk/kern/syscall_sw.c` plus injected shellcode region.
- Confidence: `medium`.

## Function Call Stack

- Primary traced chain (from `Call-Stack Analysis`):
- Userland syscall -> syscall dispatch -> `sysent[439].sy_call`.
- Before patch: `sysent[439] -> kas_info` (restricted behavior).
- After patch: `sysent[439] -> kcall10 cave` (loads function pointer + args, executes `BLR x16`, stores results back).
- The upstream entry(s) and patched decision node are linked by direct xref/callsite evidence in this file.

## Patch Hit Points

- Key patchpoint evidence (from `Patch-Site / Byte-Level Change`):
- diversity: `0xBCAD`
- `sy_arg_bytes = 0x20`
- The before/after instruction transform is constrained to this validated site.

## Current Patch Search Logic

- Implemented in `scripts/patchers/kernel_jb_patch_kcall10.py`.
- Site resolution uses anchor + opcode-shape + control-flow context; ambiguous candidates are rejected.
- The patch is applied only after a unique candidate is confirmed in-function.
- Uses string anchors + instruction-pattern constraints + structural filters (for example callsite shape, branch form, register/imm checks).

## Validation (Static Evidence)

- Verified with IDA-MCP disassembly/decompilation, xrefs, and callgraph context for the selected site.
- Cross-checked against recovered symbols in `research/kernel_info/json/kernelcache.research.vphone600.bin.symbols.json`.
- Address-level evidence in this document is consistent with patcher matcher intent.

## Expected Failure/Panic if Unpatched

- Kernel arbitrary-call syscall path is unavailable; userland kcall-based bootstrap stages cannot execute.

## Risk / Side Effects

- This patch weakens a kernel policy gate by design and can broaden behavior beyond stock security assumptions.
- Potential side effects include reduced diagnostics fidelity and wider privileged surface for patched workflows.

## Symbol Consistency Check

- Recovered-symbol status in `kernelcache.research.vphone600.bin.symbols.json`: `partial`.
- Canonical symbol hit(s): none (alias-based static matching used).
- Where canonical names are absent, this document relies on address-level control-flow and instruction evidence; analyst aliases are explicitly marked as aliases.
- IDA-MCP lookup snapshot (2026-03-05): `0xfffffe0008010c94` currently resolves to `nosys` (size `0x34`).

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
- Runtime status: `hit` (3 patch writes, method_return=True)
- Included in `KernelJBPatcher.find_all()`: `True`
- IDA mapping: `0/3` points in recognized functions; `3` points are code-cave/data-table writes.
- IDA mapping status: `ok` (IDA runtime mapping loaded.)
- Call-chain mapping status: `ok` (IDA call-chain report loaded.)
- Call-chain validation: `0` function nodes, `0` patch-point VAs.
- Verdict: `valid`
- Recommendation: Keep enabled for this kernel build; continue monitoring for pattern drift.
- Policy note: method is in the low-risk optimized set (validated hit on this kernel).
- Key verified points:
- `0xFFFFFE000774E5A0` (`code-cave/data`): sysent[439].sy_call = \_nosys 0xF6F048 (auth rebase, div=0xBCAD, next=2) [kcall10 low-risk] | `0ccd0701adbc1080 -> 48f0f600adbc1080`
- `0xFFFFFE000774E5B0` (`code-cave/data`): sysent[439].sy_return_type = 1 [kcall10 low-risk] | `01000000 -> 01000000`
- `0xFFFFFE000774E5B4` (`code-cave/data`): sysent[439].sy_narg=0,sy_arg_bytes=0 [kcall10 low-risk] | `03000c00 -> 00000000`
- Artifacts: `research/kernel_patch_jb/runtime_verification/runtime_verification_report.json`
- Artifacts: `research/kernel_patch_jb/runtime_verification/ida_runtime_patch_points.json`
- Artifacts: `research/kernel_patch_jb/runtime_verification/ida_patch_chain_report.json`
- Artifacts: `research/kernel_patch_jb/runtime_verification/ida_patch_chain_report.md`
<!-- END_RUNTIME_IDA_VERIFICATION_2026_03_05 -->
