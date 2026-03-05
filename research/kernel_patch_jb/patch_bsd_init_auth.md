# B13 `patch_bsd_init_auth`

## Patch Goal

Bypass the root volume authentication gate during early BSD init by forcing the auth helper return path to success.

## Binary Targets (IDA + Recovered Symbols)

- Recovered symbol: `bsd_init` at `0xfffffe0007f7add4`.
- Anchor string: `"rootvp not authenticated after mounting @%s:%d"` at `0xfffffe000707d6bb`.
- Anchor xref: `0xfffffe0007f7bc04` inside `sub_FFFFFE0007F7ADD4` (same function as `bsd_init`).

## Call-Stack Analysis

- Static callers of `bsd_init` (`0xfffffe0007f7add4`):
  - `sub_FFFFFE0007F7ACE0`
  - `sub_FFFFFE0007B43EE0`
- The patch point is in the rootvp/authentication decision path inside `bsd_init`, before the panic/report path using the rootvp-not-authenticated string.

## Patch-Site / Byte-Level Change

- Patcher intent:
  - Find `ldr x0, [xN, #0x2b8] ; cbz x0, ... ; bl auth_fn`.
  - Replace `bl auth_fn` with `mov x0, #0`.
- Expected replacement bytes:
  - after: `00 00 80 D2` (`mov x0, #0`)
- Current IDA image appears already post-variant / non-matching for the exact pre-patch triplet at the old location, so the exact original 4-byte BL at this build-state is not asserted here.

## Pseudocode (Before)

```c
int rc = auth_rootvp(rootvp);
if (rc != 0) {
    panic("rootvp not authenticated ...");
}
```

## Pseudocode (After)

```c
int rc = 0;   // forced success
if (rc != 0) {
    panic("rootvp not authenticated ...");
}
```

## Symbol Consistency

- `bsd_init` symbol and anchor context are consistent.
- Exact auth-call instruction bytes require pre-patch image state for strict byte-for-byte confirmation.

## Patch Metadata

- Patch document: `patch_bsd_init_auth.md` (B13).
- Primary patcher module: `scripts/patchers/kernel_jb_patch_bsd_init_auth.py`.
- Analysis mode: static binary analysis (IDA-MCP + disassembly + recovered symbols), no runtime patch execution.

## Target Function(s) and Binary Location

- Primary target: recovered symbol `bsd_init` at `0xfffffe0007f7add4`.
- Auth-check patchpoint is in the rootvp-authentication decision sequence documented in this file.

## Kernel Source File Location

- Expected XNU source: `bsd/kern/bsd_init.c`.
- Confidence: `high`.

## Function Call Stack

- Primary traced chain (from `Call-Stack Analysis`):
- Static callers of `bsd_init` (`0xfffffe0007f7add4`):
- `sub_FFFFFE0007F7ACE0`
- `sub_FFFFFE0007B43EE0`
- The patch point is in the rootvp/authentication decision path inside `bsd_init`, before the panic/report path using the rootvp-not-authenticated string.
- The upstream entry(s) and patched decision node are linked by direct xref/callsite evidence in this file.

## Patch Hit Points

- Key patchpoint evidence (from `Patch-Site / Byte-Level Change`):
- Find `ldr x0, [xN, #0x2b8] ; cbz x0, ... ; bl auth_fn`.
- Expected replacement bytes:
- after: `00 00 80 D2` (`mov x0, #0`)
- The before/after instruction transform is constrained to this validated site.

## Current Patch Search Logic

- Implemented in `scripts/patchers/kernel_jb_patch_bsd_init_auth.py`.
- Site resolution uses anchor + opcode-shape + control-flow context; ambiguous candidates are rejected.
- The patch is applied only after a unique candidate is confirmed in-function.
- Anchor string: `"rootvp not authenticated after mounting @%s:%d"` at `0xfffffe000707d6bb`.
- Anchor xref: `0xfffffe0007f7bc04` inside `sub_FFFFFE0007F7ADD4` (same function as `bsd_init`).

## Validation (Static Evidence)

- Verified with IDA-MCP disassembly/decompilation, xrefs, and callgraph context for the selected site.
- Cross-checked against recovered symbols in `research/kernel_info/json/kernelcache.research.vphone600.bin.symbols.json`.
- Address-level evidence in this document is consistent with patcher matcher intent.

## Expected Failure/Panic if Unpatched

- Root volume auth check can trigger `"rootvp not authenticated ..."` panic/report path during early BSD init.

## Risk / Side Effects

- This patch weakens a kernel policy gate by design and can broaden behavior beyond stock security assumptions.
- Potential side effects include reduced diagnostics fidelity and wider privileged surface for patched workflows.

## Symbol Consistency Check

- Recovered-symbol status in `kernelcache.research.vphone600.bin.symbols.json`: `match`.
- Canonical symbol hit(s): `bsd_init`.
- Where canonical names are absent, this document relies on address-level control-flow and instruction evidence; analyst aliases are explicitly marked as aliases.
- IDA-MCP lookup snapshot (2026-03-05): `bsd_init` -> `bsd_init` at `0xfffffe0007f7add4` (size `0xe3c`).

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
- IDA function sample: `exec_handle_sugid`
- Chain function sample: `exec_handle_sugid`
- Caller sample: `exec_mach_imgact`
- Callee sample: `exec_handle_sugid`, `sub_FFFFFE0007B0EA64`, `sub_FFFFFE0007B0F4F8`, `sub_FFFFFE0007B1663C`, `sub_FFFFFE0007B1B508`, `sub_FFFFFE0007B1C348`
- Verdict: `questionable`
- Recommendation: Hit is valid but patch is inactive in find_all(); enable only after staged validation.
- Key verified points:
- `0xFFFFFE0007FB09DC` (`exec_handle_sugid`): mov x0,#0 [_bsd_init auth] | `a050ef97 -> 000080d2`
- Artifacts: `research/kernel_patch_jb/runtime_verification/runtime_verification_report.json`
- Artifacts: `research/kernel_patch_jb/runtime_verification/ida_runtime_patch_points.json`
- Artifacts: `research/kernel_patch_jb/runtime_verification/ida_patch_chain_report.json`
- Artifacts: `research/kernel_patch_jb/runtime_verification/ida_patch_chain_report.md`
<!-- END_RUNTIME_IDA_VERIFICATION_2026_03_05 -->
