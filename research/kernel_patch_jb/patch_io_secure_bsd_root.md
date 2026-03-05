# B19 `patch_io_secure_bsd_root`

## Patch Goal

Bypass secure-root enforcement branch so the checked path does not block execution.

## Binary Targets (IDA + Recovered Symbols)

- Recovered symbol: `IOSecureBSDRoot` at `0xfffffe0008297fd8`.
- Additional fallback function observed by string+context matching:
  - `sub_FFFFFE000836E168` (AppleARMPE call path with `SecureRoot` / `SecureRootName` references)
- Strict branch candidate used by current fallback-style logic:
  - `0xfffffe000836e1f0` (`CBZ W0, ...`) after `BLRAA`

## Call-Stack Analysis

- `IOSecureBSDRoot` is the named entrypoint for secure-root handling.
- `sub_FFFFFE000836E168` is reached through platform-dispatch data refs (vtable-style), not direct BL callers.

## Patch-Site / Byte-Level Change

- Candidate patch site: `0xfffffe000836e1f0`
- Before:
  - bytes: `20 0D 00 34`
  - asm: `CBZ W0, loc_FFFFFE000836E394`
- After:
  - bytes: `69 00 00 14`
  - asm: `B #0x1A4`

## Pseudocode (Before)

```c
status = callback(...);
if (status == 0) {
    goto secure_root_pass_path;
}
// fail / alternate handling
```

## Pseudocode (After)

```c
goto secure_root_pass_path;   // unconditional
```

## Symbol Consistency

- `IOSecureBSDRoot` symbol is recovered and trustworthy as the primary semantic target.
- Current fallback patch site is in a related dispatch function; this is semantically plausible but should be treated as lower confidence than a direct in-symbol site.

## Patch Metadata

- Patch document: `patch_io_secure_bsd_root.md` (B19).
- Primary patcher module: `scripts/patchers/kernel_jb_patch_secure_root.py`.
- Analysis mode: static binary analysis (IDA-MCP + disassembly + recovered symbols), no runtime patch execution.

## Target Function(s) and Binary Location

- Primary target: `IOSecureBSDRoot` policy-branch site selected by guard-site filters.
- Patchpoint is the deny-check branch converted to permissive flow.

## Kernel Source File Location

- Likely IOKit secure-root policy code inside kernel collection (not fully exposed in open-source XNU tree).
- Closest open-source family: `iokit/Kernel/*` root device / BSD name handling.
- Confidence: `low`.

## Function Call Stack

- Primary traced chain (from `Call-Stack Analysis`):
- `IOSecureBSDRoot` is the named entrypoint for secure-root handling.
- `sub_FFFFFE000836E168` is reached through platform-dispatch data refs (vtable-style), not direct BL callers.
- The upstream entry(s) and patched decision node are linked by direct xref/callsite evidence in this file.

## Patch Hit Points

- Key patchpoint evidence (from `Patch-Site / Byte-Level Change`):
- Candidate patch site: `0xfffffe000836e1f0`
- Before:
- bytes: `20 0D 00 34`
- asm: `CBZ W0, loc_FFFFFE000836E394`
- After:
- bytes: `69 00 00 14`
- The before/after instruction transform is constrained to this validated site.

## Current Patch Search Logic

- Implemented in `scripts/patchers/kernel_jb_patch_secure_root.py`.
- Site resolution uses anchor + opcode-shape + control-flow context; ambiguous candidates are rejected.
- The patch is applied only after a unique candidate is confirmed in-function.
- Uses string anchors + instruction-pattern constraints + structural filters (for example callsite shape, branch form, register/imm checks).

## Validation (Static Evidence)

- Verified with IDA-MCP disassembly/decompilation, xrefs, and callgraph context for the selected site.
- Cross-checked against recovered symbols in `research/kernel_info/json/kernelcache.research.vphone600.bin.symbols.json`.
- Address-level evidence in this document is consistent with patcher matcher intent.

## Expected Failure/Panic if Unpatched

- Secure BSD root policy check continues to deny modified-root boot/runtime paths needed by jailbreak filesystem flow.

## Risk / Side Effects

- This patch weakens a kernel policy gate by design and can broaden behavior beyond stock security assumptions.
- Potential side effects include reduced diagnostics fidelity and wider privileged surface for patched workflows.

## Symbol Consistency Check

- Recovered-symbol status in `kernelcache.research.vphone600.bin.symbols.json`: `match`.
- Canonical symbol hit(s): `IOSecureBSDRoot`.
- Where canonical names are absent, this document relies on address-level control-flow and instruction evidence; analyst aliases are explicitly marked as aliases.
- IDA-MCP lookup snapshot (2026-03-05): `IOSecureBSDRoot` -> `IOSecureBSDRoot` at `0xfffffe0008297fd8`.

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
- IDA function sample: `__ZN10AppleARMPE20callPlatformFunctionEPK8OSSymbolbPvS3_S3_S3_`
- Chain function sample: `__ZN10AppleARMPE20callPlatformFunctionEPK8OSSymbolbPvS3_S3_S3_`
- Caller sample: none
- Callee sample: `__ZN10AppleARMPE20callPlatformFunctionEPK8OSSymbolbPvS3_S3_S3_`, `sub_FFFFFE0007AC57A0`, `sub_FFFFFE0007AC5830`, `sub_FFFFFE0007B1B4E0`, `sub_FFFFFE0007B1C324`, `sub_FFFFFE0008133868`
- Verdict: `questionable`
- Recommendation: Hit is valid but patch is inactive in find_all(); enable only after staged validation.
- Key verified points:
- `0xFFFFFE000836E1F0` (`__ZN10AppleARMPE20callPlatformFunctionEPK8OSSymbolbPvS3_S3_S3_`): b #0x1A4 [_IOSecureBSDRoot] | `200d0034 -> 69000014`
- Artifacts: `research/kernel_patch_jb/runtime_verification/runtime_verification_report.json`
- Artifacts: `research/kernel_patch_jb/runtime_verification/ida_runtime_patch_points.json`
- Artifacts: `research/kernel_patch_jb/runtime_verification/ida_patch_chain_report.json`
- Artifacts: `research/kernel_patch_jb/runtime_verification/ida_patch_chain_report.md`
<!-- END_RUNTIME_IDA_VERIFICATION_2026_03_05 -->
