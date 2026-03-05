# C23 `patch_hook_cred_label_update_execve`

## Patch Goal

Install an inline trampoline on the sandbox cred-label execve hook, inject ownership-propagation shellcode, and resume original hook flow safely.

## Binary Targets (IDA + Recovered Symbols)

- Sandbox policy strings/data:
  - `"Sandbox"` pointer at `0xfffffe0007a66cc0`
  - `"Seatbelt sandbox policy"` pointer at `0xfffffe0007a66cc8`
  - `mpc_ops` table at `0xfffffe0007a66d20`
- Dynamic hook selection (ops[0..29], max size):
  - selected entry: `ops[18] = 0xfffffe00093d2ce4` (size `0x1070`)
- Recovered hook symbol (callee in this path):
  - `_hook_cred_label_update_execve` at `0xfffffe00093d0d0c`
- `vnode_getattr` resolution by string-near-BL method:
  - string `%s: vnode_getattr: %d` xref at `0xfffffe00084caa18`
  - nearest preceding BL target: `0xfffffe0007cd84f8`

## Call-Stack Analysis

- MAC framework dispatch -> `mac_policy_ops[18]` (`0xfffffe00093d2ce4`) -> internal call to `_hook_cred_label_update_execve` (`0xfffffe00093d0d0c`).
- No direct code xrefs to `ops[18]` function (expected: data-driven dispatch table call path).

## Patch-Site / Byte-Level Change

- Trampoline site: `0xfffffe00093d2ce4`
- Before:
  - bytes: `7F 23 03 D5`
  - asm: `PACIBSP`
- After:
  - asm: `B cave` (PC-relative, target depends on allocated cave offset)
- Cave semantics:
  - slot 0: relocated `PACIBSP`
  - slot 18: `BL vnode_getattr_target`
  - tail: restore regs + `B hook+4`

## Pseudocode (Before)

```c
int hook_cred_label_update_execve(args...) {
    // original sandbox hook logic
    ...
}
```

## Pseudocode (After)

```c
int hook_entry(args...) {
    branch_to_cave();
}

int cave(args...) {
    pacibsp();
    if (vp != NULL) {
        vnode_getattr(vp, &vap, &ctx);
        propagate_uid_gid_if_needed(new_cred, vap, proc);
    }
    branch_to_hook_plus_4();
}
```

## Symbol Consistency

- `_hook_cred_label_update_execve` symbol is present and aligned with call-path evidence.
- `ops[18]` wrapper itself has no recovered explicit symbol name; behavior is consistent with sandbox MAC dispatch wrapper.

## Patch Metadata

- Patch document: `patch_hook_cred_label_update_execve.md` (C23).
- Primary patcher module: `scripts/patchers/kernel_jb_patch_hook_cred_label.py`.
- Analysis mode: static binary analysis (IDA-MCP + disassembly + recovered symbols), no runtime patch execution.

## Target Function(s) and Binary Location

- Primary target: hook/trampoline path around `hook_cred_label_update_execve`.
- Patch hit combines inline branch rewrite plus code-cave logic, with addresses listed below.

## Kernel Source File Location

- Component: sandbox/AMFI hook glue around execve cred-label callback (partially private in KC).
- Related open-source context: `security/mac_process.c`, `bsd/kern/kern_exec.c`.
- Confidence: `low`.

## Function Call Stack

- Primary traced chain (from `Call-Stack Analysis`):
- MAC framework dispatch -> `mac_policy_ops[18]` (`0xfffffe00093d2ce4`) -> internal call to `_hook_cred_label_update_execve` (`0xfffffe00093d0d0c`).
- No direct code xrefs to `ops[18]` function (expected: data-driven dispatch table call path).
- The upstream entry(s) and patched decision node are linked by direct xref/callsite evidence in this file.

## Patch Hit Points

- Key patchpoint evidence (from `Patch-Site / Byte-Level Change`):
- Trampoline site: `0xfffffe00093d2ce4`
- Before:
- bytes: `7F 23 03 D5`
- asm: `PACIBSP`
- After:
- asm: `B cave` (PC-relative, target depends on allocated cave offset)
- The before/after instruction transform is constrained to this validated site.

## Current Patch Search Logic

- Implemented in `scripts/patchers/kernel_jb_patch_hook_cred_label.py`.
- Site resolution uses anchor + opcode-shape + control-flow context; ambiguous candidates are rejected.
- The patch is applied only after a unique candidate is confirmed in-function.
- Uses string anchors + instruction-pattern constraints + structural filters (for example callsite shape, branch form, register/imm checks).

## Validation (Static Evidence)

- Verified with IDA-MCP disassembly/decompilation, xrefs, and callgraph context for the selected site.
- Cross-checked against recovered symbols in `research/kernel_info/json/kernelcache.research.vphone600.bin.symbols.json`.
- Address-level evidence in this document is consistent with patcher matcher intent.

## Expected Failure/Panic if Unpatched

- Exec hook path retains ownership/suid propagation restrictions, leading to launch denial or broken privilege state transitions.

## Risk / Side Effects

- This patch weakens a kernel policy gate by design and can broaden behavior beyond stock security assumptions.
- Potential side effects include reduced diagnostics fidelity and wider privileged surface for patched workflows.

## Symbol Consistency Check

- Recovered-symbol status in `kernelcache.research.vphone600.bin.symbols.json`: `match`.
- Canonical symbol hit(s): `_hook_cred_label_update_execve`.
- Where canonical names are absent, this document relies on address-level control-flow and instruction evidence; analyst aliases are explicitly marked as aliases.
- IDA-MCP lookup snapshot (2026-03-05): `_hook_cred_label_update_execve` resolved at `0xfffffe00093d0d0c` (size `0x460`).

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
- Runtime status: `hit` (2 patch writes, method_return=True)
- Included in `KernelJBPatcher.find_all()`: `True`
- IDA mapping: `2/2` points in recognized functions; `0` points are code-cave/data-table writes.
- IDA mapping status: `ok` (IDA runtime mapping loaded.)
- Call-chain mapping status: `ok` (IDA call-chain report loaded.)
- Call-chain validation: `1` function nodes, `2` patch-point VAs.
- IDA function sample: `sub_FFFFFE00093D2CE4`
- Chain function sample: `sub_FFFFFE00093D2CE4`
- Caller sample: none
- Callee sample: `__sfree_data`, `_hook_cred_label_update_execve`, `_sb_evaluate_internal`, `persona_put_and_unlock`, `proc_checkdeadrefs`, `sub_FFFFFE0007AC57A0`
- Verdict: `valid`
- Recommendation: Keep enabled for this kernel build; continue monitoring for pattern drift.
- Policy note: method is in the low-risk optimized set (validated hit on this kernel).
- Key verified points:
- `0xFFFFFE00093D2CE8` (`sub_FFFFFE00093D2CE4`): mov x0,xzr [_hook_cred_label_update_execve low-risk] | `fc6fbaa9 -> e0031faa`
- `0xFFFFFE00093D2CEC` (`sub_FFFFFE00093D2CE4`): retab [_hook_cred_label_update_execve low-risk] | `fa6701a9 -> ff0f5fd6`
- Artifacts: `research/kernel_patch_jb/runtime_verification/runtime_verification_report.json`
- Artifacts: `research/kernel_patch_jb/runtime_verification/ida_runtime_patch_points.json`
- Artifacts: `research/kernel_patch_jb/runtime_verification/ida_patch_chain_report.json`
- Artifacts: `research/kernel_patch_jb/runtime_verification/ida_patch_chain_report.md`
<!-- END_RUNTIME_IDA_VERIFICATION_2026_03_05 -->
