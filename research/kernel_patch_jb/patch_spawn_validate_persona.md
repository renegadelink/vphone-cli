# B14 `patch_spawn_validate_persona`

## Revalidated target (static, IDA MCP)

- Kernel analyzed: `/Users/qaq/Desktop/kernelcache.research.vphone600.macho` (stripped symbols).
- Patcher (`scripts/patchers/kernel_jb_patch_spawn_persona.py`) resolves the newer-layout gate and emits:
  - file offset `0x00FA694C` -> `b #0x130`
- In IDA VA space, the same site is:
  - function `jb_b16_b14_patch_spawn_validate_persona_entry` @ `0xFFFFFE0007FA898C`
  - patch point `0xFFFFFE0007FAA94C`
  - original: `TBZ W8, #1, loc_FFFFFE0007FAAA7C`
  - patched: unconditional `B loc_FFFFFE0007FAAA7C`

## What this bypass actually skips

At `0xFFFFFE0007FAA94C`, bit1 of local spawn-persona state (`[SP+var_2E0]`) gates an inner validation block.

When the block executes (unpatched path), it performs:

1. `BL jb_b14_patch_persona_check_core` @ `0xFFFFFE0007FCA14C`
2. Optional follow-up `BL jb_b14_patch_persona_check_followup` @ `0xFFFFFE0007FC9F98` (when bit `0x400` is set)
3. On nonzero return, immediate error path:
   - sets error (`W28 = 1`)
   - jumps to `sub_FFFFFE000806C338(9, 19)` path (spawn failure report)

So B14 does not "relax everything"; it specifically removes this persona-precheck gate branch so execution continues from `0xFFFFFE0007FAAA7C`.

## Why this matters for unsigned binary launch and launchd dylib flow

`jb_b16_b14_patch_spawn_validate_persona_entry` is in the exec/spawn image-activation path (it references:

- `com.apple.private.spawn-panic-crash-behavior`
- `com.apple.private.spawn-subsystem-root`
- hardened-process entitlements
  ).

Static caller trace (backward xrefs) shows it is reached from multiple MAC policy dispatch paths used during spawn:

- `jb_b16_supp_mac_proc_check_launch_constraints` (`0xFFFFFE00082D66B8`) -> patched function
- `jb_b14_supp_spawn_policy_slot_0x30_dispatch` (`0xFFFFFE00082DA058`) -> patched function
- `jbA2_supp_mac_policy_dispatch_ops90_execve` (`0xFFFFFE00082D9D0C`) -> patched function
- `jb_a4_supp_mac_policy_vnode_check_exec` (`0xFFFFFE00082DBB18`) -> patched function

And the higher spawn/exec chain includes:

- `jbA2_supp_exec_activate_image` -> `jbA2_supp_imgact_exec_driver` -> `jbA2_supp_imgact_validate_and_activate` -> these policy dispatchers -> patched function.

### Practical implication

For unsigned/modified launch scenarios (including launchd with injected dylib), process creation still traverses this persona gate before later userland hooks are useful. If persona validation returns nonzero here, spawn aborts early; daemons/binaries never get to the stage where unsigned payload behavior is desired.  
B14 prevents that early rejection by forcing the skip branch.

## IDA naming and patch-point markings done

### Patched-function group

- `0xFFFFFE0007FA898C` -> `jb_b16_b14_patch_spawn_validate_persona_entry`
- `0xFFFFFE0007FCA14C` -> `jb_b14_patch_persona_check_core`
- `0xFFFFFE0007FC9F98` -> `jb_b14_patch_persona_check_followup`
- Comments added at:
  - `0xFFFFFE0007FAA94C` (B14 patch site)
  - `0xFFFFFE0007FAAA7C` (forced-branch target)
  - `0xFFFFFE0007FAAA84` (follow-up check call site)

### Supplement group

- `0xFFFFFE00082DA058` -> `jb_b14_supp_spawn_policy_slot_0x30_dispatch`
- `0xFFFFFE00082D9D0C` -> `jbA2_supp_mac_policy_dispatch_ops90_execve`
- `0xFFFFFE00082D66B8` -> `jb_b16_supp_mac_proc_check_launch_constraints`
- `0xFFFFFE00082DBB18` -> `jb_a4_supp_mac_policy_vnode_check_exec`
- `0xFFFFFE0007FA6858` -> `patched_b13_exec_policy_stage_from_load_machfile`
- `0xFFFFFE0007F81F00` -> `jbA2_supp_execve_mac_policy_bridge`

## Risk

- This bypass weakens spawn persona enforcement and can allow launches that kernel policy normally rejects.

## Symbol Consistency Audit (2026-03-05)

- Status: `partial`
- Direct recovered symbol `spawn_validate_persona` is not present in current `kernel_info` JSON.
- Upstream policy-path symbols are recovered and consistent with the traced context (for example `mac_proc_check_launch_constraints` at `0xfffffe00082df194`, `mac_vnode_check_signature` at `0xfffffe00082e4624`, and `exec_activate_image` at `0xfffffe0007fb5474`).
- Current naming at the exact patch function remains analyst labeling of validated address paths.

## Patch Metadata

- Patch document: `patch_spawn_validate_persona.md` (B14).
- Primary patcher module: `scripts/patchers/kernel_jb_patch_spawn_persona.py`.
- Analysis mode: static binary analysis (IDA-MCP + disassembly + recovered symbols), no runtime patch execution.

## Patch Goal

Skip persona validation branch that can abort spawn/exec pipeline before userland bootstrap.

## Target Function(s) and Binary Location

- Primary target: spawn persona gate function at `0xfffffe0007fa898c`.
- Patchpoint: `0xfffffe0007faa94c` (`tbz` -> unconditional `b`).

## Kernel Source File Location

- Expected XNU source family: `bsd/kern/kern_exec.c` spawn/exec persona validation path.
- Confidence: `medium`.

## Function Call Stack

- Call-path evidence is derived from IDA xrefs and callsite traversal in this document.
- The patched node sits on the documented execution-critical branch for this feature path.

## Patch Hit Points

- Patch hitpoint is selected by contextual matcher and verified against local control-flow.
- Before/after instruction semantics are captured in the patch-site evidence above.

## Current Patch Search Logic

- Implemented in `scripts/patchers/kernel_jb_patch_spawn_persona.py`.
- Site resolution uses anchor + opcode-shape + control-flow context; ambiguous candidates are rejected.
- The patch is applied only after a unique candidate is confirmed in-function.
- Uses string anchors + instruction-pattern constraints + structural filters (for example callsite shape, branch form, register/imm checks).

## Pseudocode (Before)

```c
if (persona_bit1_set) {
    if (persona_check(...) != 0) return 1;
}
```

## Pseudocode (After)

```c
/* TBZ gate bypassed */
goto persona_check_skip;
```

## Validation (Static Evidence)

- Verified with IDA-MCP disassembly/decompilation, xrefs, and callgraph context for the selected site.
- Cross-checked against recovered symbols in `research/kernel_info/json/kernelcache.research.vphone600.bin.symbols.json`.
- Address-level evidence in this document is consistent with patcher matcher intent.

## Expected Failure/Panic if Unpatched

- Persona validation branch can return error early in spawn/exec path, aborting process launch before userland hooks apply.

## Risk / Side Effects

- This patch weakens a kernel policy gate by design and can broaden behavior beyond stock security assumptions.
- Potential side effects include reduced diagnostics fidelity and wider privileged surface for patched workflows.

## Symbol Consistency Check

- Recovered-symbol status in `kernelcache.research.vphone600.bin.symbols.json`: `partial`.
- Canonical symbol hit(s): none (alias-based static matching used).
- Where canonical names are absent, this document relies on address-level control-flow and instruction evidence; analyst aliases are explicitly marked as aliases.
- IDA-MCP lookup snapshot (2026-03-05): `0xfffffe0007fa898c` currently resolves to `sub_FFFFFE0007FA8658` (size `0x394`).

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
- IDA function sample: `exec_spawnattr_getmacpolicyinfo`
- Chain function sample: `exec_spawnattr_getmacpolicyinfo`
- Caller sample: `mac_proc_check_launch_constraints`, `sub_FFFFFE00082E2484`, `sub_FFFFFE00082E27D0`, `sub_FFFFFE00082E4118`
- Callee sample: `bank_task_initialize`, `chgproccnt`, `cloneproc`, `dup2`, `exec_activate_image`, `exec_resettextvp`
- Verdict: `questionable`
- Recommendation: Hit is valid but patch is inactive in find_all(); enable only after staged validation.
- Key verified points:
- `0xFFFFFE0007FB48B0` (`exec_spawnattr_getmacpolicyinfo`): b #0x130 [_spawn_validate_persona gate] | `88090836 -> 4c000014`
- Artifacts: `research/kernel_patch_jb/runtime_verification/runtime_verification_report.json`
- Artifacts: `research/kernel_patch_jb/runtime_verification/ida_runtime_patch_points.json`
- Artifacts: `research/kernel_patch_jb/runtime_verification/ida_patch_chain_report.json`
- Artifacts: `research/kernel_patch_jb/runtime_verification/ida_patch_chain_report.md`
<!-- END_RUNTIME_IDA_VERIFICATION_2026_03_05 -->
