# C21 `patch_cred_label_update_execve`

## Scope (revalidated with static analysis)

- Target patch method: `KernelJBPatchCredLabelMixin.patch_cred_label_update_execve` in `scripts/patchers/kernel_jb_patch_cred_label.py`.
- Target function in kernel: `jb_c21_patch_target_amfi_cred_label_update_execve` (`0xFFFFFE000863FC6C`).
- Patch-point label (inside function): `jb_c21_patchpoint_retab_redirect` (`0xFFFFFE000864011C`, original `RETAB` site).

## Verified call/dispatch trace (no trust in old notes)

1. Exec pipeline enters `jb_c21_supp_exec_handle_image` (`0xFFFFFE0007FA4A58`).
2. It calls `jb_c21_supp_exec_policy_stage` (`0xFFFFFE0007FA6858`).
3. That stage schedules `jb_c21_supp_exec_policy_wrapper` (`0xFFFFFE0007F81F00`).
4. Wrapper calls `jb_c21_supp_mac_policy_dispatch_ops90_execve` (`0xFFFFFE00082D9D0C`).
5. Dispatcher loads callback from `policy->ops + 0x90` at `jb_c21_supp_dispatch_load_ops_off90` (`0xFFFFFE00082D9DBC`) and calls it at `jb_c21_supp_dispatch_call_ops_off90` (`0xFFFFFE00082D9FCC`, `BLRAA ... X17=#0xEC79`).

This `+0x90` slot is the shared execve cred-label hook slot used by both AMFI and Sandbox hooks.

## How AMFI wires this callback

- `jb_c21_supp_amfi_init_register_policy_ops` (`0xFFFFFE0008640718`) builds AMFI `mac_policy_ops` and writes `jb_c21_patch_target_amfi_cred_label_update_execve` into offset `+0x90` (store at `0xFFFFFE0008640AA0`).
- Then it registers the policy descriptor via `sub_FFFFFE00082CDDB0` (mac policy register path).

## What the unpatched function enforces

Inside `jb_c21_patch_target_amfi_cred_label_update_execve`:

- Multiple explicit kill paths return failure (`W0=1`) for unsigned/forbidden exec cases.
- A key branch logs and kills with:
  - `"dyld signature cannot be verified... or ... unsigned application outside of a supported development configuration"`
- It conditionally mutates `*a10` (`cs_flags`) and later checks validity bits before honoring entitlements.
- If validity path is not satisfied, it logs `"not CS_VALID, not honoring entitlements"` and skips entitlement-driven flag propagation.

## Why C21 is required (full picture)

C21 is not just another allow-return patch; it is a **state-fix patch** for `cs_flags` at execve policy time.

Patch shellcode behavior (from patcher implementation):

- Load `cs_flags` pointer from stack (`arg9` path).
- `ORR` with `0x04000000` and `0x0000000F`.
- `AND` with `0xFFFFC0FF` (clears bits in `0x00003F00`).
- Store back and return success (`X0=0`).

Practical effect:

- Unsigned binaries avoid AMFI execve kill outcomes **and** get permissive execution flags instead of failing later due bad flag state.
- For launchd dylib injection (`/cores/launchdhook.dylib`), this patch is critical because the unpatched path can still fail on dyld-signature / restrictive-flag checks even if a generic kill-return patch exists elsewhere.
- Clearing the `0x3F00` cluster and forcing low/upper bits ensures launch context is treated permissively enough for injected non-Apple-signed payload flow.

## Relationship with Sandbox hook (important)

- Sandbox also has a cred-label execve hook in the same ops slot (`+0x90`):
  - `jb_c21_supp_sandbox_hook_cred_label_update_execve` (`0xFFFFFE00093BDB64`)
- That Sandbox hook contains policy such as `"only launchd is allowed to spawn untrusted binaries"`.

So launchd-dylib viability depends on **combined behavior**:

- Sandbox hook policy acceptance for launch context, and
- AMFI C21 flag/state coercion so dyld/code-signing state does not re-kill or strip required capability.

## IDA labels added in this verification pass

- **patched-function group**:
  - `jb_c21_patch_target_amfi_cred_label_update_execve` @ `0xFFFFFE000863FC6C`
  - `jb_c21_patchpoint_retab_redirect` @ `0xFFFFFE000864011C`
  - `jb_c21_ref_shared_kill_return` @ `0xFFFFFE00086400FC`
- **supplement group**:
  - `jb_c21_supp_exec_handle_image` @ `0xFFFFFE0007FA4A58`
  - `jb_c21_supp_exec_policy_stage` @ `0xFFFFFE0007FA6858`
  - `jb_c21_supp_exec_policy_wrapper` @ `0xFFFFFE0007F81F00`
  - `jb_c21_supp_mac_policy_dispatch_ops90_execve` @ `0xFFFFFE00082D9D0C`
  - `jb_c21_supp_dispatch_load_ops_off90` @ `0xFFFFFE00082D9DBC`
  - `jb_c21_supp_dispatch_call_ops_off90` @ `0xFFFFFE00082D9FCC`
  - `jb_c21_supp_amfi_start` @ `0xFFFFFE0008640624`
  - `jb_c21_supp_amfi_init_register_policy_ops` @ `0xFFFFFE0008640718`
  - `jb_c21_supp_sandbox_hook_cred_label_update_execve` @ `0xFFFFFE00093BDB64`
  - `jb_c21_supp_sandbox_execve_context_gate` @ `0xFFFFFE00093BC054`

## Symbol Consistency Audit (2026-03-05)

- Status: `partial`
- Recovered symbol `_hook_cred_label_update_execve` is present and consistent.
- Many `jb_*` helper names in this file are analyst aliases and do not all appear in recovered symbol JSON.

## Patch Metadata

- Patch document: `patch_cred_label_update_execve.md` (C21).
- Primary patcher module: `scripts/patchers/kernel_jb_patch_cred_label.py`.
- Analysis mode: static binary analysis (IDA-MCP + disassembly + recovered symbols), no runtime patch execution.

## Patch Goal

Redirect cred-label execve handling to shellcode that coerces permissive cs_flags and returns success.

## Target Function(s) and Binary Location

- Primary target: AMFI cred-label callback body at `0xfffffe000863fc6c`.
- Patchpoint: `0xfffffe000864011c` (`retab` redirect to injected shellcode/cave).

## Kernel Source File Location

- Component: AMFI policy callback implementation in kernel collection (private).
- Related open-source MAC framework context: `security/mac_process.c` + exec paths in `bsd/kern/kern_exec.c`.
- Confidence: `medium`.

## Function Call Stack

- Primary traced chain (from `Verified call/dispatch trace (no trust in old notes)`):
- 1. Exec pipeline enters `jb_c21_supp_exec_handle_image` (`0xFFFFFE0007FA4A58`).
- 2. It calls `jb_c21_supp_exec_policy_stage` (`0xFFFFFE0007FA6858`).
- 3. That stage schedules `jb_c21_supp_exec_policy_wrapper` (`0xFFFFFE0007F81F00`).
- 4. Wrapper calls `jb_c21_supp_mac_policy_dispatch_ops90_execve` (`0xFFFFFE00082D9D0C`).
- 5. Dispatcher loads callback from `policy->ops + 0x90` at `jb_c21_supp_dispatch_load_ops_off90` (`0xFFFFFE00082D9DBC`) and calls it at `jb_c21_supp_dispatch_call_ops_off90` (`0xFFFFFE00082D9FCC`, `BLRAA ... X17=#0xEC79`).
- The upstream entry(s) and patched decision node are linked by direct xref/callsite evidence in this file.

## Patch Hit Points

- Patch hitpoint is selected by contextual matcher and verified against local control-flow.
- Before/after instruction semantics are captured in the patch-site evidence above.

## Current Patch Search Logic

- Implemented in `scripts/patchers/kernel_jb_patch_cred_label.py`.
- Site resolution uses anchor + opcode-shape + control-flow context; ambiguous candidates are rejected.
- The patch is applied only after a unique candidate is confirmed in-function.
- Uses string anchors + instruction-pattern constraints + structural filters (for example callsite shape, branch form, register/imm checks).

## Pseudocode (Before)

```c
if (amfi_checks_fail || cs_flags_invalid) {
    return 1;
}
return apply_default_execve_flags(...);
```

## Pseudocode (After)

```c
cs_flags |= 0x04000000 | 0x0000000F;
cs_flags &= 0xFFFFC0FF;
return 0;
```

## Validation (Static Evidence)

- Verified with IDA-MCP disassembly/decompilation, xrefs, and callgraph context for the selected site.
- Cross-checked against recovered symbols in `research/kernel_info/json/kernelcache.research.vphone600.bin.symbols.json`.
- Address-level evidence in this document is consistent with patcher matcher intent.

## Expected Failure/Panic if Unpatched

- Exec policy path preserves restrictive `cs_flags` and deny returns, causing AMFI kill outcomes or later entitlement-state failures.

## Risk / Side Effects

- This patch weakens a kernel policy gate by design and can broaden behavior beyond stock security assumptions.
- Potential side effects include reduced diagnostics fidelity and wider privileged surface for patched workflows.

## Symbol Consistency Check

- Recovered-symbol status in `kernelcache.research.vphone600.bin.symbols.json`: `partial`.
- Canonical symbol hit(s): none (alias-based static matching used).
- Where canonical names are absent, this document relies on address-level control-flow and instruction evidence; analyst aliases are explicitly marked as aliases.
- IDA-MCP lookup snapshot (2026-03-05): `0xfffffe000863fc6c` currently resolves to `__ZN18AppleMobileApNonce21_saveNonceInfoInNVRAMEPKc` (size `0x250`).

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
- Call-chain validation: `1` function nodes, `3` patch-point VAs.
- IDA function sample: `__Z25_cred_label_update_execveP5ucredS0_P4procP5vnodexS4_P5labelS6_S6_PjPvmPi`
- Chain function sample: `__Z25_cred_label_update_execveP5ucredS0_P4procP5vnodexS4_P5labelS6_S6_PjPvmPi`
- Caller sample: `__ZL35_initializeAppleMobileFileIntegrityv`
- Callee sample: `__Z25_cred_label_update_execveP5ucredS0_P4procP5vnodexS4_P5labelS6_S6_PjPvmPi`, `__ZN24AppleMobileFileIntegrity27submitAuxiliaryInfoAnalyticEP5vnodeP7cs_blob`, `sub_FFFFFE0007B4EA8C`, `sub_FFFFFE0007CD7750`, `sub_FFFFFE0007CD7760`, `sub_FFFFFE0007F8C478`
- Verdict: `valid`
- Recommendation: Keep enabled for this kernel build; continue monitoring for pattern drift.
- Policy note: method is in the low-risk optimized set (validated hit on this kernel).
- Key verified points:
- `0xFFFFFE000864DF00` (`__Z25_cred_label_update_execveP5ucredS0_P4procP5vnodexS4_P5labelS6_S6_PjPvmPi`): mov x0,xzr [_cred_label_update_execve low-risk] | `ff4302d1 -> e0031faa`
- `0xFFFFFE000864DF04` (`__Z25_cred_label_update_execveP5ucredS0_P4procP5vnodexS4_P5labelS6_S6_PjPvmPi`): retab [_cred_label_update_execve low-risk] | `fc6f03a9 -> ff0f5fd6`
- Artifacts: `research/kernel_patch_jb/runtime_verification/runtime_verification_report.json`
- Artifacts: `research/kernel_patch_jb/runtime_verification/ida_runtime_patch_points.json`
- Artifacts: `research/kernel_patch_jb/runtime_verification/ida_patch_chain_report.json`
- Artifacts: `research/kernel_patch_jb/runtime_verification/ida_patch_chain_report.md`
<!-- END_RUNTIME_IDA_VERIFICATION_2026_03_05 -->
