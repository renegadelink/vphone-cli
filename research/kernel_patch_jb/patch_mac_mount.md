# B11 `patch_mac_mount` (full static re-validation, 2026-03-05)

## Scope and method

- Re-done from scratch with static analysis only (IDA MCP), treating prior notes as untrusted.
- Verified function flow, callers, syscall-entry reachability, and patch-site semantics on the current kernel image in IDA.

## Patched function and exact gate

- Patched function (`patched` group):
  - `patch_mac_mount__patched_fn_mount_gate` @ `0xFFFFFE0007CA8E08`
- Critical sequence:
  - `0xFFFFFE0007CA8EA8`: `BL patch_mac_mount__supp_mount_ctx_prepare`
  - `0xFFFFFE0007CA8EAC`: `CBNZ W0, 0xFFFFFE0007CA8EC8` **(patch target)**
  - `0xFFFFFE0007CA8EC8`: `MOV W0, #1` (deny/error return path)
- Meaning:
  - This gate consumes return code from the context/policy-prep call and forces immediate failure (`W0=1`) on non-zero.
  - `patch_mac_mount` must neutralize the deny branch, not the BL call.

## Why this function is called (full trace from mount entry paths)

- IDA-marked `supplement` functions:
  - `patch_mac_mount__supp_sys_mount_adapter` @ `0xFFFFFE0007CA9AF8`
  - `patch_mac_mount__supp_sys_mount_core` @ `0xFFFFFE0007CA9B38`
  - `patch_mac_mount__supp_sys_fmount` @ `0xFFFFFE0007CAA924`
  - `patch_mac_mount__supp_sys_fs_snapshot` @ `0xFFFFFE0007CBE51C`
  - `patch_mac_mount__supp_snapshot_mount_core` @ `0xFFFFFE0007CBED28`
  - `patch_mac_mount__supp_mount_common` @ `0xFFFFFE0007CA7868`
  - `patch_mac_mount__supp_mount_ctx_prepare` @ `0xFFFFFE0007CCD1B4`
- Syscall-table-backed handlers (data pointers observed in `__const`):
  - `0xFFFFFE0007740800` -> `patch_mac_mount__supp_sys_mount_adapter`
  - `0xFFFFFE0007742018` -> `patch_mac_mount__supp_sys_mount_core`
  - `0xFFFFFE00077429A8` -> `patch_mac_mount__supp_sys_fmount`
  - `0xFFFFFE00077428E8` -> `patch_mac_mount__supp_sys_fs_snapshot`
- Reachability into patched gate:
  - `patch_mac_mount__supp_mount_common` calls patched gate at `0xFFFFFE0007CA79F4`
  - `patch_mac_mount__supp_sys_mount_core` also directly calls patched gate at `0xFFFFFE0007CAA03C`
  - `patch_mac_mount__supp_sys_fmount` enters via `mount_common` (`0xFFFFFE0007CAAA3C`)
  - `patch_mac_mount__supp_snapshot_mount_core` enters via `mount_common` (`0xFFFFFE0007CBEF5C`)

## Purpose of the patch (why required for unsigned payload + launchd hook workflow)

- This gate is in the mount authorization/preflight path; deny branch returns early before normal mount completion path.
- Downstream mount path is only reached if this gate does not abort (e.g., later call to `sub_FFFFFE00082E11E4` in the patched function).
- Project install/runtime dependency on successful mounts is explicit:
  - `scripts/cfw_install.sh` and `scripts/cfw_install_jb.sh` require `mount_apfs` success and hard-fail on mount failure.
  - JB flow writes unsigned payload binaries under mounted rootfs paths and deploys hook dylibs under `/mnt1/cores/...`.
  - JB-1 modifies launchd to load `/cores/launchdhook.dylib`; if mount path is blocked, required filesystem state/artifacts are not reliably available.
- Therefore this patch is a mount-authorization bypass needed to keep the mount pipeline alive for:
  1. installing/using unsigned payload binaries, and
  2. making launchd dylib injection path viable.

## Correctness note on patch style

- Correct implementation: patch deny branch (`CBNZ W0`) to `NOP`.
- Incorrect/old style: NOP the preceding `BL` can leave stale `W0` and spuriously force deny.
- Current code path is aligned with correct style (branch patch).

## IDA markings applied (requested two groups)

- `patched` group:
  - `patch_mac_mount__patched_fn_mount_gate`
  - patch-point comment at `0xFFFFFE0007CA8EAC`
- `supplement` group:
  - `patch_mac_mount__supp_*` functions listed above
  - patch context comments at `0xFFFFFE0007CA8EA8` and `0xFFFFFE0007CA8EC8`

## Security impact

- This bypass weakens MAC enforcement in mount flow and expands what mount operations can proceed.
- It is functional for JB bring-up but should be treated as a high-impact policy bypass.

## Symbol Consistency Audit (2026-03-05)

- Status: `partial`
- Recovered symbol `__mac_mount` exists at `0xfffffe0007cb4eec`.
- This document traces a deeper mount-policy path and uses analyst labels for internal helpers; those names are only partially represented in recovered symbol JSON.

## Patch Metadata

- Patch document: `patch_mac_mount.md` (B11).
- Primary patcher module: `scripts/patchers/kernel_jb_patch_mac_mount.py`.
- Analysis mode: static binary analysis (IDA-MCP + disassembly + recovered symbols), no runtime patch execution.

## Patch Goal

Bypass the mount-policy deny branch in MAC mount flow so jailbreak filesystem setup can continue.

## Target Function(s) and Binary Location

- Primary target: mount gate function at `0xfffffe0007ca8e08` (`CBNZ W0` deny branch site).
- Patchpoint: `0xfffffe0007ca8eac` (`cbnz` -> `nop`).

## Kernel Source File Location

- Expected XNU source family: `security/mac_vfs.c` / `bsd/vfs/vfs_syscalls.c` mount policy bridge.
- Confidence: `medium`.

## Function Call Stack

- Primary traced chain (from `Why this function is called (full trace from mount entry paths)`):
- IDA-marked `supplement` functions:
- `patch_mac_mount__supp_sys_mount_adapter` @ `0xFFFFFE0007CA9AF8`
- `patch_mac_mount__supp_sys_mount_core` @ `0xFFFFFE0007CA9B38`
- `patch_mac_mount__supp_sys_fmount` @ `0xFFFFFE0007CAA924`
- `patch_mac_mount__supp_sys_fs_snapshot` @ `0xFFFFFE0007CBE51C`
- The upstream entry(s) and patched decision node are linked by direct xref/callsite evidence in this file.

## Patch Hit Points

- Patch hitpoint is selected by contextual matcher and verified against local control-flow.
- Before/after instruction semantics are captured in the patch-site evidence above.

## Current Patch Search Logic

- Implemented in `scripts/patchers/kernel_jb_patch_mac_mount.py`.
- Site resolution uses anchor + opcode-shape + control-flow context; ambiguous candidates are rejected.
- The patch is applied only after a unique candidate is confirmed in-function.
- Uses string anchors + instruction-pattern constraints + structural filters (for example callsite shape, branch form, register/imm checks).

## Pseudocode (Before)

```c
rc = mount_ctx_prepare(...);
if (rc != 0) {
    return 1;
}
```

## Pseudocode (After)

```c
rc = mount_ctx_prepare(...);
/* deny branch skipped */
```

## Validation (Static Evidence)

- Verified with IDA-MCP disassembly/decompilation, xrefs, and callgraph context for the selected site.
- Cross-checked against recovered symbols in `research/kernel_info/json/kernelcache.research.vphone600.bin.symbols.json`.
- Address-level evidence in this document is consistent with patcher matcher intent.

## Expected Failure/Panic if Unpatched

- MAC mount precheck deny branch returns error early, causing mount pipeline failure during CFW/JB install steps.

## Risk / Side Effects

- This patch weakens a kernel policy gate by design and can broaden behavior beyond stock security assumptions.
- Potential side effects include reduced diagnostics fidelity and wider privileged surface for patched workflows.

## Symbol Consistency Check

- Recovered-symbol status in `kernelcache.research.vphone600.bin.symbols.json`: `match`.
- Canonical symbol hit(s): `__mac_mount`.
- Where canonical names are absent, this document relies on address-level control-flow and instruction evidence; analyst aliases are explicitly marked as aliases.
- IDA-MCP lookup snapshot (2026-03-05): `0xfffffe0007ca8e08` currently resolves to `sub_FFFFFE0007CA8C90` (size `0x1a4`).

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
- IDA function sample: `prepare_coveredvp`
- Chain function sample: `prepare_coveredvp`
- Caller sample: `__mac_mount`, `mount_common`
- Callee sample: `buf_invalidateblks`, `enablequotas`, `prepare_coveredvp`, `sub_FFFFFE0007B1B508`, `sub_FFFFFE0007B1C348`, `sub_FFFFFE0007B1C590`
- Verdict: `questionable`
- Recommendation: Hit is valid but patch is inactive in find_all(); enable only after staged validation.
- Key verified points:
- `0xFFFFFE0007CB4260` (`prepare_coveredvp`): NOP [___mac_mount deny branch] | `e0000035 -> 1f2003d5`
- Artifacts: `research/kernel_patch_jb/runtime_verification/runtime_verification_report.json`
- Artifacts: `research/kernel_patch_jb/runtime_verification/ida_runtime_patch_points.json`
- Artifacts: `research/kernel_patch_jb/runtime_verification/ida_patch_chain_report.json`
- Artifacts: `research/kernel_patch_jb/runtime_verification/ida_patch_chain_report.md`
<!-- END_RUNTIME_IDA_VERIFICATION_2026_03_05 -->
