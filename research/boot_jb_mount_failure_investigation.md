# JB Mount Failure Investigation (2026-03-04)

## Symptom

- `make setup_machine JB=1` reached `cfw_install_jb` and failed at:
  - `Failed to mount /dev/disk1s1 at /mnt1 (opts=rw).`

## Runtime Evidence (Normal Boot)

From `make boot` serial log:

- APFS mount tasks fail with permission errors:
  - `mount_apfs: volume could not be mounted: Operation not permitted`
  - `mount: /private/xarts failed with 77`
  - `mount: /private/preboot failed with 77`
  - launchd panics: `boot task failure: mount-phase-1 - exited due to exit(77)`
- Ignition/boot path shows entitlement-like failure:
  - `handle_get_dev_by_role:13101: disk1s1 This operation needs entitlement`

This indicates failure in APFS role-based device lookup during early boot mount tasks.

## Runtime Evidence (DEV Control Run, 2026-03-04)

From a separate `fw_patch_dev + cfw_install_dev` boot log (not JB):

- `mount-phase-1` succeeded for xART:
  - `disk1s3 mount-complete volume xART`
  - `/dev/disk1s3 on /private/xarts ...`
- launch progressed to:
  - `data-protection`
  - `finish-obliteration`
  - `detect-installed-roots`
  - `mount-phase-2`

Interpretation: APFS boot-mount path can work on this build/kernel family after recent APFS gate changes.
This does **not** prove JB flow is fixed; it is a control signal showing the kernel-side path is not universally broken.

## Flow Separation (Critical)

- The successful `xART mount-complete` / `mount-phase-2` log is from DEV pipeline:
  - `fw_patch_dev` + `cfw_install_dev`
- JB pipeline remains:
  - `fw_patch_jb` + `cfw_install_jb`
- `cfw_install_jb` does **not** call `cfw_install_dev`; it runs base `cfw_install.sh` first, then JB-only phases.

## Kernel Artifact Checks

### 1) Ramdisk kernel identity

- `vm/Ramdisk/krnl.img4` payload hash was byte-identical to:
  - `vm/iPhone17,3_26.1_23B85_Restore/kernelcache.research.vphone600`

So ramdisk boot was using the same restore kernel payload (no accidental file mismatch in `ramdisk_build`).

### 2) Patchability state (current VM kernel)

On `vm/iPhone17,3_26.1_23B85_Restore/kernelcache.research.vphone600`:

- Base APFS patches:
  - `patch_apfs_vfsop_mount_cmp` -> not patchable (already applied)
  - `patch_apfs_mount_upgrade_checks` -> not patchable (already applied)
- Key JB patches:
  - `patch_mac_mount` -> patchable
  - `patch_dounmount` -> patchable
  - `patch_kcall10` -> patchable

Interpretation: kernel is base-patched, but critical JB mount/syscall extensions are still missing.

### 3) Reference hash comparison

- CloudOS source `kernelcache.research.vphone600` payload:
  - `b6846048f3a60eab5f360fcc0f3dcb5198aa0476c86fb06eb42f6267cdbfcae0`
- VM restore kernel payload:
  - `b0523ff40c8a08626549a33d89520cca616672121e762450c654f963f65536a0`

So restore kernel is modified vs source, but not fully JB-complete.

## IDA Deep-Dive (APFS mount-phase-1 path)

### 1) Failing function identified

- APFS function: `sub_FFFFFE000948EB10` (log name: `handle_get_dev_by_role`)
- Trigger string in function:
  - `"%s:%d: %s This operation needs entitlement\\n"` (line 13101)
- Caller xref:
  - `sub_FFFFFE000947CFE4` dispatches to `sub_FFFFFE000948EB10`

### 2) Gate logic at failure site

The deny path is reached if either check fails:

- Context gate:
  - `BL sub_FFFFFE0007CCB994`
  - `CBZ X0, deny`
- "Entitlement" gate (APFS role lookup privilege gate):
  - `ADRL X1, "com.apple.apfs.get-dev-by-role"`
  - `BL sub_FFFFFE000940CFC8`
  - `CBZ W0, deny`
- Secondary role-path gate (role == 2 volume-group path):
  - `BL sub_FFFFFE000817C240`
  - `CBZ W0, deny` (to line 13115 block)

The deny block logs line `13101` and returns failure.

### 3) Patch sites (current vphone600 kernelcache)

- File offsets:
  - `0x0248AB50` — context gate branch (`CBZ X0, deny`)
  - `0x0248AB64` — role-lookup privilege gate (`CBZ W0, deny`)
  - `0x0248AC24` — secondary role==2 deny branch (`CBZ W0, deny`)
- All three patched to `NOP` in the additive APFS patch.

### 4) Additional APFS EPERM(1) return paths in `apfs_vfsop_mount`

Function:

- `sub_FFFFFE0009478848` (`apfs_vfsop_mount`)

Observed EPERM-relevant deny blocks:

- Root-mount privilege deny:
  - log string: `"%s:%d: not allowed to mount as root\n"`
  - xref site: `0xFFFFFE000947905C`
  - error return: sets `W25 = 1`
- Verification-mount privilege deny:
  - log string: `"%s:%d: not allowed to do a verification mount of %s (is_suser %s ; uid %d)\n"`
  - xref site: `0xFFFFFE0009479CA0`
  - error return: sets `W25 = 1`

Important relation to existing Patch 13:

- At `0xFFFFFE0009479044` (same function), current code is `CMP X0, X0` (patched form),
  which forces the following `B.EQ` path and should bypass one root privilege check in this region.
- Therefore, if JB still reports `mount_apfs ... Operation not permitted`, remaining EPERM candidates
  include other deny branches (including the verification-mount gate path above), not only `handle_get_dev_by_role`.

## Root Cause (Updated, Two-Stage)

Stage 1 (confirmed and mitigated):

- APFS `handle_get_dev_by_role` entitlement/role deny gates were a concrete mount-phase-1 blocker.
- Additive patch now NOPs all three relevant deny branches.

Stage 2 (still under investigation, JB-only):

- DEV control run can pass `mount-phase-1`/`mount-phase-2`.
- JB failures must be analyzed with JB-only artifacts/logs and likely involve JB-only deltas
  (launchd dylib injection, BaseBin hooks, or JB preboot/bootstrap interaction), in addition to any remaining kernel checks.

## Mitigation Implemented

### A) Ramdisk kernel split (updated implementation)

- `scripts/fw_patch_jb.py`
  - no longer creates a ramdisk snapshot file
- `scripts/ramdisk_build.py`
  - derives ramdisk kernel source internally:
    - uses legacy `kernelcache.research.vphone600.ramdisk` if present
    - otherwise derives from pristine CloudOS `kernelcache.research.vphone600`
      under `ipsws/*CloudOS*/` using base `KernelPatcher`
  - builds:
    - `Ramdisk/krnl.ramdisk.img4` from derived/base source
    - `Ramdisk/krnl.img4` from post-JB restore kernel
- `scripts/ramdisk_send.sh`
  - prefers `krnl.ramdisk.img4` when present.

### B) Additive APFS boot-mount gate bypass (new)

- Added new base kernel patch method:
  - `KernelPatchApfsMountMixin.patch_apfs_get_dev_by_role_entitlement()`
- Added to base kernel patch sequence in `scripts/patchers/kernel.py`.
- Behavior:
  - NOPs three deny branches in `handle_get_dev_by_role`
  - does not modify existing filesystem patches (APFS snapshot/seal/graft/mount/sandbox hooks remain unchanged).

### C) JB-only differential identified (for next isolation)

Compared with DEV flow, JB adds unique early-boot risk factors:

- launchd binary gets `LC_LOAD_DYLIB` injection for `/cores/launchdhook.dylib`
- `launchdhook.dylib`/BaseBin environment strings include:
  - `JB_ROOT_PATH`
  - `JB_TWEAKLOADER_PATH`
  - explicit launchdhook startup logs (`hello` / `bye`)
- procursus/bootstrap content is written under preboot hash path (`/mnt5/<hash>/jb-vphone`)

These do not prove causality yet, but they are the primary JB-only candidates after Stage-1 APFS gate mitigation.

## Next Validation

1. Kernel/JB isolation run (requested):
   - `make fw_patch_jb`
   - `make ramdisk_build`
   - `make ramdisk_send`
   - run `cfw_install_dev` (not JB) on this JB-patched firmware baseline
2. Compare normal boot result:
   - If `mount-phase-1/2` succeeds: strong evidence issue is in JB-only userspace phases.
   - If it still fails with `EPERM`: continue kernel/APFS deny-path tracing.
3. If step 2 succeeds, add back JB phases incrementally:
   - first JB-1 (launchd inject + jetsam patch)
   - then JB-2 (preboot bootstrap)
   - then JB-3 (BaseBin hooks)
     and capture first regression point.

## 2026-03-05 Follow-up (Data-Protection / SEP UserClient MACF)

A later failure mode moved past mount-phase and failed in `data-protection`:

- `IOUC AppleSEPUserClient failed MACF ... seputil`
- `Boot task failed: data-protection - exited due to exit(60)`

This was traced to unpatched IOKit MAC policy hook range (`ops[201..210]`) in
the sandbox extended hook set. Mitigation and patch details are documented in:

- `research/boot_data_protection_seputil_macf_investigation.md`

Follow-up (2026-03-06):

- Even after `ops[201..210]` extension, runtime still showed:
  - `IOUC AppleAPFSUserClient failed MACF ...`
  - `IOUC AppleSEPUserClient failed MACF ...`
- A second-stage mitigation was added:
  - `patch_iouc_failed_macf` (central IOUC MACF gate low-risk early return).
