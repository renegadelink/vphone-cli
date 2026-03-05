# mount `-P 1` Failure / Hang Matrix (IDA)

Date: 2026-03-06  
Target: `research/artifacts/launchd_23B85/mount.from_vm_disk.current`

## What `mount -P 1` actually does

Main entry: `start` @ `0x100003DC8`

For `-P 1` (phase-1):

1. Parse phase from `-P` and set global `dword_1000101F4 = 1`.
2. Call `setfsent()` and iterate fstab entries.
3. Resolve boot container/device via `sub_100003480` (`APFSContainerGetBootDevice`).
4. Resolve data volume via `sub_100003674` (`APFSVolumeRoleFind`).
5. Print either:
   - `mount: found boot container: ..., data volume: ..., env: ...`
   - or `mount: data volume missing, but not required in env: ...`
6. Continue mounting entries with pass number == phase via `sub_1000045B0` (exec `mount_<fstype>`).

Important: for phase-1, missing data volume is normally **not fatal**.

### Critical implementation detail (IDA)

- `sub_100003674` calls:
  - `APFSVolumeRoleFind(<bootdev>, 0x40, &outArray)`
- If return != 0:
  - prints `failed to lookup data volume - %s` with `strerror(ret & 0x3fff)`
- `Attribute not found` in your log maps to Darwin `ENOATTR(93)`.

### Important caveat on `93` provenance

- Confirmed fact:
  - `mount` sees `APFSVolumeRoleFind` return value whose low 14 bits are `93`.
- Not yet proven:
  - that kernel returns `93` directly.
- Also plausible:
  - APFS userspace layer maps another kernel/APFS status to `ENOATTR` before returning to `mount`.

## All plausible causes for phase-1 fail/hang

### A) Early argument / mode errors (immediate fail)

1. Invalid `-P` value
   - message: `-P flag requires a valid mount phase number`
   - location: `start` (`0x1000039C4`..`0x100003A70`)

2. Invalid invocation shape (bad argv combination)
   - falls into usage path (`sub_1000043B0`)

### B) Boot container / APFS role lookup path

1. Cannot read filesystem info from IORegistry (`os_env_type`)
   - message: `failed to get filesystem info`
   - function: `sub_100003480`

2. `APFSContainerGetBootDevice` failure
   - message: `failed to get boot device - ...` (with retry loop outside restore env)
   - function: `sub_100003480`

3. `APFSVolumeRoleFind` failure
   - message: `failed to lookup data volume - ...`
   - function: `sub_100003674`

4. Multiple Data volumes found
   - message: `found multiple data volumes`
   - function: `sub_100003674`

Note:

- phase-1 usually continues after (3)/(4).
- phase-2 has stricter fatal behavior on missing data volume in env=1.

### C) fstab traversal / entry filtering issues

1. `setfsent()` failure
   - message: `mount: can't get filesystem checklist`
   - fatal for phase run

2. Entry type / spec/path invalidity
   - examples:
     - `%s: invalid special file or file system.`
     - `%s: unknown special file or file system.`
     - `You must specify a filesystem type with -t.`

These are input/config failures before actual fs-specific helper mount.

### D) Per-filesystem mount helper failures (major phase-1 failure source)

Dispatcher: `sub_1000045B0`

1. FSKit path failure (`sub_100000BC0`)
   - messages:
     - `File system named %s not found`
     - `File system named %s unable to mount`
     - `FSKit unavailable`

2. `fork()` / `waitpid()` / child process control failures
   - messages include wait/fork warnings in helper path

3. `exec` failure for `mount_<fstype>` helpers
   - tries `/sbin/mount_<fstype>` then fallback paths under `/System/Library/Filesystems/...`
   - if all fail -> returns mapped failure code

4. Helper exits non-zero or gets signaled
   - parent treats as mount failure and propagates code

This bucket is the most common direct reason phase-1 exits non-zero.

### E) Ramdisk special path failures (if ramdisk entry is hit in phase-1)

Ramdisk path: `sub_100002688` + `sub_100002C34` + command wrapper `sub_100002EA4`

Possible failures:

1. preflight format/option parsing fail (`Ramdisk fstab not in expected format.`)
2. `mount_tmpfs` exec or command-run failures
3. copyfile / final mount / umount failures

Not always relevant, but can fail phase-1 if fstab phase-1 includes ramdisk flow.

### F) Kernel / IOKit policy-deny mediated failures (high-probability in your current repro)

From your runtime evidence and control results:

1. `mount` process can hit IOUC/MACF deny path on APFS UserClient access.
2. userspace may surface this as role/attribute lookup failure string, while root cause is kernel-side deny/altered return.

Given:

- same failure reproduces with non-JB `cfw_install`
- TXM known-good

current priority remains kernel delta analysis.

## Kernel patch candidates for this specific signature (ranked)

### 1) Base patch #16 (`patch_apfs_get_dev_by_role_entitlement`) — highest

Why high:

- It directly targets APFS get-dev-by-role gate, which is exactly adjacent to `APFSVolumeRoleFind` behavior.
- It NOPs conditional branches by pattern heuristics; a false match can silently alter return path while keeping system alive.
- Symptom shape fits: boot container lookup can still succeed, but role lookup returns `ENOATTR`.
- Live-kernel validation status:
  - patch #16 is present (all 3 target branches are `nop` at runtime).
  - therefore current question is semantic side effect, not "patch missing".

### 2) Base sandbox hook patch (`patch_sandbox_hooks`) — medium

Why medium:

- Touches mount/vnode MACF paths by ops-table index.
- If ops index resolution drifts, wrong function may be stubbed and produce semantic corruption instead of crash.

### 3) Base APFS mount checks (#13/#14) — lower for this exact error

Why lower:

- These primarily alter mount authorization/upgrade checks.
- Less directly tied to role-attribute lookup API return code, but still in APFS mount vicinity.

## What to do next (action order)

1. Confirm userland return-site:
   - break at `sub_1000036C0` (`BL _APFSVolumeRoleFind`) and inspect `w0` after return.
   - expected failing value path: `w0 & 0x3fff == 93`.
2. Correlate with kernel-side return path in the same boot:
   - break/trace APFS kernel role lookup function return (`handle_get_dev_by_role` path) and record final returned `w0`.
   - determine whether kernel returns `93`, `22`, or other value when userspace later sees `93`.
3. Correlate with kernel log at same timestamp:
   - look for `IOUC AppleAPFSUserClient failed MACF in process mount`.
4. Do base-kernel patch isolation first (not JB methods):
   - run with base patch #16 disabled (or reverted) while keeping others unchanged.
   - if failure clears, root cause is narrowed to entitlement-bypass matcher.
5. If #16 is not root cause, isolate base sandbox hook patch.
6. Only then continue to JB-only methods (`VPHONE_JB_DISABLE_METHODS`), because your latest control says non-JB install still reproduces.

## Hang/stall-specific points (not just hard fail)

1. Boot-device lookup retry loop (`APFSContainerGetBootDevice`) with sleep retries.
2. Child `mount_<fstype>` helper blocking in kernel/IO path (parent waiting in `waitpid`).
3. External command wrapper (`sub_100002EA4`) blocking while waiting for command output/exit.

These produce "looks stuck" behavior even before explicit non-zero exit.

## Practical triage checklist for phase-1

1. Confirm exact failing subpath:
   - preflight/APFS lookup vs helper mount vs waitpid/exec.
2. Correlate with kernel log at same timestamp:
   - especially `IOUC AppleAPFSUserClient ... mount`.
3. Separate:
   - non-fatal data-volume warning in phase-1
   - true fatal return path that makes launchd panic on `RequireSuccess`.
