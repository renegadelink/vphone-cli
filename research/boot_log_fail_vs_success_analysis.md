# Boot Log Comparison Analysis (fail vs success)

Date: 2026-03-06
Scope: compare `/Users/qaq/Desktop/boot.fail.log` and `/Users/qaq/Desktop/boot.success.log` for the current startup failure investigation.

## Executive Verdict

- The fail path is a `launchd` userspace panic caused by `data-protection` task `SIGTRAP`, not an APFS kernel panic.
- The immediate trigger in fail log is that mount could not find the APFS Data volume metadata:
  - `failed to lookup data volume - Attribute not found`
  - `mount: data volume missing, but not required in env: 1`
- APFS itself does load in both logs with the same version (`2632.40.15`) and continues mounting volumes.
- Based on these two logs alone, evidence is stronger for "Data volume discovery/mapping issue" than "APFS patch count too high".

## Key Evidence

1. APFS module load is healthy in both runs

- Fail: `apfs_module_start ... com.apple.filesystems.apfs, v2632.40.15` (line 178)
- Success: same APFS load/version (line 250)
- Interpretation: no direct sign that APFS kext fails to initialize in fail run.

2. First hard divergence is in mount-phase-1 Data volume resolution

- Fail:
  - `failed to lookup data volume - Attribute not found` (line 420)
  - `mount: data volume missing, but not required in env: 1` (line 421)
- Success:
  - `mount: found boot container: /dev/disk1, data volume: /dev/disk1s2 env: 1` (line 423)
- Interpretation: fail run cannot resolve data volume metadata; success run can.

3. data-protection task outcome differs immediately after that

- Fail:
  - `(data-protection) <Error>: exited due to SIGTRAP` (line 432)
  - `Boot task failed: data-protection - exited due to SIGTRAP` (line 433)
  - `userspace panic` follows (line 458)
- Success:
  - `init_data_protection: Gigalocker initialization completed` (line 434)
  - boot continues into `mount-phase-2` and beyond (line 502+)
- Interpretation: the crash is in boot task flow after data volume lookup failure, not in APFS module load.

4. Success path shows APFS warnings that are non-fatal

- `mount: failed to migrate Media Keys, error = c002` (line 522)
- `mount_phase_two ... Overprovision setup failed ... Ignoring...` (line 560)
- Interpretation: APFS/AKS warnings can be tolerated when data volume path is intact; these are not the blocking condition here.

## Additional Differences That Confound Direct "Patch Count" Attribution

- Different host build/hash inputs:
  - vphoned `GIT_HASH` differs (`e4456e9` vs `fd08c43`)
  - binary path differs (`vphone-cli` vs `vphone-cli-dev`)
  - `vphoned` signed hash differs
- Different device identity:
  - ECID differs across logs
- Different APFS checkpoint state:
  - Fail: `cleanly-unmounted`, largest xid `198`
  - Success: `reloading after unclean unmount`, largest xid `491`

These differences mean this is not a strict A/B test of only "APFS patch count".

## Assessment of "APFS patch applied too much?"

Current confidence: low-to-medium for that hypothesis from logs alone.

What logs support:

- The failure does involve APFS mount phase and data-protection.

What logs do not support:

- No APFS module crash/oops/panic.
- No explicit APFS patch integrity failure.
- The strongest fail signal is missing data volume attribute, not APFS code-path abort.

More likely from current evidence:

- APFS container/volume role metadata mismatch, or
- environment/image drift between the two runs, causing different boot task assumptions.

## Suggested Next Validation (minimal and decisive)

1. Re-run with identical binaries and same VM snapshot, toggling only APFS-related patch set.
2. Capture APFS volume-role metadata before boot task (expect `disk1s2` Data role to be discoverable).
3. Compare generated firmware/CFW artifacts checksums between fail/success pipelines.
4. If failure reproduces only with APFS patch delta, then bisect APFS patch subset around data-volume lookup path.

## Bottom Line

From these two logs, the actionable breakpoint is:

- "data volume lookup failed" -> "data-protection SIGTRAP" -> userspace panic.

This is a stronger lead than "APFS patch count over-applied", and should be the first branch to validate.

## Update (Control Run)

New control signal from user:

- Same failure reproduces with `cfw_install` (without JB extras).
- TXM is known working in this control.

Updated implication:

- The prior "JB userspace difference" suspicion should be de-prioritized.
- Current primary suspect becomes kernel delta (especially APFS/IOUC/MACF-related behavior under `mount -P 1`).
