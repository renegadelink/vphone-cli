# Boot Hang Focus: B19 + (B11/B12) Strategy Comparison

Date: 2026-03-05
Target binary family: `kernelcache.research.vphone600` (iOS 26.1 / 23B85)

## Final Outcome (2026-03-05)

This investigation is complete for the current delivery gate (bootability).

- B19/MNT strategy switching did **not** recover boot:
  - matrix artifact: `vm/ab_matrix_b19_mnt_20260305_034127.csv`
  - result: 9/9 combinations failed (`code=2`, watchdog timeout)
- JB-only bisect isolated a stable bootable subset:
  - PASS: `A1-A4`
  - PASS: `A1-A4 + B5-B8`
  - FAIL: tested combinations including `B9+`
- Current boot-safe default in `kernel_jb.py`:
  - enabled: `A1-A4 + B5-B8`
  - disabled: `B9-B20`, `C21-C24`
- E2E success evidence:
  - `vm/testing_exec_watch_20260305_050051.log`
  - `vm/testing_exec_watch_20260305_050146.log`
  - both reached restore-ready markers (USB mux activated + waiting-for-host gate)

## Scope

This note compares two patching styles for boot-hang triage:

1. B19 (`_IOSecureBSDRoot`) patch style mismatch:
   - upstream known-to-work fixed site
   - current dynamic patcher site
2. B11/B12 (`___mac_mount` / `_dounmount`) patch style mismatch:
   - upstream fixed-site patches
   - current dynamic strict-shape patches

The goal is to make A/B testing reproducible with concrete trigger points, pseudocode, and expected runtime effects.

---

## 1) B19 `_IOSecureBSDRoot` mismatch

### 1.1 Trigger points (clean kernel)

- `0x0128B598` (`VA 0xFFFFFE000828F598`) in `sub_FFFFFE000828F42C`
  - before: `b.ne #0x128b5bc`
  - upstream patch: `b #0x128b5bc` (`0x14000009`)
- `0x01362090` (`VA 0xFFFFFE0008366090`) in `sub_FFFFFE0008366008`
  - before: `cbz w0, #0x1362234`
  - current dynamic patch: `b #0x1362234` (`0x14000069`)

Current patched checkpoint confirms:

- `0x01362090` is patched (`b`)
- `0x0128B598` remains unpatched (`b.ne`)

### 1.2 Function logic and pseudocode

#### A) Upstream site function (`sub_FFFFFE000828F42C`)

High-level logic:

1. query `"SecureRootName"` from `IOPlatformExpert`
2. run provider call
3. release objects
4. if return code equals `0xE00002C1`, branch to fallback path (`sub_FFFFFE0007C6AA58`)

Pseudocode:

```c
ret = IOPlatformExpert->call("SecureRootName", ...);
release(...);
if (ret == 0xE00002C1) {
    return fallback_path();
}
return ret;
```

Patch effect at `0x128B598` (`b.ne -> b`):

- always take fallback path, regardless whether `ret == 0xE00002C1`.

#### B) Dynamic site function (`sub_FFFFFE0008366008`)

Key branch:

- `0x136608C`: callback for `"SecureRoot"`
- `0x1366090`: `cbz w0, #0x1362234` (branch into `"SecureRootName"` block)
- `0x1366234` onward: `"SecureRootName"` handling block

Pseudocode:

```c
if (matches("SecureRoot")) {
    ok = callback("SecureRoot");
    if (ok == 0) goto SecureRootNameBlock;  // cbz w0
    // SecureRoot success/failure handling path
}

SecureRootNameBlock:
if (matches("SecureRootName")) {
    // name-based validation + state sync
}
```

Patch effect at `0x1362090` (`cbz -> b`):

- always jump into `SecureRootNameBlock`, regardless `ok`.

### 1.3 A/B variants to test

1. `B19-A` (upstream helper only):
   - patch only `0x128B598`
   - keep `0x1362090` original
2. `B19-B` (dynamic main only):
   - patch only `0x1362090`
   - keep `0x128B598` original
3. `B19-C` (both):
   - patch both sites

### 1.4 Expected observables

- Boot logs around:
  - `apfs_find_named_root_snapshot_xid`
  - `Need authenticator (81)`
  - transition into init / panic frame
- Panic signatures:
  - null-deref style FAR near low address (for current failure class)
  - stack path involving mount/security callback chain

---

## 2) B11/B12 (`___mac_mount` / `_dounmount`) mismatch

### 2.1 Trigger points (clean kernel)

#### Upstream fixed-offset style

- `0x00CA5D54`: `tbnz w28, #5, #0xca5f18` -> `nop`
- `0x00CA5D88`: `ldrb w8, [x8, #1]` -> `mov x8, xzr`
- `0x00CA8134`: `bl #0xc92ad8` -> `nop`

#### Current dynamic style (checkpoint)

- `0x00CA4EAC`: `cbnz w0, #0xca4ec8` -> `nop` (B11)
- `0x00CA81FC`: `bl #0xc9bdbc` -> `nop` (B12)

And in checkpoint:

- upstream sites remain original (`0xCA5D54`, `0xCA5D88`, `0xCA8134` unchanged)
- dynamic sites are patched (`0xCA4EAC`, `0xCA81FC` are `nop`)

### 2.2 Function logic and pseudocode

#### A) `___mac_mount`-related branch (dynamic site near `0xCA4EA8`)

Disassembly window:

- `0xCA4EA8`: `bl ...`
- `0xCA4EAC`: `cbnz w0, deny`
- deny target writes non-zero return (`mov w0, #1`)

Pseudocode:

```c
ret = mac_policy_check(...);
if (ret != 0) {   // cbnz w0
    return EPERM_like_error;
}
continue_mount();
```

Dynamic patch (`0xCA4EAC -> nop`) effect:

- ignore `ret != 0` branch and continue mount path.

#### B) Upstream `___mac_mount` two-site style (`0xCA5D54`, `0xCA5D88`)

Disassembly window:

- `0xCA5D54`: `tbnz w28, #5, ...`
- `0xCA5D88`: `ldrb w8, [x8, #1]`

Pseudocode (behavioral interpretation):

```c
if (flag_bit5_set(w28)) goto restricted_path;
w8 = *(u8 *)(x8 + 1);
...
```

Upstream patches:

- remove bit-5 gate branch (`tbnz -> nop`)
- force register state (`ldrb -> mov x8, xzr`)

This is broader state manipulation than dynamic deny-branch patching.

#### C) `_dounmount` path

Upstream site:

- `0xCA8134`: `bl #0xc92ad8` -> `nop`

Dynamic site:

- `0xCA81FC`: `bl #0xc9bdbc` -> `nop`

Pseudocode (generic):

```c
... prepare args ...
ret = mac_or_policy_call_X(...);   // site differs between two strategies
...
ret2 = mac_or_policy_call_Y(...);
```

Difference:

- upstream and dynamic disable different call sites in unmount path;
- not equivalent by construction.

### 2.3 A/B variants to test

1. `MNT-A` (upstream-only style):
   - apply `0xCA5D54`, `0xCA5D88`, `0xCA8134`
   - keep `0xCA4EAC`, `0xCA81FC` original
2. `MNT-B` (dynamic-only style):
   - apply `0xCA4EAC`, `0xCA81FC`
   - keep `0xCA5D54`, `0xCA5D88`, `0xCA8134` original
3. `MNT-C` (both styles):
   - apply all five sites

---

## 3) Combined test matrix (recommended)

For minimal triage noise, run a 3x3 matrix:

- B19 mode: `B19-A`, `B19-B`, `B19-C`
- mount mode: `MNT-A`, `MNT-B`, `MNT-C`

Total 9 combinations, each from the same clean baseline kernel.

Record per run:

1. last APFS logs before failure/success
2. whether `Need authenticator (81)` appears
3. panic presence and panic PC/FAR
4. whether init proceeds past current hang point

---

## 4) Historical A/B Knobs (used during triage, now removed)

During the triage phase, temporary runtime knobs were introduced to toggle
upstream-vs-dynamic strategies for B11/B12/B13/B14/B19 and execute the matrix.

Those knobs are no longer part of the default runtime path after stabilization;
the shipped default now hard-selects the boot-safe subset (`A1-A4 + B5-B8`).

The triage results from those knobs are preserved in this document and in:

- `vm/ab_matrix_b19_mnt_20260305_034127.csv`
- `TODO.md` (Boot Hang Research + Progress Update sections)
- `research/00_patch_comparison_all_variants.md` (Kernelcache section)

---

## 5) Practical note

Do not mix incremental patching across already-patched binaries when comparing these modes.
Always regenerate from clean baseline before each combination, otherwise branch-site interactions can mask true causality.

---

## 6) Additional non-equivalent points (beyond B19/B11/B12)

This section answers "还有没有别的不一样的" with boot-impact-focused mismatches.

### 6.1 B13 `_bsd_init auth` is not the same logical site

#### Trigger points

- upstream fixed site: `0x00F6D95C` in `sub_FFFFFE0007F6D2B8`
- current dynamic site: `0x00FA2A78` in `sub_FFFFFE0007FA2838`

#### Function logic (high level)

- `sub_FFFFFE0007F6D2B8` is a workqueue/thread-call state machine.
- `sub_FFFFFE0007FA2838` is another lock/CAS-heavy control path.

Neither decompilation corresponds to `_bsd_init` body semantics directly.

#### Pseudocode (site-level)

`0xF6D95C` neighborhood:

```c
...
call unlock_or_wakeup(...);   // BL at 0xF6D95C
...
```

`0xFA2A78` neighborhood:

```c
...
stats_counter++;
x2 = x9;                      // MOV at 0xFA2A78
cas_release(lock, x2, 0);
...
```

#### Risk

- This is a strong false-equivalence signal.
- If this patch is intended as `_bsd_init` auth bypass, current dynamic hit should be treated as suspect.

### 6.2 B14 `_spawn_validate_persona` strategy changed from 2xNOP to forced branch

#### Trigger points

- upstream fixed sites: `0x00FA7024`, `0x00FA702C` (same function `sub_FFFFFE0007FA6F7C`)
- current dynamic site: `0x00FA694C` (function `sub_FFFFFE0007FA6858`)

#### Function logic and loop relevance

In `sub_FFFFFE0007FA6858`, there is an explicit spin loop:

- `0xFA6ACC`: `LDADD ...`
- `0xFA6AD4`: `B.EQ 0xFA6ACC` (self-loop)

Pseudocode:

```c
do {
    old = atomic_fetch_add(counter, 1);
} while (old == target);   // tight spin at 0xFA6ACC/0xFA6AD4
```

And same function calls:

- `sub_FFFFFE0007B034E4` (at `0xFA6A94`)
- `sub_FFFFFE0007B040CC` (at `0xFA6AA8`)

Your panic signature previously mapped into this call chain, so this mismatch is high-priority for 100% CPU / hang triage.

### 6.3 B9 `_vm_fault_enter_prepare` does not hit the same function

#### Trigger points

- upstream fixed site: `0x00BA9E1C` in `sub_FFFFFE0007BA9C48`
- current dynamic site: `0x00BA9BB0` in `sub_FFFFFE0007BA9944`

#### Pseudocode (site-level)

`0xBA9E1C`:

```c
// parameter setup right before BL
ldp x4, x5, [sp, ...];
bl helper(...);
```

`0xBA9BB0`:

```c
if (w25 == 3) w21 = 2; else w21 = w25;   // csel
```

These are structurally unrelated.

### 6.4 B10 `_vm_map_protect` site differs in same large function

#### Trigger points

- upstream fixed site: `0x00BC024C`
- current dynamic site: `0x00BC012C`
- both inside `sub_FFFFFE0007BBFA48`

#### Pseudocode (site-level)

`0xBC012C`:

```c
perm = cond ? perm_a : perm_b;   // csel
```

`0xBC024C`:

```c
// different control block; not the same selection point
...
```

Even in the same function, these are not equivalent branch gates.

### 6.5 B15 `_task_for_pid` and B17 shared-region are also shifted

#### Trigger points

- B15 upstream: `0x00FC383C` (`sub_FFFFFE0007FC34B4`)
- B15 dynamic: `0x00FFF83C` (`sub_FFFFFE0007FFF824`)

- B17 upstream: `0x010729CC`
- B17 dynamic: `0x01072A88`
- both in `sub_FFFFFE000807272C`, but not same instruction role

#### Risk

- These are unlikely to explain early APFS/init mount failure alone, but they are still non-equivalent and should not be assumed interchangeable.

---

## 7) Practical triage order for 100% virtualization CPU

Given current evidence, prioritize:

1. B14 strategy A/B first (upstream `0xFA7024/0xFA702C` vs dynamic `0xFA694C`).
2. B13 strategy A/B next (`0xF6D95C` vs `0xFA2A78`).
3. Then B19 and MNT matrix.

Reason: B14 path contains a known tight spin construct and directly calls the function chain previously observed in panic mapping.

---

## 8) Normal boot baseline signature (for pass/fail triage)

Use the following runtime markers as "normal startup reached restore-ready stage" baseline:

1. USB bring-up checkpoint completes:
   - `CHECKPOINT END: MAIN:[0x040E] enable_usb`
2. Network checkpoint enters and exits without device requirement:
   - `CHECKPOINT BEGIN: MAIN:[0x0411] config_network_interface`
   - `no device required to enable network interface, skipping`
   - `CHECKPOINT END: MAIN:[0x0411] config_network_interface`
3. Restore daemon enters host-wait state:
   - `waiting for host to trigger start of restore [timeout of 120 seconds]`
4. USB/NCM path activates and host loopback socket churn appears:
   - `IOUSBDeviceController::setupDeviceSetConfiguration: configuration 0 -> 1`
   - `AppleUSBDeviceMux::message - kMessageInterfaceWasActivated`
   - repeated `sock ... accepted ... 62078 ...` then `sock ... closed`
5. BSD network interface bring-up for `anpi0` succeeds:
   - `configureDatagramSizeOnBSDInterface() [anpi0] ... returning 0x00000000`
   - `enableBSDInterface() [anpi0], returning 0x00000000`
   - `configureIPv6LLOnBSDInterface() [anpi0], IPv6 enable returning 0x00000000`
   - `disableTrafficShapingOnBSDInterface() [anpi0], disable traffic shaping returning 0x00000000`

Practical rule:

- If A/B variant run reaches marker #3 and then shows #4/#5 progression, treat it as "boot path not stuck in early kernel loop".
- If run stalls before marker #1/#2 completion or never reaches #3, prioritize kernel-side loop/panic investigation.

---

## 9) Why the failing sets are currently excluded

Short answer: they are not equivalent rewrites on this firmware, and multiple
sites land in different control contexts than expected upstream references.

IDA-backed findings used for exclusion:

1. B9 differs by function, not just offset:
   - dynamic `0xBA9BB0` in `sub_FFFFFE0007BA9944`
   - upstream `0xBA9E1C` in `sub_FFFFFE0007BA9C48`
2. B10 is same large function but different decision blocks:
   - dynamic `0xBC012C` vs upstream `0xBC024C` in `sub_FFFFFE0007BBFA48`
3. B13 differs by function and behavior:
   - dynamic `0xFA2A78` in `sub_FFFFFE0007FA2838`
   - upstream `0xF6D95C` in `sub_FFFFFE0007F6D2B8`
4. B14 dynamic path sits in the spin-loop-containing function:
   - `sub_FFFFFE0007FA6858` has `0xFA6ACC`/`0xFA6AD4` tight loop
   - same path calls `sub_FFFFFE0007B034E4` and `sub_FFFFFE0007B040CC`

Given this mismatch profile, enabling B9+ as a default set is high risk for
boot regressions until each method is re-derived and validated individually on
the exact kernel build.

---

## 10) Final operational state

- Default JB boot profile: `A1-A4 + B5-B8` only
- Verified by `BASE_PATCH=jb make testing_exec` reproducibility runs:
  - `vm/testing_exec_watch_20260305_050051.log`
  - `vm/testing_exec_watch_20260305_050146.log`
- Delivery stance:
  - prioritize bootability and deterministic restore-ready progression
  - reintroduce B9+ / Group C only behind per-method revalidation

---

## 11) New Field Finding: "restore done but system still not fully up" (`make boot`)

Source: interactive serial output from `make boot` on 2026-03-05 (user report).

### 11.1 What the log proves

This run is **not** failing at the old restore-ready gate and **not** the old
early kernel boot-hang class.

Observed progression:

1. APFS root/data/xART/preboot mounts complete in kernel/userspace handoff.
2. `launchd` starts and executes boot tasks.
3. `mount-phase-1`, `mount-phase-2`, `finish-restore`, `init-with-data-volume`,
   `keybag`, `usermanagerd` tasks are reached.
4. Log shows:
   - `Early boot complete. Continuing system boot.`
   - `hello from launchdhook.dylib` / `bye from launchdhook.dylib`

So the pipeline already crossed into JB userspace initialization.

### 11.2 Suspicious signals in this run

1. Early `launchd` assertion:
   - `com.apple.xpc.launchd ... assertion failed ... 0xffffffffffffffff`
2. Ignition warning:
   - `libignition: cryptex1 sniff: ignition failed: 8`
   - then fallback path continues (`ignition disabled`) and boot tasks proceed.
3. `vphoned` host side repeatedly reports:
   - `Connection reset by peer`
   - indicates daemon channel is not yet stable/ready during this phase.

### 11.3 Most likely fault domain (ranked)

1. **JB-1 launchd modification path (highest probability)**:
   - `patch-launchd-jetsam` dynamic branch rewrite may select an incorrect
     conditional in some launchd builds.
   - `inject-dylib /cores/launchdhook.dylib` adds early runtime side effects.
   - The assertion appears in `launchd` startup window, matching this stage.
2. **JB hook/runtime environment coupling**:
   - `JB_ROOT_PATH` and BaseBin hook expectations under preboot hash path.
   - If path/state is incomplete, startup can degrade without immediate kernel panic.
3. **Less likely: kernel B9+ regression**
   - Current default already excludes B9+ and this log clearly reaches deep
     userspace boot tasks, so this symptom class is different from earlier
     watchdog/restore-gate failures.

### 11.4 Practical triage to confirm

Use same restored disk and isolate JB userspace phases:

1. Baseline control:
   - Boot with dev/regular userspace flow (no JB-1 launchd dylib injection).
2. Re-enable only JB-1:
   - apply jetsam patch alone first, then add dylib injection.
3. Add JB-2/JB-3 incrementally:
   - procursus bootstrap, then BaseBin hooks.
4. Capture first regression point and lock to the exact phase.

### 11.5 Conclusion for this report

- Current symptom ("restore completes but cannot fully start") is now best
  modeled as a **post-restore userspace startup regression**, centered around
  JB launchd modification/hook stages, not the previous kernel early-boot hang.

---

## 12) Failed vs Successful Boot Log Comparison (same device class, 2026-03-05)

Compared inputs:

- Failing side: `vphone-cli` (startup-hang-fix branch) user-provided `make boot` log.
- Successful side: `vphone-cli-dev` (main) user-provided `make boot` log.

### 12.1 Signals that appear in both logs (low-priority/noise for this issue)

The following lines appear on the successful boot too, so they are unlikely to
be the direct blocker for "cannot fully start":

1. `apfs_find_named_root_snapshot_xid ... No such file or directory (2)`
2. `TXM [Error]: selector: 45 | 78` and `failed to set boot uuid ... 78`
3. `libignition ... cryptex1 sniff: ignition failed: 8` then `ignition disabled`
4. `MKB_INIT: No system keybag found on filesystem.`
5. `mount: failed to migrate Media Keys, error = c002`
6. `Overprovision setup failed ... Ignoring...`

These are therefore weak root-cause candidates for this specific regression.

### 12.2 Differential signals (high-value)

Only/primarily observed in failing run:

1. Early `launchd` assertion:
   - `assertion failed ... launchd + 59944 ... 0xffffffffffffffff`
2. JB launchd hook footprint:
   - `hello from launchdhook.dylib`
   - `set JB_ROOT_PATH = /private/preboot/<hash>/jb-vphone/procursus`
3. Host control channel never stabilizes to a healthy daemon session
   before manual stop (`Connection reset by peer` keeps repeating).

Observed in successful run (and absent in failing excerpt):

1. Host eventually reaches:
   - `[control] connected to vphoned v1 ...`
   - `[control] pushing update ...`
2. No corresponding early `launchd` assertion line in provided success log.

### 12.3 Most likely causes (ranked by differential evidence)

1. **`patch-launchd-jetsam` dynamic hit risk (top suspect)**  
   The patcher selects a conditional branch dynamically using string xref +
   backward window + return-block heuristic. A wrong branch rewrite can produce
   launchd internal assertion failures while still allowing partial boot-task logs.

2. **`launchd` dylib injection (`/cores/launchdhook.dylib`) side effects**  
   Hook runs very early in launchd lifecycle; if environment/setup assumptions
   are not met, boot can degrade without immediate kernel panic.

3. **JB-1 combined effect (jetsam patch + dylib injection), not kernel B9+**  
   Kernel path already reaches deep userspace tasks in both cases; this no longer
   matches the previous watchdog/restore-gate kernel hang signature.

### 12.4 Recommended isolation sequence (to convert suspicion -> proof)

Use same restored disk, only vary JB-1 components:

1. `launchd` unmodified control.
2. Apply jetsam patch only.
3. Apply dylib injection only.
4. Apply both (current JB-1).

Record for each:

- whether `launchd assertion failed ... 0xffffffffffffffff` appears
- whether `[control] connected to vphoned v1` appears
- time to first stable userspace service set.
