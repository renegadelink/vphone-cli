"""kernel_jb.py — Jailbreak extension patcher for iOS kernelcache."""

import os
import time

from .kernel_jb_base import KernelJBPatcherBase
from .kernel_jb_patch_amfi_trustcache import KernelJBPatchAmfiTrustcacheMixin
from .kernel_jb_patch_amfi_execve import KernelJBPatchAmfiExecveMixin
from .kernel_jb_patch_task_conversion import KernelJBPatchTaskConversionMixin
from .kernel_jb_patch_sandbox_extended import KernelJBPatchSandboxExtendedMixin
from .kernel_jb_patch_post_validation import KernelJBPatchPostValidationMixin
from .kernel_jb_patch_proc_security import KernelJBPatchProcSecurityMixin
from .kernel_jb_patch_proc_pidinfo import KernelJBPatchProcPidinfoMixin
from .kernel_jb_patch_port_to_map import KernelJBPatchPortToMapMixin
from .kernel_jb_patch_vm_fault import KernelJBPatchVmFaultMixin
from .kernel_jb_patch_vm_protect import KernelJBPatchVmProtectMixin
from .kernel_jb_patch_mac_mount import KernelJBPatchMacMountMixin
from .kernel_jb_patch_dounmount import KernelJBPatchDounmountMixin
from .kernel_jb_patch_bsd_init_auth import KernelJBPatchBsdInitAuthMixin
from .kernel_jb_patch_spawn_persona import KernelJBPatchSpawnPersonaMixin
from .kernel_jb_patch_task_for_pid import KernelJBPatchTaskForPidMixin
from .kernel_jb_patch_load_dylinker import KernelJBPatchLoadDylinkerMixin
from .kernel_jb_patch_shared_region import KernelJBPatchSharedRegionMixin
from .kernel_jb_patch_nvram import KernelJBPatchNvramMixin
from .kernel_jb_patch_secure_root import KernelJBPatchSecureRootMixin
from .kernel_jb_patch_thid_crash import KernelJBPatchThidCrashMixin
from .kernel_jb_patch_cred_label import KernelJBPatchCredLabelMixin
from .kernel_jb_patch_syscallmask import KernelJBPatchSyscallmaskMixin
from .kernel_jb_patch_hook_cred_label import KernelJBPatchHookCredLabelMixin
from .kernel_jb_patch_kcall10 import KernelJBPatchKcall10Mixin
from .kernel_jb_patch_iouc_macf import KernelJBPatchIoucmacfMixin


class KernelJBPatcher(
    KernelJBPatchKcall10Mixin,
    KernelJBPatchIoucmacfMixin,
    KernelJBPatchHookCredLabelMixin,
    KernelJBPatchSyscallmaskMixin,
    KernelJBPatchCredLabelMixin,
    KernelJBPatchThidCrashMixin,
    KernelJBPatchSecureRootMixin,
    KernelJBPatchNvramMixin,
    KernelJBPatchSharedRegionMixin,
    KernelJBPatchLoadDylinkerMixin,
    KernelJBPatchTaskForPidMixin,
    KernelJBPatchSpawnPersonaMixin,
    KernelJBPatchBsdInitAuthMixin,
    KernelJBPatchDounmountMixin,
    KernelJBPatchMacMountMixin,
    KernelJBPatchVmProtectMixin,
    KernelJBPatchVmFaultMixin,
    KernelJBPatchPortToMapMixin,
    KernelJBPatchProcPidinfoMixin,
    KernelJBPatchProcSecurityMixin,
    KernelJBPatchPostValidationMixin,
    KernelJBPatchSandboxExtendedMixin,
    KernelJBPatchTaskConversionMixin,
    KernelJBPatchAmfiExecveMixin,
    KernelJBPatchAmfiTrustcacheMixin,
    KernelJBPatcherBase,
):
    _TIMING_LOG_MIN_SECONDS = 10.0

    # Default low-risk schedule.
    _DEFAULT_METHODS = (
        "patch_amfi_cdhash_in_trustcache",      # A1
        "patch_amfi_execve_kill_path",          # A2
        "patch_cred_label_update_execve",       # C21 (low-riskized)
        "patch_hook_cred_label_update_execve",  # C23 (low-riskized)
        "patch_kcall10",                        # C24 (low-riskized)
        "patch_post_validation_additional",     # B5
        "patch_syscallmask_apply_to_proc",      # C22
        "patch_task_conversion_eval_internal",  # A3
        "patch_sandbox_hooks_extended",         # A4
        "patch_iouc_failed_macf",              # A5
        "patch_proc_security_policy",           # B6
        "patch_proc_pidinfo",                   # B7
        "patch_convert_port_to_map",            # B8
    )

    # Validated hit methods that are currently not part of default schedule.
    _OPTIONAL_METHODS = (
        "patch_bsd_init_auth",
        "patch_dounmount",
        "patch_io_secure_bsd_root",
        "patch_load_dylinker",
        "patch_mac_mount",
        "patch_nvram_verify_permission",
        "patch_shared_region_map",
        "patch_spawn_validate_persona",
        "patch_task_for_pid",
        "patch_thid_should_crash",
        "patch_vm_fault_enter_prepare",
        "patch_vm_map_protect",
    )

    # Reserved for future use if a method is re-classified as high-impact.
    _HIGH_RISK_METHODS = ()

    # Reserved for future use if a method becomes no-hit on target kernels.
    _NOHIT_METHODS = ()

    # Compatibility fields used by local tooling/reporting.
    _GROUP_AB_METHODS = _DEFAULT_METHODS
    _GROUP_C_METHODS = ()

    def __init__(self, data, verbose=False):
        super().__init__(data, verbose)
        self.patch_timings = []

    def _run_patch_method_timed(self, method_name):
        before = len(self.patches)
        t0 = time.perf_counter()
        getattr(self, method_name)()
        dt = time.perf_counter() - t0
        added = len(self.patches) - before
        self.patch_timings.append((method_name, dt, added))
        if dt >= self._TIMING_LOG_MIN_SECONDS:
            print(f"  [T] {method_name:36s} {dt:7.3f}s  (+{added})")

    def _run_methods(self, methods):
        for method_name in methods:
            self._run_patch_method_timed(method_name)

    @staticmethod
    def _env_enabled(name):
        v = os.environ.get(name, "").strip().lower()
        return v in ("1", "true", "yes", "on")

    @staticmethod
    def _parse_method_list(raw):
        if not raw:
            return []
        return [item.strip() for item in raw.split(",") if item.strip()]

    def _build_method_plan(self):
        methods = list(self._DEFAULT_METHODS)

        if self._env_enabled("VPHONE_JB_ENABLE_OPTIONAL"):
            methods.extend(self._OPTIONAL_METHODS)
        if self._env_enabled("VPHONE_JB_ENABLE_HIGH_RISK"):
            methods.extend(self._HIGH_RISK_METHODS)

        methods.extend(
            self._parse_method_list(os.environ.get("VPHONE_JB_EXTRA_METHODS", ""))
        )

        disabled = set(
            self._parse_method_list(os.environ.get("VPHONE_JB_DISABLE_METHODS", ""))
        )
        allow_nohit = self._env_enabled("VPHONE_JB_ALLOW_NOHIT")

        final = []
        seen = set()
        for method_name in methods:
            if method_name in seen:
                continue
            if method_name in disabled:
                continue
            if not allow_nohit and method_name in self._NOHIT_METHODS:
                continue
            if not callable(getattr(self, method_name, None)):
                continue
            seen.add(method_name)
            final.append(method_name)
        return tuple(final)

    def _print_timing_summary(self):
        if not self.patch_timings:
            return
        slow_items = [
            item
            for item in sorted(self.patch_timings, key=lambda item: item[1], reverse=True)
            if item[1] >= self._TIMING_LOG_MIN_SECONDS
        ]
        if not slow_items:
            return

        print(
            "\n  [Timing Summary] JB patch method cost (desc, >= "
            f"{self._TIMING_LOG_MIN_SECONDS:.0f}s):"
        )
        for method_name, dt, added in slow_items:
            print(f"    {dt:7.3f}s  (+{added:3d})  {method_name}")

    def find_all(self):
        self._reset_patch_state()
        self.patch_timings = []

        plan = self._build_method_plan()
        self._log(
            "[*] JB method plan: "
            + (", ".join(plan) if plan else "(empty)")
        )
        self._run_methods(plan)
        self._print_timing_summary()

        return self.patches

    def apply(self):
        patches = self.find_all()
        for off, patch_bytes, _ in patches:
            self.data[off : off + len(patch_bytes)] = patch_bytes
        return len(patches)

    # ══════════════════════════════════════════════════════════════
    # Group A: Existing patches (unchanged)
    # ══════════════════════════════════════════════════════════════
