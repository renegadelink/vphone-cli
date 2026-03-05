"""Mixin: KernelJBPatchSyscallmaskMixin."""

from .kernel_jb_base import asm, _rd32, struct


class KernelJBPatchSyscallmaskMixin:
    _PACIBSP_U32 = 0xD503237F

    def _is_syscallmask_legacy_candidate(self, func_off):
        """Match legacy 4-arg prologue shape expected by C22 shellcode."""
        func_end = self._find_func_end(func_off, 0x280)
        if func_end <= func_off or func_end - func_off < 0x80:
            return False

        scan_end = min(func_off + 0xA0, func_end)
        seen_cbz_x2 = False
        seen_mov_x19_x0 = False
        seen_mov_x20_x1 = False
        seen_mov_x21_x2 = False
        seen_mov_x22_x3 = False

        for off in range(func_off, scan_end, 4):
            d = self._disas_at(off)
            if not d:
                continue
            i = d[0]
            op = i.op_str.replace(" ", "")
            if i.mnemonic == "cbz" and op.startswith("x2,"):
                seen_cbz_x2 = True
            elif i.mnemonic == "mov":
                if op == "x19,x0":
                    seen_mov_x19_x0 = True
                elif op == "x20,x1":
                    seen_mov_x20_x1 = True
                elif op == "x21,x2":
                    seen_mov_x21_x2 = True
                elif op == "x22,x3":
                    seen_mov_x22_x3 = True

        return (
            seen_cbz_x2
            and seen_mov_x19_x0
            and seen_mov_x20_x1
            and seen_mov_x21_x2
            and seen_mov_x22_x3
        )

    def _find_syscallmask_apply_func(self):
        """Find _syscallmask_apply_to_proc.

        Prefer symbol hit. If strict legacy shape is absent, still allow
        symbol-based low-risk in-function patching on newer layouts.
        """
        sym_off = self._resolve_symbol("_syscallmask_apply_to_proc")
        if sym_off >= 0:
            return sym_off

        str_off = self.find_string(b"syscallmask.c")
        if str_off < 0:
            return -1

        refs = self.find_string_refs(str_off, *self.kern_text)
        if not refs:
            refs = self.find_string_refs(str_off)
        if not refs:
            return -1

        base_funcs = sorted(
            {
                self.find_function_start(ref[0])
                for ref in refs
                if self.find_function_start(ref[0]) >= 0
            }
        )
        if not base_funcs:
            return -1

        candidates = set(base_funcs)
        for base in base_funcs:
            start = max(base - 0x200, self.sandbox_text[0], self.kern_text[0])
            end = min(base + 0x200, self.sandbox_text[1], self.kern_text[1])
            for off in range(start, end, 4):
                if _rd32(self.raw, off) == self._PACIBSP_U32:
                    candidates.add(off)

        ordered = sorted(
            candidates, key=lambda c: min(abs(c - b) for b in base_funcs)
        )
        for cand in ordered:
            if self._is_syscallmask_legacy_candidate(cand):
                return cand

        # Low-risk fallback for newer layouts: use nearest anchor function.
        return base_funcs[0]

    def _find_last_branch_target(self, func_off):
        """Find the last BL/B target in a function."""
        func_end = self._find_func_end(func_off, 0x280)
        for off in range(func_end - 4, func_off, -4):
            target = self._is_bl(off)
            if target >= 0:
                return off, target
            val = _rd32(self.raw, off)
            if (val & 0xFC000000) == 0x14000000:
                imm26 = val & 0x3FFFFFF
                if imm26 & (1 << 25):
                    imm26 -= 1 << 26
                target = off + imm26 * 4
                if self.kern_text[0] <= target < self.kern_text[1]:
                    return off, target
        return -1, -1

    def _resolve_syscallmask_helpers(self, func_off):
        """Resolve zalloc/filter helpers with panic-target rejection."""
        panic = self.panic_off
        zalloc_off = self._resolve_symbol("_zalloc_ro_mut")
        filter_off = self._resolve_symbol("_proc_set_syscall_filter_mask")

        func_end = self._find_func_end(func_off, 0x280)

        if zalloc_off < 0:
            for off in range(func_off, func_end, 4):
                target = self._is_bl(off)
                if target < 0 or target == panic:
                    continue
                if len(self.bl_callers.get(target, [])) >= 50:
                    zalloc_off = target
                    break

        if filter_off < 0:
            _, filter_off = self._find_last_branch_target(func_off)

        if (
            zalloc_off < 0
            or filter_off < 0
            or zalloc_off == panic
            or filter_off == panic
            or zalloc_off == filter_off
        ):
            return -1, -1

        return zalloc_off, filter_off

    def _find_syscallmask_inject_bl(self, func_off, zalloc_off):
        """Find BL site that will be redirected into the cave."""
        func_end = self._find_func_end(func_off, 0x280)
        for off in range(func_off, min(func_off + 0x120, func_end), 4):
            if self._is_bl(off) == zalloc_off:
                return off
        return -1

    def patch_syscallmask_apply_to_proc(self):
        """Low-risk early-return patch for _syscallmask_apply_to_proc.

        Replaces function body head with:
          mov x0, xzr
          retab
        This avoids code caves, syscall trampolines, and large shellcode
        while guaranteeing deterministic behavior on current vphone600.
        """
        self._log("\n[JB] _syscallmask_apply_to_proc: low-risk early return")

        func_off = self._find_syscallmask_apply_func()
        if func_off < 0:
            self._log(
                "  [-] _syscallmask_apply_to_proc not found (legacy signature mismatch, fail-closed)"
            )
            return False

        func_end = self._find_func_end(func_off, 0x200)
        if func_end <= func_off + 8:
            self._log("  [-] function too small for in-place early return patch")
            return False

        self.emit(
            func_off + 4,
            asm("mov x0, xzr"),
            "mov x0,xzr [_syscallmask_apply_to_proc low-risk]",
        )
        self.emit(
            func_off + 8,
            bytes([0xFF, 0x0F, 0x5F, 0xD6]),  # retab
            "retab [_syscallmask_apply_to_proc low-risk]",
        )
        return True
