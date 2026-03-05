"""Mixin: KernelJBPatchIoucmacfMixin."""

from .kernel_jb_base import ARM64_OP_IMM, asm


class KernelJBPatchIoucmacfMixin:
    def patch_iouc_failed_macf(self):
        """Bypass IOUserClient MACF deny path at the shared IOUC gate.

        Strategy:
        - Anchor on IOUC "failed MACF"/"failed sandbox" format-string xrefs.
        - Resolve the shared containing function.
        - Require a BL call to a MACF dispatcher-like callee:
          contains `ldr x10, [x10, #0x9e8]` and `blraa/blr x10`.
        - Apply low-risk early return (keep PACIBSP at +0x0):
          mov x0, xzr ; retab

        This bypasses centralized IOUC MACF deny returns (for example
        AppleAPFSUserClient / AppleSEPUserClient).
        """
        self._log("\n[JB] IOUC MACF gate: low-risk early return")

        fail_macf_str = self.find_string(b"IOUC %s failed MACF in process %s")
        if fail_macf_str < 0:
            self._log("  [-] IOUC failed-MACF format string not found")
            return False

        fail_macf_refs = self.find_string_refs(fail_macf_str, *self.kern_text)
        if not fail_macf_refs:
            fail_macf_refs = self.find_string_refs(fail_macf_str)
        if not fail_macf_refs:
            self._log("  [-] no xrefs for IOUC failed-MACF format string")
            return False

        fail_sb_str = self.find_string(b"IOUC %s failed sandbox in process %s")
        fail_sb_refs = []
        if fail_sb_str >= 0:
            fail_sb_refs = self.find_string_refs(fail_sb_str, *self.kern_text)
            if not fail_sb_refs:
                fail_sb_refs = self.find_string_refs(fail_sb_str)

        sb_ref_set = {adrp for adrp, _, _ in fail_sb_refs}

        def _has_macf_dispatch_shape(callee_off):
            callee_end = self._find_func_end(callee_off, 0x600)
            saw_load = False
            saw_call = False
            for off in range(callee_off, callee_end, 4):
                d = self._disas_at(off)
                if not d:
                    continue
                ins = d[0]
                op = ins.op_str.replace(" ", "").lower()
                if ins.mnemonic == "ldr" and ",#0x9e8]" in op and op.startswith("x10,[x10"):
                    saw_load = True
                if ins.mnemonic in ("blraa", "blrab", "blr") and op.startswith("x10"):
                    saw_call = True
                if saw_load and saw_call:
                    return True
            return False

        candidates = []
        for adrp_off, _, _ in fail_macf_refs:
            fn = self.find_function_start(adrp_off)
            if fn < 0:
                continue
            fn_end = self._find_func_end(fn, 0x2000)
            if fn_end <= fn + 0x20:
                continue

            # Require a BL call to a MACF-dispatcher-like function.
            has_dispatch_call = False
            for off in range(fn, fn_end, 4):
                bl_target = self._is_bl(off)
                if bl_target < 0:
                    continue
                if _has_macf_dispatch_shape(bl_target):
                    has_dispatch_call = True
                    break
            if not has_dispatch_call:
                continue

            # Prefer candidates that also reference the sandbox-fail format string.
            score = 0
            for sb_adrp in sb_ref_set:
                if fn <= sb_adrp < fn_end:
                    score += 2

            # Sanity: should branch on w0 before logging failed-MACF.
            has_guard = False
            scan_start = max(fn, adrp_off - 0x100)
            for off in range(scan_start, adrp_off, 4):
                d = self._disas_at(off)
                if not d:
                    continue
                ins = d[0]
                if ins.mnemonic not in ("cbz", "cbnz"):
                    continue
                if not ins.op_str.replace(" ", "").startswith("w0,"):
                    continue
                target = None
                for op in reversed(ins.operands):
                    if op.type == ARM64_OP_IMM:
                        target = op.imm
                        break
                if target and off < target < fn_end:
                    has_guard = True
                    break
            if not has_guard:
                continue

            candidates.append((score, fn, adrp_off, fn_end))

        if not candidates:
            self._log("  [-] no safe IOUC MACF candidate function")
            return False

        # Deterministic pick: highest score, then lowest function offset.
        candidates.sort(key=lambda item: (-item[0], item[1]))
        score, fn, _, _ = candidates[0]
        self._log(f"  [+] candidate fn=0x{fn:X} (score={score})")

        self.emit(fn + 4, asm("mov x0, xzr"), "mov x0,xzr [IOUC MACF gate low-risk]")
        self.emit(fn + 8, bytes([0xFF, 0x0F, 0x5F, 0xD6]), "retab [IOUC MACF gate low-risk]")
        return True
