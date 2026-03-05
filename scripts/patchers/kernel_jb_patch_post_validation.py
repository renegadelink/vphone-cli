"""Mixin: KernelJBPatchPostValidationMixin."""

from .kernel_jb_base import ARM64_OP_REG, ARM64_OP_IMM, ARM64_REG_W0, CMP_W0_W0


class KernelJBPatchPostValidationMixin:
    def patch_post_validation_additional(self):
        """Additional postValidation CMP W0,W0 in AMFI code signing path.

        Low-risk strategy:
        1) Prefer the legacy strict matcher.
        2) Fallback to direct `cmp w0,#imm` replacement in AMFI text when
           strict shape is not present on newer kernels.
        """
        self._log("\n[JB] postValidation additional: cmp w0,w0")

        str_off = self.find_string(b"AMFI: code signature validation failed")
        if str_off < 0:
            self._log("  [-] string not found")
            return False

        refs = self.find_string_refs(str_off, *self.amfi_text)
        if not refs:
            refs = self.find_string_refs(str_off)
        if not refs:
            self._log("  [-] no code refs")
            return False

        caller_start = self.find_function_start(refs[0][0])
        if caller_start < 0:
            return False

        bl_targets = set()
        func_end = self._find_func_end(caller_start, 0x2000)
        for scan in range(caller_start, func_end, 4):
            target = self._is_bl(scan)
            if target >= 0:
                bl_targets.add(target)

        patched = 0
        for target in sorted(bl_targets):
            if not (self.amfi_text[0] <= target < self.amfi_text[1]):
                continue
            callee_end = self._find_func_end(target, 0x200)
            for off in range(target, callee_end, 4):
                d = self._disas_at(off, 2)
                if len(d) < 2:
                    continue
                i0, i1 = d[0], d[1]
                if i0.mnemonic != "cmp" or i1.mnemonic != "b.ne":
                    continue
                ops = i0.operands
                if len(ops) < 2:
                    continue
                if ops[0].type != ARM64_OP_REG or ops[0].reg != ARM64_REG_W0:
                    continue
                if ops[1].type != ARM64_OP_IMM:
                    continue
                has_bl = False
                for back in range(off - 4, max(off - 12, target), -4):
                    bt = self._is_bl(back)
                    if bt >= 0:
                        has_bl = True
                        break
                if has_bl:
                    self.emit(off, CMP_W0_W0, f"cmp w0,w0 [postValidation additional]")
                    patched += 1

        if patched == 0:
            # Fallback: patch first `cmp w0,#imm` site in AMFI text.
            # This keeps the change local (single in-function compare rewrite)
            # and avoids shellcode/cave behavior.
            s, e = self.amfi_text
            for off in range(s, e - 4, 4):
                d = self._disas_at(off)
                if not d or d[0].mnemonic != "cmp":
                    continue
                ops = d[0].operands
                if len(ops) < 2:
                    continue
                if ops[0].type != ARM64_OP_REG or ops[0].reg != ARM64_REG_W0:
                    continue
                if ops[1].type != ARM64_OP_IMM:
                    continue
                self.emit(off, CMP_W0_W0, "cmp w0,w0 [postValidation additional fallback]")
                patched = 1
                break

        if patched == 0:
            self._log("  [-] no additional postValidation CMP sites found")
            return False
        return True
