"""Mixin: KernelJBPatchHookCredLabelMixin."""

from .kernel_jb_base import asm, _rd32

PACIBSP = bytes([0x7F, 0x23, 0x03, 0xD5])  # 0xD503237F


class KernelJBPatchHookCredLabelMixin:
    def _find_vnode_getattr_via_string(self):
        """Find vnode_getattr by locating a caller function via string ref.

        The string "vnode_getattr" appears in format strings like
        "%s: vnode_getattr: %d" inside functions that CALL vnode_getattr.
        We find such a caller, then extract the BL target near the string
        reference to get the real vnode_getattr address.

        Previous approach: find_string → find_string_refs → find_function_start
        was wrong because it returned the CALLER (e.g. an AppleImage4 function)
        instead of vnode_getattr itself.
        """
        str_off = self.find_string(b"vnode_getattr")
        if str_off < 0:
            return -1

        refs = self.find_string_refs(str_off)
        if not refs:
            return -1

        # The string ref is inside a function that calls vnode_getattr.
        # Scan backward from the string ref for a BL instruction — the
        # nearest preceding BL is very likely the BL vnode_getattr call
        # (the error message prints right after the call fails).
        ref_off = refs[0][0]  # ADRP offset
        for scan_off in range(ref_off - 4, ref_off - 64, -4):
            if scan_off < 0:
                break
            insn = _rd32(self.raw, scan_off)
            if (insn >> 26) == 0x25:  # BL opcode
                imm26 = insn & 0x3FFFFFF
                if imm26 & (1 << 25):
                    imm26 -= 1 << 26  # sign extend
                target = scan_off + imm26 * 4
                if any(s <= target < e for s, e in self.code_ranges):
                    self._log(
                        f"  [+] vnode_getattr at 0x{target:X} "
                        f"(via BL at 0x{scan_off:X}, "
                        f"near string ref at 0x{ref_off:X})"
                    )
                    return target

        # Fallback: try additional string hits
        start = str_off + 1
        for _ in range(5):
            str_off2 = self.find_string(b"vnode_getattr", start)
            if str_off2 < 0:
                break
            refs2 = self.find_string_refs(str_off2)
            if refs2:
                ref_off2 = refs2[0][0]
                for scan_off in range(ref_off2 - 4, ref_off2 - 64, -4):
                    if scan_off < 0:
                        break
                    insn = _rd32(self.raw, scan_off)
                    if (insn >> 26) == 0x25:  # BL
                        imm26 = insn & 0x3FFFFFF
                        if imm26 & (1 << 25):
                            imm26 -= 1 << 26
                        target = scan_off + imm26 * 4
                        if any(s <= target < e for s, e in self.code_ranges):
                            self._log(
                                f"  [+] vnode_getattr at 0x{target:X} "
                                f"(via BL at 0x{scan_off:X})"
                            )
                            return target
            start = str_off2 + 1

        return -1

    def patch_hook_cred_label_update_execve(self):
        """Low-risk early-return patch for sandbox cred-label hook.

        Keep PACIBSP at entry and patch following instructions to:
          mov x0, xzr
          retab
        This avoids ops-table rewrites, code caves, and long trampolines.
        """
        self._log("\n[JB] _hook_cred_label_update_execve: low-risk early return")

        # Find sandbox ops table
        ops_table = self._find_sandbox_ops_table_via_conf()
        if ops_table is None:
            self._log("  [-] sandbox ops table not found")
            return False

        # ── 3. Find hook index dynamically ───────────────────────
        # mpo_cred_label_update_execve is one of the largest sandbox
        # hooks at an early index (< 30).  Scan for it.
        hook_index = -1
        orig_hook = -1
        best_size = 0
        for idx in range(0, 30):
            entry = self._read_ops_entry(ops_table, idx)
            if entry is None or entry <= 0:
                continue
            if not any(s <= entry < e for s, e in self.code_ranges):
                continue
            fend = self._find_func_end(entry, 0x2000)
            fsize = fend - entry
            if fsize > best_size:
                best_size = fsize
                hook_index = idx
                orig_hook = entry

        if hook_index < 0 or best_size < 1000:
            self._log(
                "  [-] hook entry not found in ops table "
                f"(best: idx={hook_index}, size={best_size})"
            )
            return False

        self._log(f"  [+] hook at ops[{hook_index}] = 0x{orig_hook:X} ({best_size} bytes)")

        # Verify first instruction is PACIBSP
        first_insn = self.raw[orig_hook : orig_hook + 4]
        if first_insn != PACIBSP:
            self._log(
                f"  [-] first insn not PACIBSP "
                f"(got 0x{_rd32(self.raw, orig_hook):08X})"
            )
            return False

        func_end = self._find_func_end(orig_hook, 0x2000)
        if func_end <= orig_hook + 8:
            self._log("  [-] hook function too small for low-risk patch")
            return False
        self.emit(
            orig_hook + 4,
            asm("mov x0, xzr"),
            "mov x0,xzr [_hook_cred_label_update_execve low-risk]",
        )
        self.emit(
            orig_hook + 8,
            bytes([0xFF, 0x0F, 0x5F, 0xD6]),  # retab
            "retab [_hook_cred_label_update_execve low-risk]",
        )

        return True
