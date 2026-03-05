"""Mixin: KernelJBPatchKcall10Mixin."""

from .kernel_jb_base import _rd64, struct

# Max sysent entries in XNU (dispatch clamps at 0x22E = 558).
_SYSENT_MAX_ENTRIES = 558
# Each sysent entry is 24 bytes.
_SYSENT_ENTRY_SIZE = 24
# PAC discriminator used by the syscall dispatch (MOV X17, #0xBCAD; BLRAA X8, X17).
_SYSENT_PAC_DIVERSITY = 0xBCAD


class KernelJBPatchKcall10Mixin:
    def _find_sysent_table(self, nosys_off):
        """Find the real sysent table base.

        Strategy:
        1. Find any DATA entry whose decoded pointer == _nosys.
        2. Scan backward in 24-byte steps to find the true table start
           (entry 0 is the indirect syscall handler, NOT _nosys).
        3. Validate each backward entry: sy_call decodes to a code range
           AND the metadata fields (narg, arg_bytes) look reasonable.

        Previous bug: the old code took the first _nosys match as entry 0,
        but _nosys first appears at entry ~428 (varies by XNU build).
        """
        # Step 1: find any _nosys-matching entry
        nosys_entry = -1
        seg_start = -1
        for seg_name, vmaddr, fileoff, filesize, _ in self.all_segments:
            if "DATA" not in seg_name:
                continue
            for off in range(fileoff, fileoff + filesize - _SYSENT_ENTRY_SIZE, 8):
                val = _rd64(self.raw, off)
                decoded = self._decode_chained_ptr(val)
                if decoded == nosys_off:
                    # Verify: next entry should also have valid sy_call
                    val2 = _rd64(self.raw, off + _SYSENT_ENTRY_SIZE)
                    decoded2 = self._decode_chained_ptr(val2)
                    if decoded2 > 0 and any(
                        s <= decoded2 < e for s, e in self.code_ranges
                    ):
                        nosys_entry = off
                        seg_start = fileoff
                        break
            if nosys_entry >= 0:
                break

        if nosys_entry < 0:
            return -1

        self._log(
            f"  [*] _nosys entry found at foff 0x{nosys_entry:X}, "
            f"scanning backward for table start"
        )

        # Step 2: scan backward to find entry 0
        base = nosys_entry
        entries_back = 0
        while base - _SYSENT_ENTRY_SIZE >= seg_start:
            if entries_back >= _SYSENT_MAX_ENTRIES:
                break
            prev = base - _SYSENT_ENTRY_SIZE
            # Check sy_call decodes to valid code
            val = _rd64(self.raw, prev)
            decoded = self._decode_chained_ptr(val)
            if decoded <= 0 or not any(
                s <= decoded < e for s, e in self.code_ranges
            ):
                break
            # Check metadata looks like a sysent entry
            narg = struct.unpack_from("<H", self.raw, prev + 20)[0]
            arg_bytes = struct.unpack_from("<H", self.raw, prev + 22)[0]
            if narg > 12 or arg_bytes > 96:
                break
            base = prev
            entries_back += 1

        self._log(
            f"  [+] sysent table base at foff 0x{base:X} "
            f"({entries_back} entries before first _nosys)"
        )
        return base

    def _encode_chained_auth_ptr(self, target_foff, next_val, diversity=0,
                                  key=0, addr_div=0):
        """Encode an arm64e kernel cache auth rebase chained fixup pointer.

        Layout (DYLD_CHAINED_PTR_64_KERNEL_CACHE):
          bits[29:0]:  target (file offset)
          bits[31:30]: cacheLevel (0)
          bits[47:32]: diversity (16 bits)
          bit[48]:     addrDiv
          bits[50:49]: key (0=IA, 1=IB, 2=DA, 3=DB)
          bits[62:51]: next (12 bits, 4-byte stride delta to next fixup)
          bit[63]:     isAuth (1)
        """
        val = (
            (target_foff & 0x3FFFFFFF)
            | ((diversity & 0xFFFF) << 32)
            | ((addr_div & 1) << 48)
            | ((key & 3) << 49)
            | ((next_val & 0xFFF) << 51)
            | (1 << 63)
        )
        return struct.pack("<Q", val)

    def _extract_chain_next(self, raw_val):
        """Extract the 'next' chain field from a raw chained fixup pointer."""
        return (raw_val >> 51) & 0xFFF

    def patch_kcall10(self):
        """Low-risk safe stub for syscall 439.

        Instead of injecting an arbitrary-call shellcode trampoline, route
        syscall 439 to `_nosys` with valid chained-fixup auth encoding.
        """
        self._log("\n[JB] kcall10: low-risk nosys stub")

        # Find _nosys
        nosys_off = self._resolve_symbol("_nosys")
        if nosys_off < 0:
            nosys_off = self._find_nosys()
        if nosys_off < 0:
            self._log("  [-] _nosys not found")
            return False

        self._log(f"  [+] _nosys at 0x{nosys_off:X}")

        # Find sysent table (real base via backward scan)
        sysent_off = self._find_sysent_table(nosys_off)
        if sysent_off < 0:
            self._log("  [-] sysent table not found")
            return False

        self._log(f"  [+] sysent table at file offset 0x{sysent_off:X}")

        # Entry 439 (SYS_kas_info)
        entry_439 = sysent_off + 439 * _SYSENT_ENTRY_SIZE

        # Patch sysent[439] to _nosys with proper chained auth pointer.

        # Read original raw value to preserve the chain 'next' field
        old_sy_call_raw = _rd64(self.raw, entry_439)
        call_next = self._extract_chain_next(old_sy_call_raw)

        self.emit(
            entry_439,
            self._encode_chained_auth_ptr(
                nosys_off,
                next_val=call_next,
                diversity=_SYSENT_PAC_DIVERSITY,
                key=0,       # IA
                addr_div=0,  # fixed discriminator (not address-blended)
            ),
            f"sysent[439].sy_call = _nosys 0x{nosys_off:X} "
            f"(auth rebase, div=0xBCAD, next={call_next}) [kcall10 low-risk]",
        )

        # sy_return_type = SYSCALL_RET_INT_T (1)
        self.emit(
            entry_439 + 16,
            struct.pack("<I", 1),
            "sysent[439].sy_return_type = 1 [kcall10 low-risk]",
        )

        # sy_narg = 0, sy_arg_bytes = 0
        self.emit(
            entry_439 + 20,
            struct.pack("<I", 0),
            "sysent[439].sy_narg=0,sy_arg_bytes=0 [kcall10 low-risk]",
        )

        return True
