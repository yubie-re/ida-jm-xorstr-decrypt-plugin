import sys
import ida_allins
import ida_bytes
import ida_idaapi
import ida_kernwin
import ida_search
import ida_ua
import idaapi
import idc


class xor_decryption_mod(ida_idaapi.plugmod_t):
    stack_count = 0

    def __del__(self):
        ida_kernwin.msg("unloaded xor decryptor\n")

    """
    Returns the instruction at a linear address
    """
    def get_insn(self, ea: int):
        insn = idaapi.insn_t()
        idaapi.decode_insn(insn, ea)
        return insn

    """
    Returns the previous instruction
    """
    def get_previous_insn(self, ea):
        insn = idaapi.insn_t()
        idaapi.decode_prev_insn(insn, ea)
        return insn

    """
    Returns the next instruction, or None if it can't find any
    """
    def get_next_insn(self, previous_insn):
        insn = idaapi.insn_t()
        if previous_insn.size == 0:
            return None
        idaapi.decode_insn(insn, previous_insn.ea + previous_insn.size)
        return insn

    """
    Finds where the initial mov is for the key or data. This matches the stack address and checks that it is being written to with a mov.
    This moves backwards.
    returns the instruction where the first mov is for the data or key.

    movabs rax, -4762152789334367252
    >> RETURN HERE FOR DATA << mov QWORD PTR [rsp], rax
    movabs rax, -6534519754492314190
    mov QWORD PTR [rsp+8], rax
    movabs rax, -2862143164529545214
    mov QWORD PTR [rsp+16], rax
    movabs rax, -4140208776682645948
    mov QWORD PTR [rsp+24], rax
    vmovdqa ymm1, YMMWORD PTR [rsp]
    movabs rax, -2550414817236710003
    >> RETURN HERE FOR KEY << mov QWORD PTR [rsp+32], rax
    movabs rax, -4595755740016602734
    mov QWORD PTR [rsp+40], rax
    movabs rax, -5461194525092864914
    mov QWORD PTR [rsp+48], rax
    movabs rax, -4140208776682645984
    mov QWORD PTR [rsp+56], rax
    vpxor ymm0, ymm1, YMMWORD PTR [rsp+32]
    vmovdqa YMMWORD PTR [rsp], ymm0
    """
    def find_stack_push_start(self, insn, stackaddr):
        calls = 0
        while insn.itype != ida_allins.NN_mov or (insn.ops[0].addr != stackaddr) or insn.ops[0].type != ida_ua.o_displ or insn.ops[1].type != ida_ua.o_reg and calls < 5000:
            calls += 1
            if insn.ea == idaapi.SIZE_MAX:
                return None
            insn = self.get_previous_insn(insn.ea)
        if calls == 5000:
            return None
        return insn

    """
    Finds the last findable immediate value for known for a register by moving backwards until finding a mov instruction where the register is written to
    This moves backwards.
    returns the immediate value of a register

    movabs rax, >> RETURNS THIS: -6534519754492314190 <<
    mov QWORD PTR [rsp+8], rax
    movabs rax, -2862143164529545214
    mov QWORD PTR [rsp+16], rax
    movabs rax, -4140208776682645948
    mov QWORD PTR [rsp+24], rax
    vmovdqa ymm1, YMMWORD PTR [rsp]
    movabs rax, -2550414817236710003
    mov QWORD PTR [rsp+32], rax
    movabs rax, -4595755740016602734
    mov QWORD PTR [rsp+40], rax
    movabs rax, -5461194525092864914
    mov QWORD PTR [rsp+48], rax
    movabs rax, -4140208776682645984
    mov QWORD PTR [rsp+56], rax
    vpxor ymm0, ymm1, YMMWORD PTR [rsp+32]
    vmovdqa YMMWORD PTR [rsp], ymm0
    """
    def find_register_value(self, insn, reg):
        calls = 0
        while insn.itype != ida_allins.NN_mov or (insn.ops[0].type != ida_ua.o_reg) or (insn.ops[0].reg != reg) and calls < 1000:
            if insn.ea == idaapi.SIZE_MAX:
                return None
            insn = self.get_previous_insn(insn.ea)
        if calls == 1000:
            return None
        if (insn.ops[1].type != ida_ua.o_imm):
            stack_insn = self.find_stack_push_start(
                self.get_previous_insn(insn.ea), insn.ops[1].addr)
            if stack_insn == None:
                return None
            return self.find_register_value(stack_insn, stack_insn.ops[1].reg)
        return insn.ops[1].value

    """
    Used to find what stack address is moved into the xmm/ymm register later used in the pxor instructions
    This moves backwards.
    returns the movdqx instruction

    movabs rax, -6534519754492314190
    mov QWORD PTR [rsp+8], rax
    movabs rax, -2862143164529545214
    mov QWORD PTR [rsp+16], rax
    movabs rax, -4140208776682645948
    mov QWORD PTR [rsp+24], rax
    RETURN HERE >> vmovdqa ymm1, YMMWORD PTR [rsp]
    movabs rax, -2550414817236710003
    mov QWORD PTR [rsp+32], rax
    movabs rax, -4595755740016602734
    mov QWORD PTR [rsp+40], rax
    movabs rax, -5461194525092864914
    mov QWORD PTR [rsp+48], rax
    movabs rax, -4140208776682645984
    mov QWORD PTR [rsp+56], rax
    vpxor ymm0, ymm1, YMMWORD PTR [rsp+32]
    vmovdqa YMMWORD PTR [rsp], ymm0
    """
    def find_register_movdq_insn(self, insn, reg):
        calls = 0
        while (insn.itype != ida_allins.NN_vmovdqa and insn.itype != ida_allins.NN_vmovdqu and insn.itype != ida_allins.NN_movdqa and insn.itype != ida_allins.NN_movdqu) or (insn.ops[0].type != ida_ua.o_reg) or (insn.ops[0].reg != reg) and calls < 1000:
            if insn.ea == idaapi.SIZE_MAX:
                return None
            insn = self.get_previous_insn(insn.ea)
        if calls == 1000:
            return None
        return insn

    """
    Used to find where the ymm/xmm xored output is moved back onto the stack (useful to find where to place psuedocode comments)
    This moves forwards
    returns the movdqx instruction where this happens

    movabs rax, -6534519754492314190
    mov QWORD PTR [rsp+8], rax
    movabs rax, -2862143164529545214
    mov QWORD PTR [rsp+16], rax
    movabs rax, -4140208776682645948
    mov QWORD PTR [rsp+24], rax
    vmovdqa ymm1, YMMWORD PTR [rsp]
    movabs rax, -2550414817236710003
    mov QWORD PTR [rsp+32], rax
    movabs rax, -4595755740016602734
    mov QWORD PTR [rsp+40], rax
    movabs rax, -5461194525092864914
    mov QWORD PTR [rsp+48], rax
    movabs rax, -4140208776682645984
    mov QWORD PTR [rsp+56], rax
    vpxor ymm0, ymm1, YMMWORD PTR [rsp+32]
     >> RETURNS HERE << vmovdqa YMMWORD PTR [rsp], ymm0
    """
    def find_stack_movdq_insn(self, insn, reg):
        calls = 0
        while (insn.itype != ida_allins.NN_vmovdqa and insn.itype != ida_allins.NN_vmovdqu and insn.itype != ida_allins.NN_movdqa and insn.itype != ida_allins.NN_movdqu) or (insn.ops[1].type != ida_ua.o_reg) or (insn.ops[1].reg != reg) and calls < 1000:
            if insn.ea == idaapi.SIZE_MAX:
                return None
            insn = self.get_next_insn(insn)
            if insn == None:
                return None
        if calls == 1000:
            return None
        return insn

    """
    Finds the next stack push instruction which matches the stack address given.
    This moves forwards
    returns the mov instruction which accesses the address

    movabs rax, -6534519754492314190
    >> CALLED HERE << mov QWORD PTR [rsp+8], rax
    movabs rax, -2862143164529545214
    >> RETURNS HERE << mov QWORD PTR [rsp+16], rax
    movabs rax, -4140208776682645948
    mov QWORD PTR [rsp+24], rax
    vmovdqa ymm1, YMMWORD PTR [rsp]
    movabs rax, -2550414817236710003
    mov QWORD PTR [rsp+32], rax
    movabs rax, -4595755740016602734
    mov QWORD PTR [rsp+40], rax
    movabs rax, -5461194525092864914
    mov QWORD PTR [rsp+48], rax
    movabs rax, -4140208776682645984
    mov QWORD PTR [rsp+56], rax
    vpxor ymm0, ymm1, YMMWORD PTR [rsp+32]
    vmovdqa YMMWORD PTR [rsp], ymm0
    """
    def find_next_stack_push(self, insn, address):
        calls = 0
        while insn.itype != ida_allins.NN_mov or (insn.ops[0].addr != address) and calls < 5000:
            calls += 1
            if insn.ea == idaapi.SIZE_MAX:
                return None
            insn = self.get_next_insn(insn)
            if insn == None:
                return None
        if calls == 5000:
            return None
        return insn

    """
    Handles a basic xor cipher with two byte arrays
    """
    def byte_xor(self, ba1, ba2):
        return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

    """
    Handles the string decryption.
    Steps:
    Find where it starts pushing data onto the stack
    Figure if we're dealing with xmm/ymm registers
    Find immediate values of the data and append them to a byte array
    Find where it starts pushing the key onto the stack
    Find immediate values of the key and append them to a byte array
    Xor the two arrays, then set comments as necessary
    """
    def handle_str_decryption(self, data_reg, key_address, func_addr, pxor_insn):
        previous_insn = self.find_register_movdq_insn(pxor_insn, data_reg)
        if previous_insn == None:
            return None
        data_address = previous_insn.ops[1].addr
        mov_start = self.find_stack_push_start(previous_insn, data_address)
        if mov_start == None:
            return None
        if idaapi.get_reg_name(data_reg, 16).startswith('xmm'):
            expected_pushes = 2
        elif idaapi.get_reg_name(data_reg, 16).startswith('ymm'):
            expected_pushes = 4
        else:
            return None
        mov_insn = mov_start
        xor_data = bytes()
        xor_key = bytes()
        for x in range(0, expected_pushes):
            register_val = self.find_register_value(
                mov_insn, mov_insn.ops[1].reg)
            if register_val == None:
                return None
            xor_data += (register_val.to_bytes(8, sys.byteorder))
            if x != expected_pushes - 1:
                mov_insn = self.find_next_stack_push(
                    mov_insn, data_address + (x + 1) * 8)
            if mov_insn == None:
                return None
        mov_insn = self.find_stack_push_start(previous_insn, key_address)
        if mov_insn == None:
            return None
        for x in range(0, expected_pushes):
            register_val = self.find_register_value(
                mov_insn, mov_insn.ops[1].reg)
            if register_val == None:
                return None
            xor_key += (register_val.to_bytes(8, sys.byteorder))
            if x != expected_pushes - 1:
                mov_insn = self.find_next_stack_push(
                    mov_insn, key_address + (x + 1) * 8)
            if mov_insn == None:
                return None
        result = self.byte_xor(xor_data, xor_key).rstrip(b'\x00').decode('utf-8')
        comment = 'Decrypted: ' + result
        mov_to_stack_insn = self.find_stack_movdq_insn(pxor_insn, pxor_insn.ops[0].reg)
        idc.set_cmt(func_addr, comment, 0)
        cfunc = idaapi.decompile(mov_to_stack_insn.ea)
        if cfunc:
            tl = idaapi.treeloc_t()
            tl.ea = mov_to_stack_insn.ea
            tl.itp = idaapi.ITP_SEMI
            cfunc.set_user_cmt(tl, comment)
            cfunc.save_user_cmts()
        return result

    """
    Starts the routine for a PXOR instruction
    ex : pxor xmm0, [rbp+1F30h+var_1B90]
    """
    def handle_pxor(self, func_addr):
        insn = self.get_insn(func_addr)
        data_reg = insn.ops[0].reg
        key_address = insn.ops[1].addr
        return self.handle_str_decryption(data_reg, key_address, func_addr, insn)

    """
    Starts the routine for a VPXOR instruction
    ex : vpxor ymm0, ymm1, YMMWORD PTR [rsp+32]
    """
    def handle_vpxor(self, func_addr):
        insn = self.get_insn(func_addr)
        data_reg = insn.ops[1].reg
        key_address = insn.ops[2].addr
        return self.handle_str_decryption(data_reg, key_address, func_addr, insn)

    """
    calls the right routine depending on the instruction type
    """
    def analyze(self, func_addr):
        insn = self.get_insn(func_addr)
        if insn.itype == ida_allins.NN_vpxor:
            return self.handle_vpxor(func_addr)
        if insn.itype == ida_allins.NN_pxor:
            return self.handle_pxor(func_addr)
        return None

    """
    Analyzes all instances of an IDA Pattern with compability for IDA 7.5 (7.5 doesn't have compiled_binpat_vec_t, find_binary is deprecated in IDA 8)
    """
    def analyze_sig_75(self, sig):
        match_ea = idc.get_inf_attr(idc.INF_MIN_EA)
        while True:
            match_ea = ida_search.find_binary(
                match_ea + 1, ida_idaapi.BADADDR, sig, 16, idc.SEARCH_DOWN)
            if match_ea != idaapi.BADADDR:
                result = self.analyze(match_ea)
                if result != None:
                    print("Found match at {:08X} {}".format(match_ea, result))
            else:
                break

    """
    Analyzes all instances of an IDA Pattern
    """
    def analyze_sig(self, sig):
        match_ea = idc.get_inf_attr(idc.INF_MIN_EA)
        binpat = ida_bytes.compiled_binpat_vec_t()
        ida_bytes.parse_binpat_str(binpat, match_ea, sig, 16)
        while True:
            match_ea = ida_bytes.bin_search(
                match_ea + 1, idaapi.BADADDR, binpat, idaapi.BIN_SEARCH_FORWARD)
            if match_ea != idaapi.BADADDR:
                result = self.analyze(match_ea)
                if result != None:
                    print("Found match at {:08X} {}".format(match_ea, result))
            else:
                break

    """
    Starts plugin logic
    """
    def run(self, arg):
        if idaapi.IDA_SDK_VERSION <= 750:
            self.analyze_sig_75("C5 ? EF")  # vpxor
            self.analyze_sig_75("66 ? EF")  # pxor
        else:
            self.analyze_sig("C5 ? EF")  # vpxor
            self.analyze_sig("66 ? EF")  # pxor
        return 0

# This class is instantiated when IDA loads the plugin.
class xor_decryption_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_UNL | ida_idaapi.PLUGIN_MULTI
    comment = "Attempts to detect & decrypt JM Xorstring"
    help = "This is help"
    wanted_name = "Xorstring Decryptor"
    wanted_hotkey = "Alt-F8"

    # def __del__(self):
    # ida_kernwin.msg("unloaded globally\n")

    def init(self):
        ida_kernwin.msg("init() called!\n")
        return xor_decryption_mod()

    def run(self, arg):
        ida_kernwin.msg("ERROR: run() called for global object!\n")
        return 0

    def term(self):
        ida_kernwin.msg("ERROR: term() called (should never be called)\n")


def PLUGIN_ENTRY():
    return xor_decryption_t()