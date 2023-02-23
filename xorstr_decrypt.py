import ida_idaapi, ida_kernwin
import idaapi
import ida_ua
import idc
import ida_allins
import sys
import ida_bytes

class xor_decryption_mod(ida_idaapi.plugmod_t):
    stack_count = 0
    def __del__(self):
        ida_kernwin.msg("unloaded xor decryptor\n")
    def get_insn(self, ea : int):
        insn = idaapi.insn_t()
        idaapi.decode_insn(insn, ea)
        return insn
    def get_previous_insn(self, ea):
        insn = idaapi.insn_t()
        idaapi.decode_prev_insn(insn, ea)
        return insn
    def get_next_insn(self, previous_insn):
        insn = idaapi.insn_t()
        if previous_insn.size == 0:
            return None
        idaapi.decode_insn(insn, previous_insn.ea + previous_insn.size)
        return insn
    def find_stack_push_start(self, insn, stackaddr):
        calls = 0
        while insn.itype != ida_allins.NN_mov or (insn.ops[0].addr != stackaddr) or insn.ops[0].type != 4 or insn.ops[1].type != 1 and calls < 5000:
            calls += 1
            if insn.ea == 0xffffffffffffffff:
                return None
            insn = self.get_previous_insn(insn.ea)
        if calls == 5000:
            return None
        return insn
    def find_register_value(self, insn, reg):
        calls = 0
        while insn.itype != ida_allins.NN_mov or (insn.ops[0].type != ida_ua.o_reg) or (insn.ops[0].reg != reg) and calls < 1000:
            if insn.ea == 0xffffffffffffffff:
                return None
            insn = self.get_previous_insn(insn.ea)
        if calls == 1000:
            return None
        if (insn.ops[1].type != ida_ua.o_imm):
            stack_insn = self.find_stack_push_start(self.get_previous_insn(insn.ea), insn.ops[1].addr)
            if stack_insn == None:
                return None
            return self.find_register_value(stack_insn, stack_insn.ops[1].reg)
        return insn.ops[1].value
    def find_next_stack_push(self, insn, address):
        calls = 0
        while insn.itype != ida_allins.NN_mov or (insn.ops[0].addr != address) and calls < 5000:
            calls += 1
            if insn.ea == 0xffffffffffffffff:
                return None
            insn = self.get_next_insn(insn)
            if insn == None:
                return None
        if calls == 5000:
            return None
        return insn
    def byte_xor(self, ba1, ba2):
        return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])
    def handle_str_decryption(self, data_reg, key_address, previous_insn, data_address, func_addr):
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
            register_val = self.find_register_value(mov_insn, mov_insn.ops[1].reg)
            if register_val == None:
                return None
            xor_data += (register_val.to_bytes(8, sys.byteorder))
            if x != expected_pushes - 1:
                mov_insn = self.find_next_stack_push(mov_insn, data_address + (x + 1) * 8)
            if mov_insn == None:
                return None
        mov_insn = self.find_stack_push_start(previous_insn, key_address)
        if mov_insn == None:
            return None
        for x in range(0, expected_pushes):
            register_val = self.find_register_value(mov_insn, mov_insn.ops[1].reg)
            if register_val == None:
                return None
            xor_key += (register_val.to_bytes(8, sys.byteorder))
            if x != expected_pushes - 1:
                mov_insn = self.find_next_stack_push(mov_insn, key_address + (x + 1) * 8)
            if mov_insn == None:
                return None
        result = str(self.byte_xor(xor_data, xor_key))
        idc.set_cmt(func_addr, result, 0)
        return result
    def handle_pxor(self, func_addr):
        insn = self.get_insn(func_addr)
        data_reg = insn.ops[0].reg
        key_address = insn.ops[1].addr
        previous_insn = self.get_previous_insn(insn.ea)
        data_address = previous_insn.ops[1].addr
        return self.handle_str_decryption(data_reg, key_address, previous_insn, data_address, func_addr)
    def handle_vpxor(self, func_addr):
        insn = self.get_insn(func_addr)
        data_reg = insn.ops[1].reg
        key_address = insn.ops[2].addr
        previous_insn = self.get_previous_insn(insn.ea)
        data_address = previous_insn.ops[1].addr
        return self.handle_str_decryption(data_reg, key_address, previous_insn, data_address, func_addr)
    def analyze(self, func_addr):
        insn = self.get_insn(func_addr)
        if insn.itype == ida_allins.NN_vpxor:
           return self.handle_vpxor(func_addr)
        if insn.itype == ida_allins.NN_pxor:
           return self.handle_pxor(func_addr)
        return None
    def analyze_sig(self, sig):
        start_ea = idc.get_inf_attr(idc.INF_MIN_EA)
        end_ea = idc.get_inf_attr(idc.INF_MAX_EA)
        binpat = ida_bytes.compiled_binpat_vec_t()
        ida_bytes.parse_binpat_str(binpat, start_ea, sig, 16)
        match_ea = start_ea
        while match_ea != idaapi.BADADDR:
            match_ea = ida_bytes.bin_search(match_ea + 1, end_ea, binpat, idaapi.BIN_SEARCH_FORWARD)
            if match_ea != idaapi.BADADDR:
                #print("Processing {:08X}".format(match_ea))
                result = self.analyze(match_ea)
                if result != None:
                    print("Found match at {:08X} {}".format(match_ea, result))
    def run(self, arg):
        self.analyze_sig("C5 ? EF") # vpxor
        self.analyze_sig("66 ? EF") # pxor
        return 0

# This class is instantiated when IDA loads the plugin.
class xor_decryption_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_UNL | ida_idaapi.PLUGIN_MULTI
    comment = "Attempts to detect & decrypt JM Xorstring"
    help = "This is help"
    wanted_name = "Xorstring Decryptor"
    wanted_hotkey = "Alt-F8"

    #def __del__(self):
        #ida_kernwin.msg("unloaded globally\n")

    def init(self):
        ida_kernwin.msg("init() called!\n")
        return xor_decryption_mod()

    def run(self, arg):
        ida_kernwin.msg("ERROR: run() called for global object!\n")
        return (arg % 2) == 0

    def term(self):
        ida_kernwin.msg("ERROR: term() called (should never be called)\n")

def PLUGIN_ENTRY():
    return xor_decryption_t()

