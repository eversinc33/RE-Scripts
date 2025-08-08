import idc
import idautils
import ida_bytes
import idaapi

DECRYPT_FUNC_NAME = "xor_decrypt_string"  

def xor_decrypt(ea, size, key):
    enc = ida_bytes.get_bytes(ea, size)
    if not enc:
        return None
    return ''.join(chr(b ^ key) for b in enc)

def get_call_args(call_ea):
    args = []
    ea = call_ea

    tries = 0
    while len(args) < 3:
        ea = idc.prev_head(ea)
        mnem = idc.print_insn_mnem(ea)
        
        # look for push instructions, skip others up to 6 times
        if mnem != "push":
            tries += 1
            if tries > 6:
                return None
            continue

        op_type = idc.get_operand_type(ea, 0)

        # if immediate is pushed use it
        if op_type in (idc.o_imm, idc.o_mem):
            val = idc.get_operand_value(ea, 0)
            args.append(val)
            continue

        # if it is a register, look for mov or movzx
        if op_type == idc.o_reg:
            reg = idc.print_operand(ea, 0)
            prev_ea = idc.prev_head(ea)
            prev_mnem = idc.print_insn_mnem(prev_ea)

            # try skipping other instructions
            skipped = 0
            while not prev_mnem.startswith("mov"):
                prev_ea = idc.prev_head(prev_ea)
                prev_mnem = idc.print_insn_mnem(prev_ea)
                skipped += 1
                if skipped > 10: 
                    return None
                
            # found mov
            if prev_mnem.startswith("mov"):
                dst = idc.print_operand(prev_ea, 0)
                src_type = idc.get_operand_type(prev_ea, 1)
                src_val = idc.get_operand_value(prev_ea, 1)

                if dst == reg and src_type in (idc.o_imm, idc.o_mem):
                    args.append(src_val)
                    continue
            return None
        return None

    return args[::-1]

def set_hexrays_comment(address, text):
    '''
    set comment in decompiled code
    '''
    cfunc = idaapi.decompile(address)
    tl = idaapi.treeloc_t()
    tl.ea = address
    tl.itp = idaapi.ITP_SEMI
    cfunc.set_user_cmt(tl, text)
    cfunc.save_user_cmts() 

def main():
    # get decrypt function address
    decrypt_func_ea = idc.get_name_ea_simple(DECRYPT_FUNC_NAME)
    if decrypt_func_ea == idc.BADADDR:
        print(f"[!] Could not resolve decryption function. Rename function to {DECRYPT_FUNC_NAME}")
        return

    count = 0
    # for each call to decrypt func ...
    for xref in idautils.CodeRefsTo(decrypt_func_ea, 0):
        # ... get arguments
        args = get_call_args(xref)
        if not args:
            continue

        key = ida_bytes.get_byte(args[0])
        size = ida_bytes.get_dword(args[1])
        enc = ida_bytes.get_dword(args[2])

        print(f"Encoded Addr: {hex(args[0])}, Size: {size}, Key: {hex(key)}")

        # decrypt
        dec = xor_decrypt(enc, size, key)
        if dec is None:
            continue

        # set comments
        idc.set_cmt(xref, f'Decrypted: "{dec}"', 0)
        set_hexrays_comment(xref, f'Decrypted: "{dec}"')
        print(f"Decrypted: {dec} @ {hex(xref)}")
        count += 1

    print(f"[+] Annotated {count} call(s) to {DECRYPT_FUNC_NAME}")

main()