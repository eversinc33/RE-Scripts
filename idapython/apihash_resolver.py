
```python
import idaapi
import idautils

import idaapi
import idc

target_func_name = "TODO"

hash_dict = {
    # TODO: fill in from hash_generate
}

def extract_hash_from_call(call_addr):
    # Start walking backwards from the call instruction
    curr_addr = call_addr
    
    for _ in range(10):  # Look back up to 10 instructions
        curr_addr = idc.prev_head(curr_addr)
        inst = idc.print_insn_mnem(curr_addr)
        
        # Look for move instructions that might load the hash
        if inst in ['mov', 'movd', 'movq']:
            if idc.print_operand(curr_addr, 0).lower() in ['edx', 'rdx']:
                op_type = idc.get_operand_type(curr_addr, 1)
                
                # Check if the second operand is an immediate value (constant)
                if op_type == idc.o_imm:
                    # Extract the immediate value (hash)
                    hash_val = idc.get_operand_value(curr_addr, 1)
                    return hash_val
    
    # No hash found
    print(f"Could not extract hash near call at {hex(call_addr)}")
    return None

def set_comment(address, text):
    ## Set in dissassembly
    idc.set_cmt(address, text, 0)

def rename_parent_function_at_address(address, new_name):
    # Get the function start address that contains the given address
    func_start = idc.get_func_attr(address, idc.FUNCATTR_START)
    
    # Check if the function start address is valid
    if func_start == idc.BADADDR:
        print(f"Invalid function start address for address {hex(address)}")
        return
    
    # Rename the function at the start address
    success = idc.set_name(func_start, new_name, 0x800) # setname_force
    if success:
        print(f"Renamed function at address {hex(func_start)} to {new_name}")
    else:
        print(f"Failed to rename function at address {hex(func_start)}")

def analyze_and_comment_function(func_name):
    # Get the function address using its name
    func_ea = idc.get_name_ea_simple(func_name)
    if func_ea == idc.BADADDR:
        print(f"Function {func_name} not found!")
        return

    print(f"Found function {func_name} at {hex(func_ea)}")
    
    # Get all cross-references to the function
    xrefs = idautils.XrefsTo(func_ea, idaapi.XREF_FAR)

    # Iterate over each cross-reference (which corresponds to a call to the function)
    for xref in xrefs:
        call_addr = xref.frm  # The address where the call to the function is made

        # Assuming HASH is the second argument
        h = extract_hash_from_call(call_addr)
        if h != None:
            hash_val = str(hex(h & 0xFFFFFFFF)).upper().replace("X","x")
            if hash_dict.get(hash_val, 0) != 0:
                print(f"Comment at {hex(call_addr)}: {hash_dict.get(hash_val, 0)}")
                set_comment(call_addr, hash_dict.get(hash_val, 0))
                rename_parent_function_at_address(call_addr, f"Mw_{hash_dict.get(hash_val, 0)}")
 
def main():
    func_name = target_func_name
    analyze_and_comment_function(func_name)

if __name__ == "__main__":
    main()

```
