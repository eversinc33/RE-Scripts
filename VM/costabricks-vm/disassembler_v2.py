import pefile
import struct 

FILENAME = "130fa726df5a58e9334cc28dc62e3ebaa0b7c0d637fce1a66daff66ee05a9437"
BYTECODE_TEXT_OFFSET = 0xA4
BYTECODE_LEN = 0x40000

pe = pefile.PE(FILENAME)

text_section = 0
for section in pe.sections:
    if section.Name.rstrip(b'\x00') == b'.text':
        text_section = section.PointerToRawData
        break

vm_bytecode_loc = text_section + BYTECODE_TEXT_OFFSET
bytecode_len = BYTECODE_LEN

opcodes = {
    0: "mov",
    1: "xor",
    2: "add",
    3: "and",
    4: "sub",
    5: "call",
    6: "nop",
    7: "VirtualAlloc",
    8: "VirtualFree",
    9: "__memmove",
    0xA: "cmp",
    0xB: "div",
    0xC: "jnz",
    0xD: "jz",
    0xE: "jmp",
    0xF: "LoadLibrary", 
    0x10: "GetProcAddress",
    0x11: "ExitProcess",
    0x12: "shr",
    0x13: "shl"
}

sizes = {
    0x08: "int8",
    0x10: "int16",
    0x20: "int32",
    0x40: "int64"
}

class Params:
    def __init__(self, data):
        self.is_pointer = struct.unpack_from("<H", data, 0)[0] == 0
        self.op_size    = struct.unpack_from("<H", data, 2)[0]
        self.reg_index  = struct.unpack_from("<I", data, 4)[0]
        self.immediate  = struct.unpack_from("<I", data, 8)[0]

    def __str__(self):
        repr = ""
        if self.op_size != 0:
            repr += f"({sizes[self.op_size]})"
        if self.is_pointer != 0:
            repr += "*"
        if self.reg_index != 0:
            repr += f"regs[{hex(self.reg_index)}]"
        else:
            repr += str(hex(self.immediate))
        return repr

LABEL = "__LABEL_"

class Instruction:
    def __init__(self, index, opcode, params):
        self.index  = index
        self.opcode = opcodes[opcode]
        self.params = params

    def __str__(self):
        # Remove noisy instructions
        #if self.opcode.lower() in ["cmp", "jz", "jnz", "jmp", "and", "mov", "add", "sub", "shl", "shr"]:
        #    return ""
        match self.opcode.lower():
            case "and":
                return f"{self.params[0]} &= {self.params[1]}"
            case "mov":
                if not self.params:
                    return LABEL
                return f"{self.params[0]} = {self.params[1]}"
            case "sub":
                return f"{self.params[0]} -= {self.params[1]}"
            case "xor":
                return f"{self.params[0]} ^= {self.params[1]}"
            case "add":
                return f"{self.params[0]} += {self.params[1]}"
            case "shl":
                return f"{self.params[0]} << {self.params[1]}"
            case "shr":
                return f"{self.params[0]} >> {self.params[1]}"
            case "getprocaddress":
                return f"{self.params[2]} = {self.opcode}({self.params[0]}, {self.params[1]})"
            case "virtualalloc":
                return f"{self.params[0]} = {self.opcode}({self.params[1]})"
            case "loadlibrary":
                return f"{self.params[0]} = {self.opcode}({self.params[1]})"
            case "__memmove":
                return f"{self.opcode}({self.params[0]}, {self.params[1]}, {self.params[2]})"
            case _:
                if self.opcode in ["jmp","jz","jnz"]:
                    return f"{self.opcode} {hex(self.params[0].reg_index)}"
                repr = f"{self.opcode} "
                for p in params:
                    repr += f"{p}, "
                if len(params) != 0:
                    return repr[:-2] # remove comma from last param 
                return repr
        print(self.opcode)
        
with open(FILENAME, "rb") as f:
    f.seek(vm_bytecode_loc)
    data = f.read(bytecode_len)

    i = 0
    print("__START:")
    while i < bytecode_len:
        index = struct.unpack_from("<I", data, i)[0] # 32bit LE
        opcode = struct.unpack_from("<H", data, i + 4)[0] # 16bit LE
        n_params = struct.unpack_from("<H", data, i + 0xA)[0] # 16bit LE

        i += 0xC # advance pointer to params

        params = []
        for param in range(0, n_params):
            params.append(Params(data[i:]))
            i += 0x10 # advance to next param

        instruction = Instruction(index, opcode, params)
        if str(instruction) == LABEL:
            print(f"{LABEL}{hex(instruction.index)}:")
        else:
            if str(instruction) != "":
                print(f"{hex(instruction.index)}\t{instruction}")