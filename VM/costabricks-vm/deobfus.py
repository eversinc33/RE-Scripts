from collections import Counter
import re

with open("disasm.txt", "r", encoding="utf-16") as f:
    lines = f.readlines()

pattern = re.compile(r"regs\[(0x[0-9a-fA-F]+)\]")
regs = []

# collect all registers used
for line in lines:
    regs += pattern.findall(line)

# count usage
usage = Counter(regs)

# filter lines
filtered_lines = []
for line in lines:
    if "regs" not in line:
        filtered_lines.append(line)
    else:
        match = pattern.search(line)
        if match and usage[match.group(1)] > 1:
            filtered_lines.append(line)

with open("deobfus_disasm.txt", "w") as f:
    f.writelines(filtered_lines)
