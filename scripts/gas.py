import re


def extract_lea_operands(asm):
    pattern = r'lea\s+(?P<dst>\S+),\s*(?P<src>\S+)'
    match = re.search(pattern, asm)
    if match:
        return match.group('dst'), match.group('src')
    else:
        return None


asm = 'lea       -1(%rdi,%rax),%rcx'

print(extract_lea_operands(asm))
