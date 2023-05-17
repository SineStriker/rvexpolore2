from __future__ import annotations

import re
import sys
import os


def main():
    if len(sys.argv) < 3:
        print(f"Usage: python {os.path.basename(__file__)} <input> <output>")
        sys.exit(0)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    f = open(input_file, mode='r')
    lines = f.readlines()
    f.close()

    blocks: list[list[str]] = []
    cur_blocks: list[str] = []
    for line in lines:
        line = line.replace("\n", "")
        if line.startswith("[Inferior "):
            if len(cur_blocks) > 0:
                blocks.append(cur_blocks)
                cur_blocks = []
            break

        if re.search(r"Breakpoint (\d+),", line):
            if len(cur_blocks) > 0:
                blocks.append(cur_blocks)
                cur_blocks = []
            cur_blocks.append(line)

        elif len(cur_blocks) > 0:
            cur_blocks.append(line)

    code_lines:list[str] = []
    for block in blocks:
        ip_str = ""
        regs: list[str] = []
        for line in block:
            if line.startswith("r"):
                strs = line.split()
                if strs[0] != "rip":
                    regs.append(strs[1])
            elif line.startswith("Breakpoint"):
                ip_str = re.search(r"Breakpoint \d+, (\w+)", line).group(1)

        code_lines.append(f"{ip_str}:{str.join(',', regs)}")

    # Write out file
    f = open(output_file, mode='w')
    f.write(str.join("\n", code_lines))
    f.close()

if __name__ == "__main__":
    main()
