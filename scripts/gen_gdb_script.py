from __future__ import annotations

import os
import sys
import argparse

from iced_common import *


def main():
    # Parse args
    parser = argparse.ArgumentParser(
        description="Generate gdb script file breaking all branch instructions.")
    parser.add_argument("-o",
                        "--out", help="Clean local caches after install.", metavar="<path>", default="")
    parser.add_argument("files", nargs="*")
    args = parser.parse_args()

    files: list[str] = args.files
    if len(files) == 0:
        print("No source file specified.")
        sys.exit(-1)

    # Read assembly file
    f = open(files[0], mode='rb')
    code = f.read()
    f.close()

    # ============================================
    # Decode
    # ============================================
    EXAMPLE_CODE_BITNESS = 64
    EXAMPLE_CODE_RIP = 0x401000
    EXAMPLE_CODE = code

    # Create the decoder and initialize RIP
    decoder = Decoder(EXAMPLE_CODE_BITNESS, EXAMPLE_CODE, ip=EXAMPLE_CODE_RIP)

    formatter = Formatter(FormatterSyntax.GAS)
    formatter.digit_separator = "`"
    formatter.first_operand_char_index = 10

    info_factory = InstructionInfoFactory()

    code_lines: list[str] = []

    debug_region_start = 0x4010ba
    debug_state = 0

    for instr in decoder:
        disasm = formatter.format(instr)
        start_index = instr.ip - EXAMPLE_CODE_RIP
        bytes_str = EXAMPLE_CODE[start_index:start_index +
                                             instr.len].hex().upper()
        if bytes_str == "0000":
            break

        if instr.flow_control in [FlowControl.INDIRECT_BRANCH, FlowControl.CONDITIONAL_BRANCH,
                                  FlowControl.UNCONDITIONAL_BRANCH, FlowControl.CALL, FlowControl.RETURN]:
            print(
                f"Branch instruction: 0x{instr.ip:X}, {mnemonic_to_string(instr.mnemonic)}")
            code_lines += [
                f"break *0x{instr.ip:X}"
            ]

            if debug_state > 0:
                debug_state = 2

        elif instr.ip >= debug_region_start and debug_state < 2:
            print(
                f"Critical instruction: 0x{instr.ip:X}, {mnemonic_to_string(instr.mnemonic)}")
            code_lines += [
                f"break *0x{instr.ip:X}"
            ]

            debug_state = 1

    code_lines += [
        "run",
        "while 1",
        "    info all-registers rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15 rip eflags cs ss ds es fs gs",
        "    continue",
        "end",
    ]

    out_file = str(os.path.basename(args.out)).split(".")[
        0] if args.out == "" else args.out

    # Write out file
    f = open(out_file, mode='w')
    f.write(str.join("\n", code_lines))
    f.close()


if __name__ == "__main__":
    main()
