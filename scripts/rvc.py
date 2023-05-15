# Preprocess an assemply file and output a c file

import os
import sys
import argparse

from iced_x86 import *

def main():
    # Parse args
    parser = argparse.ArgumentParser(
        description="Setup vcpkg for this project.")
    parser.add_argument("-o",
                        "--out", help="Clean local caches after install.", metavar="<path>")
    parser.add_argument("files", nargs="*")
    args = parser.parse_args()

    files: list[str] = args.files
    if len(files) == 0:
        print("No source file specified.")
        sys.exit(-1)
    
    # Read assembly file
    f = open(sys.argv[1], mode='rb')
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

    basic_blocks: list[list[Instruction]] = []
    cur_block: list[Instruction] = []

    for instr in decoder:
        


if __name__ == "__main__":
    main()
