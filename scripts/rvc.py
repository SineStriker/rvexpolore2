# Preprocess an assemply file and output a c file

import os
import sys
import argparse


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
    
    


if __name__ == "__main__":
    main()
