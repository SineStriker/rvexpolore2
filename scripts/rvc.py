# Preprocess an binary file and output a source file

from __future__ import annotations

import os
import sys
import argparse

from iced_common import *


def main():
    # Parse args
    parser = argparse.ArgumentParser(
        description="Generate interpretation source of binary.")
    parser.add_argument("-o",
                        "--out", help="Clean local caches after install.", metavar="<path>", default="")
    parser.add_argument("-e",
                        "--entry", help="Specify entry.", metavar="<address>", default="0x401000")
    parser.add_argument("--native-call", dest="native_call", help="Push native return address when calling",
                        action="store_true", default=False)
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

    native_call: bool = args.native_call

    # Create the decoder and initialize RIP
    decoder = Decoder(EXAMPLE_CODE_BITNESS, EXAMPLE_CODE, ip=EXAMPLE_CODE_RIP)

    formatter = Formatter(FormatterSyntax.GAS)
    formatter.digit_separator = "`"
    formatter.first_operand_char_index = 10

    info_factory = InstructionInfoFactory()

    # Divide basic blocks
    basic_blocks: list[list[Instruction]] = []
    cur_block: list[Instruction] = []
    possible_labels: list[int] = []

    available_instrs: list[Instruction] = []
    for instr in decoder:
        disasm = formatter.format(instr)
        start_index = instr.ip - EXAMPLE_CODE_RIP
        bytes_str = EXAMPLE_CODE[start_index:start_index +
                                             instr.len].hex().upper()
        if bytes_str == "0000":
            break

        available_instrs.append(instr)

        print(
            f"{instr.ip:016X} {bytes_str:20} {disasm:40} {flow_control_to_string(instr.flow_control):30} {mnemonic_to_string(instr.mnemonic)}")

        # if (instr.mnemonic == Mnemonic.ENDBR32 or instr.mnemonic == Mnemonic.ENDBR64 or instr.mnemonic == Mnemonic.NOP):
        #     continue

        # Collect possible targets
        if instr.flow_control == FlowControl.CONDITIONAL_BRANCH or instr.flow_control == FlowControl.UNCONDITIONAL_BRANCH or instr.flow_control == FlowControl.CALL:
            op_kind = instr.op_kind(0)
            if op_kind == OpKind.NEAR_BRANCH64:
                possible_labels.append(instr.near_branch64)

    for instr in available_instrs:
        maybe_label: bool = instr.mnemonic == Mnemonic.ENDBR32 or instr.mnemonic == Mnemonic.ENDBR64 or (
                instr.ip in possible_labels)

        if not maybe_label:
            cur_block.append(instr)

        if (instr.flow_control != FlowControl.NEXT and instr.mnemonic != Mnemonic.SYSCALL) or maybe_label:
            if len(cur_block) > 0:
                basic_blocks.append(cur_block)
                cur_block = []

        if maybe_label:
            cur_block.append(instr)

    # ============================================
    # Generate Functions
    # ============================================
    class CodeLines:

        def __init__(self) -> None:
            self.code_lines: list[str] = []
            self.block_count = 0

        def add_line(self, line: str):
            self.code_lines.append(line)

        def add_comment(self, line: str):
            self.code_lines.append("// " + line)

        def gen_function_head(self):
            self.code_lines += [
                "#include <unordered_map>",
                "",
                "#include \"common.h\"",
                "",
                "#define RVC_RUN",
                "",
                "int run(x64_cpu_state_t *cpu) {",
                "int _ret_code = 0;",
                "int32_t _op32_1 = 0;",
                "int32_t _op32_2 = 0;",
                "int64_t _op64_1 = 0;",
                "int64_t _op64_2 = 0;",
                "#define RET { auto _ret_addr = MEMORY(int64_t, REG_RSP(cpu)); REG_RSP(cpu) += sizeof(int64_t); " +
                ("INDIRECT_JUMP(_ret_addr)" if not native_call else "goto *((void *) _ret_addr);") + "}",
            ]

        def gen_function_end(self):
            self.code_lines += [
                # "#ifdef INDIRECT_JUMP",
                # "#undef INDIRECT_JUMP",
                # "#endif",
                "return _ret_code;",
                "}"
            ]

        def gen_scope_head(self):
            self.code_lines += [
                "{"
            ]

        def gen_scope_end(self):
            self.code_lines += [
                "}"
            ]

        def gen_ip_label(self, ip: int):
            self.code_lines += [
                f"{ip_label(ip)}:"
            ]

        def gen_new_line(self):
            self.code_lines += [
                ""
            ]

        def gen_instr_head(self, instr: Instruction):
            disasm = formatter.format(instr)
            start_index = instr.ip - EXAMPLE_CODE_RIP
            bytes_str = EXAMPLE_CODE[start_index:start_index +
                                                 instr.len].hex().upper()
            self.code_lines += [
                f"// {instr.ip:016X} {bytes_str:30} {disasm:40}",
            ]

        def gen_block_head(self, instr: Instruction, instr_head: bool = False):
            self.block_count += 1
            self.code_lines += [
                f"// Basic block {self.block_count}",
            ]

            if instr_head:
                self.gen_instr_head(instr)
            self.gen_ip_label(instr.ip)

        def gen_mov(self, instr: Instruction, lea: bool = False):
            if instr.op0_kind == OpKind.REGISTER and RegisterExt.size(instr.op0_register) == 4:
                dest, src, _ = get_ops_u(instr, lea)
                dest = to_cpu_reg(RegisterExt.full_register(instr.op0_register))
                self.add_line(f"{dest} = {src};")
            else:
                dest, src, _ = get_ops(instr, lea)
                code_lines.add_line(f"{dest} = {src};")

        def gen_branch(self, instr: Instruction):
            op_kind = instr.op_kind(0)
            if op_kind == OpKind.REGISTER:
                self.add_line(
                    f"INDIRECT_JUMP({to_cpu_reg(instr.op_register(0))})")
            elif op_kind == OpKind.NEAR_BRANCH64:
                self.add_line(
                    f"goto {ip_label(instr.near_branch64)};")

        def gen_conditional_mov(self, instr: Instruction, last_cond: ALUOperate, op: str, signed: bool = True):
            self.gen_conditional_compare(last_cond, op, signed)
            self.gen_mov(instr)

        def gen_conditional_branch(self, last_cond: ALUOperate, op: str, signed: bool = True):
            self.gen_conditional_compare(last_cond, op, signed)
            self.gen_scope_head()
            self.gen_branch(instr)
            self.gen_scope_end()

        def gen_conditional_compare(self, last_cond: ALUOperate, op: str, signed: bool = True):
            if last_cond is None:
                self.add_comment("WARNING: last operation not available")
                return

            if not last_cond.test:
                self.add_line(f"if ({last_cond.dest} {op} 0)")
                return

            if signed:
                int_type = get_int_type(last_cond.size)
                # self.add_line(f"if ({dest} {op} {src})")
                self.add_line(f"if (({int_type}({last_cond.dest}) {last_cond.op} {int_type}({last_cond.src})) {op} 0)")
            else:
                uint_type = get_uint_type(last_cond.size)
                self.add_line(
                    f"if ((({uint_type}({last_cond.dest}) {last_cond.op} {uint_type}({last_cond.src})) {op} 0)")

        # def gen_post_zero_extend(self, instr: Instruction):
        #     if instr.op0_kind == OpKind.REGISTER and RegisterExt.size(instr.op0_register) == 4:
        #         dest = to_cpu_reg(RegisterExt.full_register(instr.op0_register))
        #         # self.add_line(f"{dest} &= 0x00000000FFFFFFFF;")

        def gen_jump_table(self, ips: list[int]):
            tables: list[str] = []
            key_values: list[str] = []
            for ip in ips:
                label = "&&" + ip_label(ip)
                tables.append(label)
                key_values.append(f"{{{ip}, {label}}}")
            tables_str = str.join(', ', tables)
            key_values_str = str.join(', ', key_values)

            self.code_lines += [
                f"static void *jump_table[] = {{ {tables_str} }};",
                f"static std::unordered_map<uint64_t, void *> jump_table_hash = {{ {key_values_str} }};",
                f"static int jump_table_len = {len(tables)};",
                # f"int last_jump_index = -1;",
                # f"void *last_jump_address = nullptr;",
                # "auto indirect_jump = [&](uint64_t ip) {",
                # "if (last_jump_index != ip) {",
                # f"    auto it = jump_table_hash.find(ip);"
                # f"    if (it == jump_table_hash.end())"
                # f"        error(\"Invalid branch address!!!\");"
                # f"    last_jump_index = ip;",
                # f"    last_jump_address = it->second;",
                # "}",
                # "};",
                # "#define INDIRECT_JUMP(ip) indirect_jump(ip); goto *last_jump_address;"
                "#include \"jump_table.h\"",
            ]

    def ip_label(ip: int):
        return f"lab_{ip:016X}"

    def to_cpu_reg(reg: Register):
        return f"REG_{register_to_string(reg)}(cpu)"

    def addressing(instr: Instruction):
        if instr.memory_base == Register.RIP:
            return f"0x{instr.memory_displacement:X}"

        sb = ""
        need_plus = instr.memory_base != Register.NONE
        if need_plus:
            sb += to_cpu_reg(instr.memory_base)
        if instr.memory_index != Register.NONE:
            if need_plus:
                sb += "+"
            need_plus = True
            sb += to_cpu_reg(instr.memory_index)
            if instr.memory_index_scale != 1:
                sb += "*" + str(instr.memory_index_scale)
        if instr.memory_displacement != 0 or not need_plus:
            if need_plus:
                sb += "+"
            sb += f"0x{instr.memory_displacement:X}"

        return sb

    def get_imm(op: OpKind, instr: Instruction):
        op_kind = op
        if op_kind == OpKind.IMMEDIATE8:
            imm = instr.immediate8
        elif op_kind == OpKind.IMMEDIATE16:
            imm = instr.immediate16
        elif op_kind == OpKind.IMMEDIATE32:
            imm = instr.immediate32
        elif op_kind == OpKind.IMMEDIATE64:
            imm = instr.immediate64
        elif op_kind == OpKind.IMMEDIATE32TO64:
            imm = instr.immediate32to64
        elif op_kind == OpKind.IMMEDIATE8TO16:
            imm = instr.immediate8to16
        elif op_kind == OpKind.IMMEDIATE8TO32:
            imm = instr.immediate8to32
        elif op_kind == OpKind.IMMEDIATE8TO64:
            imm = instr.immediate8to64
        return imm

    def get_int_type(size: int):
        return f"int{size * 8}_t"

    def get_uint_type(size: int):
        return f"uint{size * 8}_t"

    def get_ops(instr: Instruction, lea: bool = False) -> tuple[str, str, int]:
        size = 8
        op_kind = instr.op0_kind
        if op_kind == OpKind.REGISTER:
            reg = instr.op_register(0)
            size = RegisterExt.size(reg)
            dest = to_cpu_reg(reg)
        elif op_kind == OpKind.MEMORY:
            size = MemorySizeExt.size(instr.memory_size)
            dest = f"MEMORY({get_int_type(size)}, {addressing(instr)})"
        else:
            dest = f"0x{get_imm(op_kind, instr):X}"

        dst_size = size

        op_kind = instr.op1_kind
        if op_kind == OpKind.REGISTER:
            reg = instr.op_register(1)
            size = RegisterExt.size(reg)
            src = to_cpu_reg(reg)
        elif op_kind == OpKind.MEMORY:
            # size = MemorySizeExt.size(instr.memory_size)
            src = f"MEMORY({get_int_type(size)}, {addressing(instr)})" if not lea else f"{get_int_type(size)}({addressing(instr)})"
        else:
            src = f"0x{get_imm(op_kind, instr):X}"

        return dest, src, dst_size

    def get_ops_u(instr: Instruction, lea: bool = False) -> tuple[str, str, int]:
        size = 8
        op_kind = instr.op0_kind
        if op_kind == OpKind.REGISTER:
            reg = instr.op_register(0)
            size = RegisterExt.size(reg)
            dest = to_cpu_reg(reg)
        elif op_kind == OpKind.MEMORY:
            size = MemorySizeExt.size(instr.memory_size)
            dest = f"MEMORY({get_uint_type(size)}, {addressing(instr)})"
        else:
            dest = f"0x{get_imm(op_kind, instr):X}"

        dst_size = size

        op_kind = instr.op1_kind
        if op_kind == OpKind.REGISTER:
            reg = instr.op_register(1)
            size = RegisterExt.size(reg)
            src = f"{get_uint_type(size)}({to_cpu_reg(reg)})"
        elif op_kind == OpKind.MEMORY:
            # size = MemorySizeExt.size(instr.memory_size)
            src = f"MEMORY({get_uint_type(size)}, {addressing(instr)})" if not lea else f"{get_uint_type(size)}({addressing(instr)})"
        else:
            src = f"0x{get_imm(op_kind, instr):X}"

        return dest, src, dst_size

        # Assume instr is an Instruction instance with Mnemonic.LEA
        # Get the number of operands
        # op_count = instr.op_count

        # # Initialize an empty list to store the address expression components
        # addr_expr = []

        # # Loop through each operand
        # for i in range(op_count):
        #     # Get the operand kind
        #     op_kind = instr.op_kind(i)

        #     # If the operand is a register
        #     if op_kind == OpKind.REGISTER:
        #         # Get the register enum value
        #         reg = instr.op_register(i)

        #         # Append the register name to the address expression list
        #         addr_expr.append(register_to_string(reg))

        #     # If the operand is a memory
        #     elif op_kind == OpKind.MEMORY:
        #         # Get the base register
        #         base = instr.memory_base

        #         # Get the index register
        #         index = instr.memory_index

        #         # Get the displacement
        #         disp = instr.memory_displacement

        #         # Get the scale factor
        #         scale = instr.memory_index_scale

        #         # Get the segment register
        #         seg = instr.memory_segment

        #         # Get the memory size
        #         size = instr.memory_size

        #         # If there is a segment register, append it to the address expression list
        #         if seg != Register.NONE:
        #             addr_expr.append(register_to_string(seg) + ":")

        #         # Append the memory size to the address expression list
        #         addr_expr.append(memory_size_to_string(size))

        #         # Append an opening bracket to the address expression list
        #         addr_expr.append("[")

        #         # If there is a base register, append it to the address expression list
        #         if base != Register.NONE:
        #             addr_expr.append(register_to_string(base))

        #         # If there is an index register, append it and the scale factor to the address expression list
        #         if index != Register.NONE:
        #             addr_expr.append("+" + register_to_string(index))
        #             if scale != 1:
        #                 addr_expr.append("*" + str(scale))

        #         # If there is a displacement, append it to the address expression list
        #         if disp != 0:
        #             if disp > 0:
        #                 addr_expr.append("+" + hex(disp))
        #             else:
        #                 addr_expr.append("-" + hex(-disp))

        #         # Append a closing bracket to the address expression list
        #         addr_expr.append("]")

        #     # If the operand is something else, skip it or handle it as needed
        #     else:
        #         continue

        # # Join the address expression list with spaces and print it
        # code_lines.add_line(" ".join(addr_expr))

    # ============================================
    # Generate
    # ============================================
    code_lines = CodeLines()

    debug_region_start = 0x4010ba
    debug_state = 0

    # -- Head
    code_lines.gen_function_head()

    # -- Jump table
    labels: list[int] = []
    for block in basic_blocks:
        labels.append(block[0].ip)
    code_lines.gen_jump_table(labels)
    code_lines.gen_new_line()

    # Entry point
    code_lines.add_comment("Entry point")
    code_lines.add_line(f"goto {ip_label(int(args.entry, 16))};")
    code_lines.gen_new_line()

    class ALUOperate:
        def __init__(self, dest: str, src: str, op: str, size: int, test: bool = False):
            self.dest = dest
            self.src = src
            self.size = size
            self.op = op
            self.test = test

    last_cond: ALUOperate = None

    # Parse instructions
    for block in basic_blocks:
        code_lines.gen_block_head(block[0])
        code_lines.gen_scope_head()

        for instr in block:

            print(f"Processing instruction: 0x{instr.ip:X}")
            # code_lines.add_line(f"DEBUG(\"{instr.ip:X}, sp: %ld\\n\", {to_cpu_reg(Register.RSP)});")

            # Debug use
            if instr.flow_control in [FlowControl.INDIRECT_BRANCH, FlowControl.CONDITIONAL_BRANCH,
                                      FlowControl.UNCONDITIONAL_BRANCH, FlowControl.CALL, FlowControl.RETURN]:
                code_lines.add_line(f"dump_state(0x{instr.ip:X}, cpu);")
                if debug_state > 0:
                    debug_state = 2
            elif instr.ip >= debug_region_start and debug_state < 2:
                code_lines.add_line(f"dump_state(0x{instr.ip:X}, cpu);")
                debug_state = 1

            info = info_factory.info(instr)

            code_lines.gen_instr_head(instr)

            code_lines.add_comment(f"Op count: {instr.op_count}")

            # code_lines.add_line(f"#define REG_RIP(cpu) 0x{instr.ip:X}")
            if instr.mnemonic == Mnemonic.ENDBR32 or instr.mnemonic == Mnemonic.ENDBR64 or instr.mnemonic == Mnemonic.NOP:
                code_lines.add_comment("Nothing to do")

            elif instr.mnemonic == Mnemonic.ADD:
                dest, src, size = get_ops(instr)
                code_lines.add_line(f"{dest} += {src};")
                last_cond = ALUOperate(dest, src, "+", size)
            elif instr.mnemonic == Mnemonic.SUB:
                dest, src, size = get_ops(instr)
                code_lines.add_line(f"{dest} -= {src};")
                last_cond = ALUOperate(dest, src, "-", size)
            elif instr.mnemonic == Mnemonic.MUL:
                dest, src, size = get_ops(instr)
                # if size == 1:
                #     code_lines.add_line(f"{dest} *= {src};")
                # elif size == 2:
                #     code_lines.add_line(f"_op32_1 *= int64_t({dest}) * {src};")
                #     code_lines.add_line(f"{to_cpu_reg(Register.AX)} = _op32_1;")
                #     code_lines.add_line(f"{to_cpu_reg(Register.DX)} = _op32_1 >> 16;)")
                # elif size == 4:
                #     code_lines.add_line(f"_op64_1 *= int64_t({dest}) * {src};")
                #     code_lines.add_line(f"{to_cpu_reg(Register.EAX)} = _op64_1;")
                #     code_lines.add_line(f"{to_cpu_reg(Register.EDX)} = _op64_1 >> 32;)")
                # else:
                if instr.op_count == 3:
                    imm_str = f"0x{get_imm(instr.op_kind(2), instr):X}"
                    code_lines.add_line(f"{dest} = {src} * {imm_str};")
                    last_cond = ALUOperate(src, imm_str, "*", size)
                else:
                    code_lines.add_line(f"{dest} *= {src};")
                    last_cond = ALUOperate(dest, src, "*", size)

            elif instr.mnemonic == Mnemonic.IMUL:
                dest, src, size = get_ops(instr)
                uint_type = get_uint_type(size)

                if instr.op_count == 3:
                    imm_str = f"0x{get_imm(instr.op_kind(2), instr):X}"
                    code_lines.add_line(
                        f"*({uint_type} *) (&{dest}) = {uint_type}({src}) * {imm_str};")
                    last_cond = ALUOperate(src, imm_str, "*", size)
                else:
                    code_lines.add_line(
                        f"*({uint_type} *) (&{dest}) *= {uint_type}({src});")
                    last_cond = ALUOperate(dest, src, "*", size)

            elif instr.mnemonic == Mnemonic.DIV:
                dest, src, size = get_ops(instr)
                code_lines.add_line(f"{dest} /= {src};")
                last_cond = ALUOperate(dest, src, "/", size)
            elif instr.mnemonic == Mnemonic.IDIV:
                dest, src, size = get_ops(instr)
                uint_type = get_uint_type(size)
                code_lines.add_line(
                    f"*({uint_type} *) (&{dest}) /= {uint_type}({src});")
                last_cond = ALUOperate(dest, src, "/", size)
            elif instr.mnemonic == Mnemonic.SAL:
                dest, src, size = get_ops(instr)
                code_lines.add_line(f"{dest} <<= {src};")
                last_cond = ALUOperate(dest, src, "<<", size)
            elif instr.mnemonic == Mnemonic.SAR:
                dest, src, size = get_ops(instr)
                code_lines.add_line(f"{dest} >>= {src};")
                last_cond = ALUOperate(dest, src, ">>", size)
            elif instr.mnemonic == Mnemonic.SHL:
                dest, src, size = get_ops(instr)
                uint_type = get_uint_type(size)
                code_lines.add_line(
                    f"*({uint_type} *) (&{dest}) <<= {uint_type}({src});")
                last_cond = ALUOperate(dest, src, "<<", size)
            elif instr.mnemonic == Mnemonic.SHR:
                dest, src, size = get_ops(instr)
                uint_type = get_uint_type(size)
                code_lines.add_line(
                    f"*({uint_type} *) (&{dest}) >>= {uint_type}({src});")
                last_cond = ALUOperate(dest, src, ">>", size)

            elif instr.mnemonic == Mnemonic.XOR:
                dest, src, size = get_ops(instr)
                code_lines.add_line(f"{dest} ^= {src};")
                last_cond = ALUOperate(dest, src, "^", size)
            elif instr.mnemonic == Mnemonic.OR:
                dest, src, size = get_ops(instr)
                code_lines.add_line(f"{dest} |= {src};")
                last_cond = ALUOperate(dest, src, "|", size)
            elif instr.mnemonic == Mnemonic.AND:
                dest, src, size = get_ops(instr)
                code_lines.add_line(f"{dest} &= {src};")
                last_cond = ALUOperate(dest, src, "&", size)

            elif instr.mnemonic == Mnemonic.CMP:
                dest, src, size = get_ops(instr)
                last_cond = ALUOperate(dest, src, "-", size, True)

            elif instr.mnemonic == Mnemonic.TEST:
                dest, src, size = get_ops(instr)
                last_cond = ALUOperate(dest, src, "&", size, True)

            elif instr.mnemonic == Mnemonic.INC:
                dest, _, size = get_ops(instr)
                code_lines.add_line(f"{dest}++;")
                last_cond = ALUOperate(dest, "1", "+", size)
            elif instr.mnemonic == Mnemonic.DEC:
                dest, _, size = get_ops(instr)
                code_lines.add_line(f"{dest}--;")
                last_cond = ALUOperate(dest, "1", "-", size)
            elif instr.mnemonic == Mnemonic.NEG:
                dest, _, size = get_ops(instr)
                code_lines.add_line(f"{dest} = -{dest};")
                last_cond = ALUOperate("", dest, "-", size)
            elif instr.mnemonic == Mnemonic.NOT:
                dest, _, size = get_ops(instr)
                code_lines.add_line(f"{dest} = ~{dest};")
                last_cond = ALUOperate("", dest, "~", size)

            elif instr.mnemonic == Mnemonic.PUSH:
                reg = instr.op0_register
                int_type = get_int_type(RegisterExt.size(reg))
                code_lines.add_line(f"{to_cpu_reg(Register.RSP)} -= sizeof({int_type});")
                code_lines.add_line(f"MEMORY({int_type}, {to_cpu_reg(Register.RSP)}) = {to_cpu_reg(reg)};")

            elif instr.mnemonic == Mnemonic.POP:
                reg = instr.op0_register
                int_type = get_int_type(RegisterExt.size(reg))
                code_lines.add_line(f"{to_cpu_reg(reg)} = MEMORY({int_type}, {to_cpu_reg(Register.RSP)});")
                code_lines.add_line(f"{to_cpu_reg(Register.RSP)} += sizeof({int_type});")

            elif instr.mnemonic == Mnemonic.ENTER:
                # Push bp
                reg = Register.RBP
                int_type = get_int_type(RegisterExt.size(reg))
                code_lines.add_line(f"{to_cpu_reg(Register.RSP)} -= sizeof({int_type});")
                code_lines.add_line(f"MEMORY({int_type}, {to_cpu_reg(Register.RSP)}) = {to_cpu_reg(reg)};")

                # Mov bp, sp
                code_lines.add_line(f"{to_cpu_reg(Register.RBP)} = {to_cpu_reg(Register.RSP)};")

            elif instr.mnemonic == Mnemonic.LEAVE:
                # Mov sp, bp
                code_lines.add_line(f"{to_cpu_reg(Register.RSP)} = {to_cpu_reg(Register.RBP)};")

                # Pop bp
                reg = Register.RBP
                int_type = get_int_type(RegisterExt.size(reg))
                code_lines.add_line(f"{to_cpu_reg(reg)} = MEMORY({int_type}, {to_cpu_reg(Register.RSP)});")
                code_lines.add_line(f"{to_cpu_reg(Register.RSP)} += sizeof({int_type});")

            elif instr.mnemonic == Mnemonic.LEA:
                code_lines.gen_mov(instr, True)
            elif instr.mnemonic == Mnemonic.MOV:
                code_lines.gen_mov(instr)

            elif instr.mnemonic == Mnemonic.MOVZX:
                dest, src, size = get_ops_u(instr)
                uint_type = get_uint_type(size)
                code_lines.add_line(f"*({uint_type} *) (&{dest}) = {uint_type}({src});")
                # code_lines.gen_post_zero_extend(instr)

            elif instr.mnemonic == Mnemonic.MOVSX or instr.mnemonic == Mnemonic.MOVSXD:
                dest, src, size = get_ops(instr)
                int_type = get_int_type(size)
                code_lines.add_line(f"*({int_type} *) (&{dest}) = {int_type}({src});")
                # code_lines.gen_post_zero_extend(instr)

            elif instr.mnemonic == Mnemonic.CALL:
                # Push return address
                ret_addr = instr.ip + instr.len
                int_type = "int64_t"

                # code_lines.add_line(
                #     f"DEBUG(\"{instr.ip:X} Call {instr.near_branch64:X}, sp=%ld\\n\", {to_cpu_reg(Register.RSP)});")

                code_lines.add_line(
                    f"{to_cpu_reg(Register.RSP)} -= sizeof({int_type});")
                if not native_call:
                    code_lines.add_line(
                        f"MEMORY({int_type}, {to_cpu_reg(Register.RSP)}) = 0x{ret_addr:X};")
                else:
                    code_lines.add_line(
                        f"MEMORY({int_type}, {to_cpu_reg(Register.RSP)}) = {int_type}(&&{ip_label(ret_addr)});")

                code_lines.gen_branch(instr)

            elif instr.mnemonic == Mnemonic.RET:
                # code_lines.add_line(f"DEBUG(\"{instr.ip:X} Return, sp=%ld\\n\", {to_cpu_reg(Register.RSP)});")

                code_lines.add_line(f"RET")

            elif instr.mnemonic == Mnemonic.SYSCALL:
                code_lines.add_line(f"syscall(cpu);")

            elif instr.mnemonic == Mnemonic.JMP:
                code_lines.gen_branch(instr)

            elif instr.mnemonic == Mnemonic.JE:
                code_lines.gen_conditional_branch(last_cond, "==")
            elif instr.mnemonic == Mnemonic.JNE:
                code_lines.gen_conditional_branch(last_cond, "!=")
            elif instr.mnemonic == Mnemonic.JG:
                code_lines.gen_conditional_branch(last_cond, ">")
            elif instr.mnemonic == Mnemonic.JGE or instr.mnemonic == Mnemonic.JNS:
                code_lines.gen_conditional_branch(last_cond, ">=")
            elif instr.mnemonic == Mnemonic.JL or instr.mnemonic == Mnemonic.JS:
                code_lines.gen_conditional_branch(last_cond, "<")
            elif instr.mnemonic == Mnemonic.JLE:
                code_lines.gen_conditional_branch(last_cond, "<=")
            elif instr.mnemonic == Mnemonic.JA:
                code_lines.gen_conditional_branch(last_cond, ">", False)
            elif instr.mnemonic == Mnemonic.JAE:
                code_lines.gen_conditional_branch(last_cond, ">=", False)
            elif instr.mnemonic == Mnemonic.JB:
                code_lines.gen_conditional_branch(last_cond, "<", False)
            elif instr.mnemonic == Mnemonic.JBE:
                code_lines.gen_conditional_branch(last_cond, "<=", False)

            elif instr.mnemonic == Mnemonic.CMOVE:
                code_lines.gen_conditional_mov(instr, last_cond, "==")
            elif instr.mnemonic == Mnemonic.CMOVNE:
                code_lines.gen_conditional_mov(instr, last_cond, "!=")
            elif instr.mnemonic == Mnemonic.CMOVG:
                code_lines.gen_conditional_mov(instr, last_cond, ">")
            elif instr.mnemonic == Mnemonic.CMOVGE or instr.mnemonic == Mnemonic.CMOVNS:
                code_lines.gen_conditional_mov(instr, last_cond, ">=")
            elif instr.mnemonic == Mnemonic.CMOVL or instr.mnemonic == Mnemonic.CMOVS:
                code_lines.gen_conditional_mov(instr, last_cond, "<")
            elif instr.mnemonic == Mnemonic.CMOVLE:
                code_lines.gen_conditional_mov(instr, last_cond, "<=")
            elif instr.mnemonic == Mnemonic.CMOVA:
                code_lines.gen_conditional_mov(instr, last_cond, ">", False)
            elif instr.mnemonic == Mnemonic.CMOVAE:
                code_lines.gen_conditional_mov(instr, last_cond, ">=", False)
            elif instr.mnemonic == Mnemonic.CMOVB:
                code_lines.gen_conditional_mov(instr, last_cond, "<", False)
            elif instr.mnemonic == Mnemonic.CMOVBE:
                code_lines.gen_conditional_mov(instr, last_cond, "<=", False)

            elif instr.mnemonic == Mnemonic.CDQ:
                code_lines.add_line(
                    f"{to_cpu_reg(Register.EDX)} = int32_t(!({to_cpu_reg(Register.EAX)} & 0x80000000)) - 1;")

            elif instr.mnemonic == Mnemonic.CDQE:
                code_lines.add_line(f"{to_cpu_reg(Register.RAX)} = int64_t({to_cpu_reg(Register.EAX)});")

            elif instr.mnemonic in [
                Mnemonic.SETE, Mnemonic.SETNE, Mnemonic.SETS, Mnemonic.SETNS, Mnemonic.SETG, Mnemonic.SETGE,
                Mnemonic.SETL, Mnemonic.SETLE, Mnemonic.SETA, Mnemonic.SETAE, Mnemonic.SETB, Mnemonic.SETBE
            ]:
                last_cond = None

            else:
                code_lines.add_comment(f"WARNING: unknown instruction {mnemonic_to_string(instr.mnemonic)}")

            # code_lines.add_line(f"#undef REG_RIP")

            code_lines.gen_new_line()

        code_lines.gen_scope_end()
        code_lines.gen_new_line()

    # -- End
    code_lines.gen_function_end()

    out_file = str(os.path.basename(args.out)).split(".")[
        0] if args.out == "" else args.out

    # Write out file
    f = open(out_file, mode='w')
    f.write(str.join("\n", code_lines.code_lines))
    f.close()


if __name__ == "__main__":
    main()
