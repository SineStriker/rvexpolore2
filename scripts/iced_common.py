from iced_x86 import *
from typing import Dict, Sequence
from types import ModuleType

def rflags_bits_to_string(rf: int) -> str:
    def append(sb: str, s: str) -> str:
        if len(sb) != 0:
            sb += ", "
        return sb + s

    sb = ""
    if (rf & RflagsBits.OF) != 0:
        sb = append(sb, "OF")
    if (rf & RflagsBits.SF) != 0:
        sb = append(sb, "SF")
    if (rf & RflagsBits.ZF) != 0:
        sb = append(sb, "ZF")
    if (rf & RflagsBits.AF) != 0:
        sb = append(sb, "AF")
    if (rf & RflagsBits.CF) != 0:
        sb = append(sb, "CF")
    if (rf & RflagsBits.PF) != 0:
        sb = append(sb, "PF")
    if (rf & RflagsBits.DF) != 0:
        sb = append(sb, "DF")
    if (rf & RflagsBits.IF) != 0:
        sb = append(sb, "IF")
    if (rf & RflagsBits.AC) != 0:
        sb = append(sb, "AC")
    if (rf & RflagsBits.UIF) != 0:
        sb = append(sb, "UIF")
    if len(sb) == 0:
        return "<empty>"
    return sb

def create_enum_dict(module: ModuleType) -> Dict[int, str]:
    return {module.__dict__[key]:key for key in module.__dict__ if isinstance(module.__dict__[key], int)}

REGISTER_TO_STRING: Dict[Register_, str] = create_enum_dict(Register)
def register_to_string(value: Register_) -> str:
    s = REGISTER_TO_STRING.get(value)
    if s is None:
        return str(value) + " /*Register enum*/"
    return s

OP_ACCESS_TO_STRING: Dict[OpAccess_, str] = create_enum_dict(OpAccess)
def op_access_to_string(value: OpAccess_) -> str:
    s = OP_ACCESS_TO_STRING.get(value)
    if s is None:
        return str(value) + " /*OpAccess enum*/"
    return s

ENCODING_KIND_TO_STRING: Dict[EncodingKind_, str] = create_enum_dict(EncodingKind)
def encoding_kind_to_string(value: EncodingKind_) -> str:
    s = ENCODING_KIND_TO_STRING.get(value)
    if s is None:
        return str(value) + " /*EncodingKind enum*/"
    return s

MNEMONIC_TO_STRING: Dict[Mnemonic_, str] = create_enum_dict(Mnemonic)
def mnemonic_to_string(value: Mnemonic_) -> str:
    s = MNEMONIC_TO_STRING.get(value)
    if s is None:
        return str(value) + " /*Mnemonic enum*/"
    return s

CODE_TO_STRING: Dict[Code_, str] = create_enum_dict(Code)
def code_to_string(value: Code_) -> str:
    s = CODE_TO_STRING.get(value)
    if s is None:
        return str(value) + " /*Code enum*/"
    return s

FLOW_CONTROL_TO_STRING: Dict[FlowControl_, str] = create_enum_dict(FlowControl)
def flow_control_to_string(value: FlowControl_) -> str:
    s = FLOW_CONTROL_TO_STRING.get(value)
    if s is None:
        return str(value) + " /*FlowControl enum*/"
    return s

OP_CODE_OPERAND_KIND_TO_STRING: Dict[OpCodeOperandKind_, str] = create_enum_dict(OpCodeOperandKind)
def op_code_operand_kind_to_string(value: OpCodeOperandKind_) -> str:
    s = OP_CODE_OPERAND_KIND_TO_STRING.get(value)
    if s is None:
        return str(value) + " /*OpCodeOperandKind enum*/"
    return s

CPUID_FEATURE_TO_STRING: Dict[CpuidFeature_, str] = create_enum_dict(CpuidFeature)
def cpuid_feature_to_string(value: CpuidFeature_) -> str:
    s = CPUID_FEATURE_TO_STRING.get(value)
    if s is None:
        return str(value) + " /*CpuidFeature enum*/"
    return s

def cpuid_features_to_string(cpuid_features: Sequence[int]) -> str:
    return " and ".join([cpuid_feature_to_string(f) for f in cpuid_features])

MEMORY_SIZE_TO_STRING: Dict[MemorySize_, str] = create_enum_dict(MemorySize)
def memory_size_to_string(value: MemorySize_) -> str:
    s = MEMORY_SIZE_TO_STRING.get(value)
    if s is None:
        return str(value) + " /*MemorySize enum*/"
    return s

CONDITION_CODE_TO_STRING: Dict[ConditionCode_, str] = create_enum_dict(ConditionCode)
def condition_code_to_string(value: ConditionCode_) -> str:
    s = CONDITION_CODE_TO_STRING.get(value)
    if s is None:
        return str(value) + " /*ConditionCode enum*/"
    return s

def used_reg_to_string(reg_info: UsedRegister) -> str:
    return register_to_string(reg_info.register) + ":" + op_access_to_string(reg_info.access)

def used_mem_to_string(mem_info: UsedMemory) -> str:
    sb = "[" + register_to_string(mem_info.segment) + ":"
    need_plus = mem_info.base != Register.NONE
    if need_plus:
        sb += register_to_string(mem_info.base)
    if mem_info.index != Register.NONE:
        if need_plus:
            sb += "+"
        need_plus = True
        sb += register_to_string(mem_info.index)
        if mem_info.scale != 1:
            sb += "*" + str(mem_info.scale)
    if mem_info.displacement != 0 or not need_plus:
        if need_plus:
            sb += "+"
        sb += f"0x{mem_info.displacement:X}"
    sb += ";" + memory_size_to_string(mem_info.memory_size) + ";" + op_access_to_string(mem_info.access) + "]"
    return sb