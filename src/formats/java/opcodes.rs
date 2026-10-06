//! JVM instruction set: mnemonics and operand sizes.

/// How an instruction's operands are encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operands {
    /// No operands.
    None,
    /// A signed byte (`bipush`, `newarray` uses an unsigned type code).
    I8,
    /// A signed 16-bit value (`sipush`).
    I16,
    /// An unsigned byte local variable index.
    Local,
    /// `iinc`: local index and signed byte constant.
    Iinc,
    /// A one-byte constant pool index (`ldc`).
    Cp8,
    /// A two-byte constant pool index.
    Cp16,
    /// `invokeinterface`: index, count, 0.
    Interface,
    /// `invokedynamic`: index, 0, 0.
    Dynamic,
    /// `multianewarray`: index, dimensions.
    Multi,
    /// `newarray`: primitive type code.
    ArrayType,
    /// A signed 16-bit branch offset.
    Branch16,
    /// A signed 32-bit branch offset.
    Branch32,
    TableSwitch,
    LookupSwitch,
    Wide,
}

use Operands::*;

/// `(mnemonic, operands)` for each opcode.
pub const OPCODES: [(&str, Operands); 256] = {
    let mut t = [("<reserved>", None); 256];
    t[0x00] = ("nop", None);
    t[0x01] = ("aconst_null", None);
    t[0x02] = ("iconst_m1", None);
    t[0x03] = ("iconst_0", None);
    t[0x04] = ("iconst_1", None);
    t[0x05] = ("iconst_2", None);
    t[0x06] = ("iconst_3", None);
    t[0x07] = ("iconst_4", None);
    t[0x08] = ("iconst_5", None);
    t[0x09] = ("lconst_0", None);
    t[0x0a] = ("lconst_1", None);
    t[0x0b] = ("fconst_0", None);
    t[0x0c] = ("fconst_1", None);
    t[0x0d] = ("fconst_2", None);
    t[0x0e] = ("dconst_0", None);
    t[0x0f] = ("dconst_1", None);
    t[0x10] = ("bipush", I8);
    t[0x11] = ("sipush", I16);
    t[0x12] = ("ldc", Cp8);
    t[0x13] = ("ldc_w", Cp16);
    t[0x14] = ("ldc2_w", Cp16);
    t[0x15] = ("iload", Local);
    t[0x16] = ("lload", Local);
    t[0x17] = ("fload", Local);
    t[0x18] = ("dload", Local);
    t[0x19] = ("aload", Local);
    t[0x1a] = ("iload_0", None);
    t[0x1b] = ("iload_1", None);
    t[0x1c] = ("iload_2", None);
    t[0x1d] = ("iload_3", None);
    t[0x1e] = ("lload_0", None);
    t[0x1f] = ("lload_1", None);
    t[0x20] = ("lload_2", None);
    t[0x21] = ("lload_3", None);
    t[0x22] = ("fload_0", None);
    t[0x23] = ("fload_1", None);
    t[0x24] = ("fload_2", None);
    t[0x25] = ("fload_3", None);
    t[0x26] = ("dload_0", None);
    t[0x27] = ("dload_1", None);
    t[0x28] = ("dload_2", None);
    t[0x29] = ("dload_3", None);
    t[0x2a] = ("aload_0", None);
    t[0x2b] = ("aload_1", None);
    t[0x2c] = ("aload_2", None);
    t[0x2d] = ("aload_3", None);
    t[0x2e] = ("iaload", None);
    t[0x2f] = ("laload", None);
    t[0x30] = ("faload", None);
    t[0x31] = ("daload", None);
    t[0x32] = ("aaload", None);
    t[0x33] = ("baload", None);
    t[0x34] = ("caload", None);
    t[0x35] = ("saload", None);
    t[0x36] = ("istore", Local);
    t[0x37] = ("lstore", Local);
    t[0x38] = ("fstore", Local);
    t[0x39] = ("dstore", Local);
    t[0x3a] = ("astore", Local);
    t[0x3b] = ("istore_0", None);
    t[0x3c] = ("istore_1", None);
    t[0x3d] = ("istore_2", None);
    t[0x3e] = ("istore_3", None);
    t[0x3f] = ("lstore_0", None);
    t[0x40] = ("lstore_1", None);
    t[0x41] = ("lstore_2", None);
    t[0x42] = ("lstore_3", None);
    t[0x43] = ("fstore_0", None);
    t[0x44] = ("fstore_1", None);
    t[0x45] = ("fstore_2", None);
    t[0x46] = ("fstore_3", None);
    t[0x47] = ("dstore_0", None);
    t[0x48] = ("dstore_1", None);
    t[0x49] = ("dstore_2", None);
    t[0x4a] = ("dstore_3", None);
    t[0x4b] = ("astore_0", None);
    t[0x4c] = ("astore_1", None);
    t[0x4d] = ("astore_2", None);
    t[0x4e] = ("astore_3", None);
    t[0x4f] = ("iastore", None);
    t[0x50] = ("lastore", None);
    t[0x51] = ("fastore", None);
    t[0x52] = ("dastore", None);
    t[0x53] = ("aastore", None);
    t[0x54] = ("bastore", None);
    t[0x55] = ("castore", None);
    t[0x56] = ("sastore", None);
    t[0x57] = ("pop", None);
    t[0x58] = ("pop2", None);
    t[0x59] = ("dup", None);
    t[0x5a] = ("dup_x1", None);
    t[0x5b] = ("dup_x2", None);
    t[0x5c] = ("dup2", None);
    t[0x5d] = ("dup2_x1", None);
    t[0x5e] = ("dup2_x2", None);
    t[0x5f] = ("swap", None);
    t[0x60] = ("iadd", None);
    t[0x61] = ("ladd", None);
    t[0x62] = ("fadd", None);
    t[0x63] = ("dadd", None);
    t[0x64] = ("isub", None);
    t[0x65] = ("lsub", None);
    t[0x66] = ("fsub", None);
    t[0x67] = ("dsub", None);
    t[0x68] = ("imul", None);
    t[0x69] = ("lmul", None);
    t[0x6a] = ("fmul", None);
    t[0x6b] = ("dmul", None);
    t[0x6c] = ("idiv", None);
    t[0x6d] = ("ldiv", None);
    t[0x6e] = ("fdiv", None);
    t[0x6f] = ("ddiv", None);
    t[0x70] = ("irem", None);
    t[0x71] = ("lrem", None);
    t[0x72] = ("frem", None);
    t[0x73] = ("drem", None);
    t[0x74] = ("ineg", None);
    t[0x75] = ("lneg", None);
    t[0x76] = ("fneg", None);
    t[0x77] = ("dneg", None);
    t[0x78] = ("ishl", None);
    t[0x79] = ("lshl", None);
    t[0x7a] = ("ishr", None);
    t[0x7b] = ("lshr", None);
    t[0x7c] = ("iushr", None);
    t[0x7d] = ("lushr", None);
    t[0x7e] = ("iand", None);
    t[0x7f] = ("land", None);
    t[0x80] = ("ior", None);
    t[0x81] = ("lor", None);
    t[0x82] = ("ixor", None);
    t[0x83] = ("lxor", None);
    t[0x84] = ("iinc", Iinc);
    t[0x85] = ("i2l", None);
    t[0x86] = ("i2f", None);
    t[0x87] = ("i2d", None);
    t[0x88] = ("l2i", None);
    t[0x89] = ("l2f", None);
    t[0x8a] = ("l2d", None);
    t[0x8b] = ("f2i", None);
    t[0x8c] = ("f2l", None);
    t[0x8d] = ("f2d", None);
    t[0x8e] = ("d2i", None);
    t[0x8f] = ("d2l", None);
    t[0x90] = ("d2f", None);
    t[0x91] = ("i2b", None);
    t[0x92] = ("i2c", None);
    t[0x93] = ("i2s", None);
    t[0x94] = ("lcmp", None);
    t[0x95] = ("fcmpl", None);
    t[0x96] = ("fcmpg", None);
    t[0x97] = ("dcmpl", None);
    t[0x98] = ("dcmpg", None);
    t[0x99] = ("ifeq", Branch16);
    t[0x9a] = ("ifne", Branch16);
    t[0x9b] = ("iflt", Branch16);
    t[0x9c] = ("ifge", Branch16);
    t[0x9d] = ("ifgt", Branch16);
    t[0x9e] = ("ifle", Branch16);
    t[0x9f] = ("if_icmpeq", Branch16);
    t[0xa0] = ("if_icmpne", Branch16);
    t[0xa1] = ("if_icmplt", Branch16);
    t[0xa2] = ("if_icmpge", Branch16);
    t[0xa3] = ("if_icmpgt", Branch16);
    t[0xa4] = ("if_icmple", Branch16);
    t[0xa5] = ("if_acmpeq", Branch16);
    t[0xa6] = ("if_acmpne", Branch16);
    t[0xa7] = ("goto", Branch16);
    t[0xa8] = ("jsr", Branch16);
    t[0xa9] = ("ret", Local);
    t[0xaa] = ("tableswitch", TableSwitch);
    t[0xab] = ("lookupswitch", LookupSwitch);
    t[0xac] = ("ireturn", None);
    t[0xad] = ("lreturn", None);
    t[0xae] = ("freturn", None);
    t[0xaf] = ("dreturn", None);
    t[0xb0] = ("areturn", None);
    t[0xb1] = ("return", None);
    t[0xb2] = ("getstatic", Cp16);
    t[0xb3] = ("putstatic", Cp16);
    t[0xb4] = ("getfield", Cp16);
    t[0xb5] = ("putfield", Cp16);
    t[0xb6] = ("invokevirtual", Cp16);
    t[0xb7] = ("invokespecial", Cp16);
    t[0xb8] = ("invokestatic", Cp16);
    t[0xb9] = ("invokeinterface", Interface);
    t[0xba] = ("invokedynamic", Dynamic);
    t[0xbb] = ("new", Cp16);
    t[0xbc] = ("newarray", ArrayType);
    t[0xbd] = ("anewarray", Cp16);
    t[0xbe] = ("arraylength", None);
    t[0xbf] = ("athrow", None);
    t[0xc0] = ("checkcast", Cp16);
    t[0xc1] = ("instanceof", Cp16);
    t[0xc2] = ("monitorenter", None);
    t[0xc3] = ("monitorexit", None);
    t[0xc4] = ("wide", Wide);
    t[0xc5] = ("multianewarray", Multi);
    t[0xc6] = ("ifnull", Branch16);
    t[0xc7] = ("ifnonnull", Branch16);
    t[0xc8] = ("goto_w", Branch32);
    t[0xc9] = ("jsr_w", Branch32);
    t[0xca] = ("breakpoint", None);
    t[0xfe] = ("impdep1", None);
    t[0xff] = ("impdep2", None);
    t
};

pub const ARRAY_TYPE: crate::value::EnumTable = &[
    (4, "boolean"),
    (5, "char"),
    (6, "float"),
    (7, "double"),
    (8, "byte"),
    (9, "short"),
    (10, "int"),
    (11, "long"),
];
