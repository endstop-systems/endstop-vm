//! The admitted instruction subset.
//!
//! Encoding: eBPF / RFC 9669, because it is documented and has existing
//! assembler and compiler tooling. Semantics: ours, normatively. Stock
//! `clang -target bpf` output is not generally admissible: LLVM's BPF target
//! is 64-bit, while this VM deliberately rejects most 64-bit operations and
//! other parts of the full ISA. A restricted source/compiler contract remains
//! product work; the loader fails closed on output outside this subset.
//!
//! ## The admission rule
//!
//! > A construct is admitted only if its semantics can be stated in one line
//! > a reviewer checks by reading, and discharged by Kani as a property of
//! > this implementation.
//!
//! Everything failing that is **deleted from the subset rather than
//! defended**. We control the whole pipeline, so ambiguity can be made
//! unreachable instead of mitigated. What that costs, and why each is worth
//! it:
//!
//! | Deleted | Because |
//! |---|---|
//! | `div`, `mod` | divide-by-zero has three different answers across eBPF, C and RV32 |
//! | signed compares | bias into unsigned at the trust boundary instead |
//! | 64-bit values | the CVE-2021-3490 shape |
//! | `lddw`, `callx` | a computed call index defeats capability confinement |
//! | atomics | single-threaded machine |
//!
//! Backward jumps are admitted in the default policy because fuel bounds every
//! execution. Callers that need a program-length WCET bound can select the
//! optional `ForwardOnly` loader policy, which rejects them.

/// An eBPF instruction is 64 bits: opcode, dst/src nibbles, offset, imm.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Insn {
    pub opcode: u8,
    /// Destination register, low nibble of the register byte.
    pub dst: u8,
    /// Source register, high nibble.
    pub src: u8,
    pub off: i16,
    pub imm: i32,
}

/// Registers. eBPF defines r0..r10; r10 is the read-only frame pointer.
pub const N_REGS: usize = 11;
/// The frame pointer register index.
pub const REG_FP: u8 = 10;

/// Instruction classes we admit, from the low three bits of the opcode.
pub const CLASS_LD: u8 = 0x00;
pub const CLASS_LDX: u8 = 0x01;
pub const CLASS_ST: u8 = 0x02;
pub const CLASS_STX: u8 = 0x03;
pub const CLASS_ALU: u8 = 0x04;
pub const CLASS_JMP: u8 = 0x05;
pub const CLASS_ALU64: u8 = 0x07;

/// ALU operations, from the top nibble.
pub const ALU_ADD: u8 = 0x00;
pub const ALU_SUB: u8 = 0x10;
pub const ALU_MUL: u8 = 0x20;
pub const ALU_OR: u8 = 0x40;
pub const ALU_AND: u8 = 0x50;
pub const ALU_LSH: u8 = 0x60;
pub const ALU_RSH: u8 = 0x70;
pub const ALU_NEG: u8 = 0x80;
pub const ALU_XOR: u8 = 0xa0;
pub const ALU_MOV: u8 = 0xb0;
pub const ALU_ARSH: u8 = 0xc0;

/// Jump operations. Unsigned only — signed compares are deleted, so a program
/// that wants a signed comparison must bias into unsigned before the trust
/// boundary, where the bias is visible and checkable.
pub const JMP_JA: u8 = 0x00;
pub const JMP_JEQ: u8 = 0x10;
pub const JMP_JGT: u8 = 0x20;
pub const JMP_JGE: u8 = 0x30;
pub const JMP_JSET: u8 = 0x40;
pub const JMP_JNE: u8 = 0x50;
pub const JMP_JLT: u8 = 0xa0;
pub const JMP_JLE: u8 = 0xb0;
pub const JMP_CALL: u8 = 0x80;
pub const JMP_EXIT: u8 = 0x90;

/// Source modifier: operand is the immediate (0) or a register (1).
pub const SRC_IMM: u8 = 0x00;
pub const SRC_REG: u8 = 0x08;

/// Memory access widths. 64-bit (`DW`) is absent by design.
pub const SIZE_W: u8 = 0x00;
pub const SIZE_H: u8 = 0x08;
pub const SIZE_B: u8 = 0x10;

/// Is this opcode in the admitted subset?
///
/// The whitelist is positive: an opcode is rejected unless it appears here.
/// A negative list would silently admit anything a future encoding adds.
pub fn admitted(opcode: u8) -> bool {
    let class = opcode & 0x07;
    let op = opcode & 0xf0;
    let src = opcode & 0x08;
    match class {
        // 32-bit ALU only. CLASS_ALU64 is rejected wholesale: the subset is
        // 32-bit-valued, so a 64-bit operation has no meaning here.
        CLASS_ALU => matches!(
            op,
            ALU_ADD | ALU_SUB | ALU_MUL | ALU_OR | ALU_AND | ALU_LSH | ALU_RSH
                | ALU_NEG | ALU_XOR | ALU_MOV | ALU_ARSH
        ),
        CLASS_JMP => match op {
            JMP_JA => src == SRC_IMM,
            JMP_JEQ | JMP_JGT | JMP_JGE | JMP_JSET | JMP_JNE | JMP_JLT | JMP_JLE => true,
            // A call is admitted; the *target* is checked at load time against
            // the capability table and cannot be computed at run time.
            JMP_CALL => src == SRC_IMM,
            JMP_EXIT => true,
            _ => false,
        },
        CLASS_LDX | CLASS_ST | CLASS_STX => {
            matches!(opcode & 0x18, SIZE_W | SIZE_H | SIZE_B)
        }
        // CLASS_LD carries only `lddw` in practice, which is deleted.
        _ => false,
    }
}

/// Does this opcode transfer control backwards or out of line?
#[inline]
pub fn is_jump(opcode: u8) -> bool {
    opcode & 0x07 == CLASS_JMP
}
