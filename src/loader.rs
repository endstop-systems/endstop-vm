//! Load-time validation.
//!
//! The loader is **safety-critical software in its own right.** FAA Order
//! 8110.49 §7-6 is explicit that a tool which writes the modifiable region
//! must itself be qualified, and that its protective component carries the
//! system's highest assurance level. That cost is not currently in the
//! budget; recording it here is the first step to putting it there.
//!
//! Everything this establishes is a **syntactic property of the image**,
//! decided before the machine moves. Nothing here depends on the program's
//! behaviour, which is why it can be decided at all.

use crate::isa::*;
use crate::{MAX_INSNS, N_CAPS};

/// Why an image was rejected.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reject {
    Empty,
    TooLong { len: usize },
    IllegalOpcode { at: usize },
    /// A jump that does not move strictly forwards. Only reachable under
    /// [`Strictness::ForwardOnly`]; loops are admitted by default because
    /// fuel already bounds them.
    BackwardJump { at: usize, off: i16 },
    JumpOutOfRange { at: usize },
    BadRegister { at: usize },
    BadCapIndex { at: usize, idx: i32 },
    /// The last instruction must be `exit`, so falling off the end is
    /// impossible rather than merely unlikely.
    NoTrailingExit,
}

/// The two bounds a caller needs, kept apart because conflating them is easy
/// and the failure is silent.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Bounds {
    /// Steps after which the program has provably finished: its own length,
    /// since forward-only jumps mean no instruction executes twice. This is
    /// the **termination** argument.
    pub termination: u32,
    /// Steps the tick can afford. A different question entirely — it is about
    /// the control period, not about the program — and it is the smaller of
    /// the two in any realistic configuration.
    pub work_budget: u32,
}

impl Bounds {
    /// The fuel to actually pass to [`crate::Vm::run`].
    ///
    /// A program may be shorter than the tick allows, in which case
    /// termination binds. A program may be longer, in which case the tick
    /// binds and the program is cut off mid-flight — which is safe, because
    /// an abort drives the safe state, but which the operator should see as
    /// a configuration error rather than normal operation.
    #[inline]
    pub fn fuel(&self) -> u32 {
        if self.termination < self.work_budget {
            self.termination
        } else {
            self.work_budget
        }
    }

    /// True when the tick budget, not the program, is what will stop it.
    /// Worth surfacing at load time: a program that cannot finish inside a
    /// tick will be aborted every tick, forever.
    #[inline]
    pub fn work_bound_binds(&self) -> bool {
        self.work_budget < self.termination
    }
}

/// Validate an image. Returns the **termination** bound, which is not the
/// same number as the tick's fuel budget — see [`Bounds`].
///
/// The order matters: length before anything indexed, opcodes before their
/// operands are interpreted, and jump targets last, since they depend on the
/// length already being known.
/// How strictly to validate.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Strictness {
    /// Loops admitted. Termination comes from fuel, which is what fuel is
    /// for. The dispatch loop stays bounded — by the fuel cap, which is
    /// *tighter* than the program length.
    Default,
    /// Reject backward jumps. Buys one thing: worst-case execution time is
    /// the program's own length rather than the fuel cap, so a short program
    /// can be budgeted as short. Costs loops entirely, and unrolling a
    /// six-element loop can eat 20-50% of the instruction budget.
    ForwardOnly,
}

/// What validation establishes about how long a program can run.
///
/// The two cases are genuinely different kinds of number, and conflating them
/// is the footgun this type exists to prevent: under [`Strictness::ForwardOnly`]
/// the program provably finishes in a bounded number of steps *derived from the
/// program*; under [`Strictness::Default`] loops are admitted, so there is no
/// such syntactic bound and the fuel cap is the only limit. A caller that wants
/// "the fuel to run with" must ask for it explicitly via [`Termination::fuel`],
/// which makes the constant-vs-derived choice visible at the call site rather
/// than hidden behind a bare `u32`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Termination {
    /// Forward-only: no instruction executes twice, so the program finishes in
    /// at most this many steps.
    Length(u32),
    /// Loops admitted: termination rests on fuel, not on the program's shape.
    FuelBounded,
}

impl Termination {
    /// The fuel to actually pass to [`crate::Vm::run`]: the derived length when
    /// that is a real bound, otherwise the global fuel cap. Named so the choice
    /// is deliberate at the call site.
    #[inline]
    pub fn fuel(self) -> u32 {
        match self {
            Termination::Length(n) => n,
            Termination::FuelBounded => crate::MAX_FUEL,
        }
    }
}

/// Validate an image at the default strictness.
pub fn validate(insns: &[Insn]) -> Result<Termination, Reject> {
    validate_with(insns, Strictness::Default)
}

/// Validate an image.
///
/// Returns a [`Termination`], not a bare number, because the two strictness
/// modes establish different kinds of bound. Under [`Strictness::ForwardOnly`]
/// it is `Length`, the program's own length, since no instruction executes
/// twice. Otherwise it is `FuelBounded`: a looping program's step count is not
/// a property of its length, and the fuel cap is the only bound.
pub fn validate_with(insns: &[Insn], strict: Strictness) -> Result<Termination, Reject> {
    if insns.is_empty() {
        return Err(Reject::Empty);
    }
    if insns.len() > MAX_INSNS {
        return Err(Reject::TooLong { len: insns.len() });
    }

    for (at, i) in insns.iter().enumerate() {
        if !admitted(i.opcode) {
            return Err(Reject::IllegalOpcode { at });
        }
        if i.dst as usize >= N_REGS || i.src as usize >= N_REGS {
            return Err(Reject::BadRegister { at });
        }

        if is_jump(i.opcode) {
            let op = i.opcode & 0xf0;
            match op {
                JMP_EXIT => {}
                JMP_CALL => {
                    // The capability index is an immediate and is checked
                    // here. Because `callx` is not in the subset, the program
                    // cannot compute an index, so the reachable effect set is
                    // fixed by this loop.
                    if i.imm < 0 || i.imm as usize >= N_CAPS {
                        return Err(Reject::BadCapIndex { at, idx: i.imm });
                    }
                }
                _ => {
                    if strict == Strictness::ForwardOnly && i.off <= 0 {
                        return Err(Reject::BackwardJump { at, off: i.off });
                    }
                    // The target must land inside the image either way. This
                    // is the check that keeps the pc in range; the direction
                    // is a separate question.
                    let target = (at as i64) + 1 + (i.off as i64);
                    if target < 0 || target >= insns.len() as i64 {
                        return Err(Reject::JumpOutOfRange { at });
                    }
                }
            }
        }
    }

    // Falling off the end would reach `PcOutOfRange`, which is safe but
    // uninformative. Requiring a trailing `exit` makes the program's
    // termination visible in the image rather than inferred from a halt.
    let last = insns[insns.len() - 1];
    if last.opcode & 0x07 != CLASS_JMP || last.opcode & 0xf0 != JMP_EXIT {
        return Err(Reject::NoTrailingExit);
    }

    // Under ForwardOnly no instruction executes twice, so the program cannot
    // take more steps than it has instructions. With loops admitted there is
    // no such bound and termination rests on fuel — `MAX_FUEL`, the number of
    // instructions a run may execute, which is what a program actually gets.
    Ok(match strict {
        Strictness::ForwardOnly => Termination::Length(insns.len() as u32),
        Strictness::Default => Termination::FuelBounded,
    })
}
