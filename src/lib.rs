//! # Endstop VM
//!
//! An interpreter for the admitted eBPF subset.
//!
//! Written rather than inherited. An earlier design took a published,
//! formally verified eBPF VM and dropped it: the proof covered a much larger
//! machine than this one executes, and it stopped at C rather than at machine
//! code.
//!
//! This is **not** the safety function. The envelope monitor is
//! (`endstop-monitor`), and under IEC 61508's limited/full-variability split
//! that distinction is what lets the program this executes be arbitrary code.
//! What the VM owes is narrower: that an untrusted program cannot escape its
//! memory, cannot fail to terminate, and cannot reach an effect outside the
//! capability table.
//!
//! ## Why this is verifiable at all
//!
//! **Step fuel bounds the dispatch loop**, and it is capped at
//! [`MAX_STEP_FUEL`], so
//! the trip count is a compile-time constant no matter what the program's
//! control flow does. The plan's objection — *"Kani cannot prove an
//! interpreter's dispatch loop safe for all executions"* — is about an
//! *unbounded* loop. A fuel-capped one is bounded by construction.
//!
//! An earlier draft claimed it was the deletion of backward jumps that made
//! this tractable. That was wrong twice over. The fuel cap is a *tighter*
//! bound than the program length would be, and more fundamentally **we are
//! not proving the program — we are proving this interpreter.** What shape
//! the untrusted program's control-flow graph has is its business; that we
//! handle any shape safely is ours. Loops are admitted.
//!
//! ## Status
//!
//! All seven properties discharged by bounded model checking (Kani): single-step
//! memory safety (V1), capability-index confinement (V2), jump-target containment
//! (V3), forward-only rejection (V3b), checked memory access (V4), and termination
//! under fuel (V5), plus precharge-before-capability ordering (V6). Each harness
//! in `proofs.rs` states its `unwind` bound. Those
//! bounds are shallow by design: the properties are structural, not depth-
//! sensitive -- V1 quantifies over a fully symbolic instruction from the VM's
//! concrete reset state, and the dispatch
//! loop is bounded by the fuel cap regardless of program length. The argument for
//! why shallow suffices is in the `proofs.rs` header.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod costs;
pub mod isa;
pub mod loader;

#[cfg(kani)]
mod proofs;

#[cfg(test)]
mod tests;

/// Panic handler for the bare-metal artifact. Spinning is fail-closed: the
/// watchdog stops being fed, the deadman expires, and drive power is cut.
// Only for the bare-metal target. A host build links std, which brings
// its own handler, and two would be a duplicate lang item — which is how
// this was found: the plant crate depends on the monitor.
#[cfg(all(not(test), not(kani), target_os = "none"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

use isa::*;

/// Scratch memory available to a program, in bytes. Fixed at build time so
/// the bound is a constant the checker can use.
pub const MEM_LEN: usize = 512;
/// Maximum program length.
pub const MAX_INSNS: usize = 512;
/// Step fuel: the **ceiling** on how many instructions one run may execute, and
/// therefore the dispatch loop's bound.
///
/// This is what bounds the loop — not the program length. [`StepFuel::new`]
/// clamps the caller's request to this value, so the trip count is a
/// compile-time constant no matter what a caller supplies. The proofs use
/// smaller values and are independent of the constant's particular value.
///
/// **A ceiling is not a tick's allowance, and the two must not be conflated.**
/// The operating budget is whatever the caller hands to `run` beneath this
/// number, and callers differ on purpose:
///
/// - The red-team board hands out the full 1024, deliberately generous so an
///   attacker has room to build something sophisticated rather than being cut
///   short. A range that starves its attackers proves nothing.
/// - A real control tick also supplies target-specific [`TickCredits`]. The
///   interpreter reserves the complete instruction charge before execution.
///   The initial table is provisional NEORV32 RTL characterization; production
///   admission remains disabled until deployed capability paths are bounded
///   and an independent privileged deadline mechanism is integrated.
///
/// Historical instructions-per-period divisions are not admission limits:
/// instruction mix, capability implementations and shared monitor work all
/// affect the actual cycle budget.
pub const MAX_STEP_FUEL: u32 = 1024;
/// Capability slots. Three: read state, propose setpoint, request signature.
pub const N_CAPS: usize = 3;

/// Why execution stopped.
///
/// Every reason is a first-class outcome rather than an error code, because
/// the evidence record stores refusals with the same fidelity as permissions
/// and a refusal is the differentiated half of the product.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Halt {
    /// `exit` reached. `r0` carries the program's result.
    Exit(u32),
    StepFuelExhausted,
    /// The target-specific conservative execution-credit budget could not pay
    /// for the next instruction. The instruction was not executed.
    TickCreditsExhausted,
    PcOutOfRange,
    IllegalOpcode,
    MemBounds,
    BadCapIndex,
    /// A write to the frame pointer, which is read-only.
    WriteToFp,
    /// A shift by 32 or more. Deleted rather than defined: C says undefined,
    /// RV32 says mask to 5 bits, eBPF says mask. One line is not available.
    ShiftOutOfRange,
}

/// What a capability call may do. The VM never performs an effect itself; it
/// hands an index and arguments to the trusted side, which constructs the
/// effect canonically. The program cannot compute the index — `callx` is not
/// in the subset — so the set of reachable effects is fixed at load time.
pub trait Caps {
    /// Invoke capability `idx` with the eBPF argument registers r1..r5.
    fn call(&mut self, idx: u32, args: [u32; 5]) -> u32;
}

/// Platform-independent bound on dispatched instructions.
///
/// Construction clamps the value to [`MAX_STEP_FUEL`], preserving the static
/// dispatch-loop bound even when a caller supplies an untrusted number.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StepFuel(u32);

impl StepFuel {
    pub const fn new(steps: u32) -> Self {
        Self(if steps > MAX_STEP_FUEL {
            MAX_STEP_FUEL
        } else {
            steps
        })
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Target-specific conservative work allowance. Credits are deliberately a
/// different type from [`StepFuel`]: a proof ceiling must not be passed where
/// a control-tick timing allowance is required.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TickCredits(u32);

impl TickCredits {
    pub const fn new(credits: u32) -> Self {
        Self(credits)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Both independent limits required for one invocation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ExecutionBudget {
    pub step_fuel: StepFuel,
    pub tick_credits: TickCredits,
}

impl ExecutionBudget {
    pub const fn new(step_fuel: StepFuel, tick_credits: TickCredits) -> Self {
        Self {
            step_fuel,
            tick_credits,
        }
    }
}

/// Versioned conservative costs for one concrete target configuration.
///
/// Values are absolute charges for one dispatch, including common dispatch
/// overhead. Capability entries include the complete bounded callee cost. The
/// model is deterministic: charges depend only on the encoded instruction,
/// never on a host cycle counter or runtime operand values.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CostModel {
    pub version: u32,
    run_overhead: u32,
    alu: u32,
    mul: u32,
    load: [u32; 3],
    store: [u32; 3],
    branch: u32,
    call: [u32; N_CAPS],
    exit: u32,
    invalid: u32,
}

impl CostModel {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        version: u32,
        run_overhead: u32,
        alu: u32,
        mul: u32,
        load: [u32; 3],
        store: [u32; 3],
        branch: u32,
        call: [u32; N_CAPS],
        exit: u32,
        invalid: u32,
    ) -> Self {
        assert!(run_overhead > 0 && alu > 0 && mul > 0 && branch > 0 && exit > 0 && invalid > 0);
        assert!(load[0] > 0 && load[1] > 0 && load[2] > 0);
        assert!(store[0] > 0 && store[1] > 0 && store[2] > 0);
        assert!(call[0] > 0 && call[1] > 0 && call[2] > 0);
        Self {
            version,
            run_overhead,
            alu,
            mul,
            load,
            store,
            branch,
            call,
            exit,
            invalid,
        }
    }

    /// A model useful for functional tests and timing characterization. It is
    /// not a deployment timing model.
    pub const fn uniform(charge: u32) -> Self {
        assert!(charge > 0);
        Self::new(
            0,
            charge,
            charge,
            charge,
            [charge; 3],
            [charge; 3],
            charge,
            [charge; N_CAPS],
            charge,
            charge,
        )
    }

    pub const fn run_overhead(&self) -> u32 {
        self.run_overhead
    }

    /// Conservative charge for an encoded instruction.
    pub const fn charge(&self, i: &Insn) -> u32 {
        if !admitted(i.opcode) {
            return self.invalid;
        }
        let class = i.opcode & 0x07;
        let op = i.opcode & 0xf0;
        match class {
            CLASS_ALU => {
                if op == ALU_MUL {
                    self.mul
                } else {
                    self.alu
                }
            }
            CLASS_LDX => self.load[width_index(i.opcode)],
            CLASS_ST | CLASS_STX => self.store[width_index(i.opcode)],
            CLASS_JMP => {
                if op == JMP_CALL {
                    let idx = i.imm as u32;
                    if idx < N_CAPS as u32 {
                        self.call[idx as usize]
                    } else {
                        self.invalid
                    }
                } else if op == JMP_EXIT {
                    self.exit
                } else {
                    self.branch
                }
            }
            _ => self.invalid,
        }
    }
}

const fn width_index(opcode: u8) -> usize {
    match opcode & 0x18 {
        SIZE_B => 0,
        SIZE_H => 1,
        _ => 2,
    }
}

/// Accounting returned with every halt, including abnormal halts.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RunOutcome {
    pub halt: Halt,
    pub steps_used: u32,
    pub credits_used: u32,
}

/// Explicitly non-deployment helpers for functional tests and cycle
/// characterization. Keeping these under a conspicuous module prevents a
/// unit-cost model from looking like the target's operational cost table.
pub mod characterization {
    use super::{CostModel, ExecutionBudget, StepFuel, TickCredits};

    pub const COSTS: CostModel = CostModel::uniform(1);

    pub const fn budget(steps: StepFuel) -> ExecutionBudget {
        ExecutionBudget::new(steps, TickCredits::new(u32::MAX))
    }
}

/// Machine state. No heap, no growth, no interior mutability.
pub struct Vm {
    regs: [u32; N_REGS],
    mem: [u8; MEM_LEN],
    step_fuel: u32,
    tick_credits: u32,
}

impl Default for Vm {
    fn default() -> Self {
        Self::new()
    }
}

impl Vm {
    pub const fn new() -> Self {
        Vm {
            regs: [0; N_REGS],
            mem: [0; MEM_LEN],
            step_fuel: 0,
            tick_credits: 0,
        }
    }

    /// Read a result register after a halt.
    #[inline]
    pub fn reg(&self, i: usize) -> u32 {
        if i < N_REGS {
            self.regs[i]
        } else {
            0
        }
    }

    /// Run a loaded program.
    ///
    /// `insns` must already have passed [`loader::validate`], which
    /// establishes the opcode whitelist, in-range jump targets and the
    /// capability index. The checks repeated here are belt-and-braces: they
    /// cost a comparison each and mean a loader bug cannot become a
    /// memory-safety bug.
    ///
    /// **Fuel is the termination argument.** It holds for any program,
    /// including one that loops forever, which is precisely what it is for.
    /// The safety of running out is established elsewhere and is mandatory:
    /// IR semantics §7 requires setpoints to be double-buffered and committed
    /// only on a clean `EXIT`, with every other halt degrading to STO/SS1
    /// rather than hold-last.
    pub fn run<C: Caps>(
        &mut self,
        insns: &[Insn],
        budget: ExecutionBudget,
        costs: &CostModel,
        caps: &mut C,
    ) -> RunOutcome {
        // Reset is part of the fixed invocation overhead. It happens even for
        // a configuration-error budget so stale registers from a prior run
        // cannot be mistaken for this invocation's result.
        self.regs = [0; N_REGS];
        self.regs[REG_FP as usize] = MEM_LEN as u32;
        self.step_fuel = budget.step_fuel.get();
        self.tick_credits = budget.tick_credits.get();
        let initial_steps = self.step_fuel;
        let initial_credits = self.tick_credits;
        if self.tick_credits < costs.run_overhead() {
            return RunOutcome {
                halt: Halt::TickCreditsExhausted,
                steps_used: 0,
                credits_used: 0,
            };
        }
        self.tick_credits -= costs.run_overhead();
        let mut pc: usize = 0;
        while self.step_fuel > 0 {
            if pc >= insns.len() {
                return self.outcome(Halt::PcOutOfRange, initial_steps, initial_credits);
            }
            let charge = costs.charge(&insns[pc]);
            if self.tick_credits < charge {
                return self.outcome(Halt::TickCreditsExhausted, initial_steps, initial_credits);
            }
            // Reserve both budgets before the instruction can mutate VM state
            // or enter a capability implementation.
            self.step_fuel -= 1;
            self.tick_credits -= charge;
            match self.step(&insns[pc], &mut pc, caps) {
                Some(h) => return self.outcome(h, initial_steps, initial_credits),
                None => {}
            }
        }
        // Fuel ran out. Per IR semantics §7 this must leave nothing
        // committed: setpoints are double-buffered and land only on a clean
        // EXIT, and any other halt degrades to STO/SS1 rather than
        // hold-last. That is what makes an attacker-timed abort safe, and it
        // is why admitting loops does not reintroduce the torn-state problem:
        // a program cut off mid-flight has committed nothing.
        self.outcome(Halt::StepFuelExhausted, initial_steps, initial_credits)
    }

    fn outcome(&self, halt: Halt, initial_steps: u32, initial_credits: u32) -> RunOutcome {
        RunOutcome {
            halt,
            steps_used: initial_steps - self.step_fuel,
            credits_used: initial_credits - self.tick_credits,
        }
    }

    /// One instruction. Returns `Some(halt)` to stop, `None` to continue.
    fn step<C: Caps>(&mut self, i: &Insn, pc: &mut usize, caps: &mut C) -> Option<Halt> {
        if !admitted(i.opcode) {
            return Some(Halt::IllegalOpcode);
        }
        let class = i.opcode & 0x07;
        let op = i.opcode & 0xf0;
        let src_is_reg = i.opcode & 0x08 == SRC_REG;

        let dst = i.dst as usize;
        let srcr = i.src as usize;
        if dst >= N_REGS || srcr >= N_REGS {
            return Some(Halt::IllegalOpcode);
        }

        match class {
            CLASS_ALU => {
                // r10 is the frame pointer and is read-only. Writing it would
                // let a program relocate its own stack view.
                if i.dst == REG_FP {
                    return Some(Halt::WriteToFp);
                }
                let a = self.regs[dst];
                let b = if src_is_reg {
                    self.regs[srcr]
                } else {
                    i.imm as u32
                };
                let v = match op {
                    ALU_ADD => a.wrapping_add(b),
                    ALU_SUB => a.wrapping_sub(b),
                    ALU_MUL => a.wrapping_mul(b),
                    ALU_OR => a | b,
                    ALU_AND => a & b,
                    ALU_XOR => a ^ b,
                    ALU_MOV => b,
                    ALU_NEG => (a as i32).wrapping_neg() as u32,
                    ALU_LSH | ALU_RSH | ALU_ARSH => {
                        // Shifts of 32 or more differ between C, RV32 and
                        // eBPF. Refuse instead of picking a winner.
                        if b >= 32 {
                            return Some(Halt::ShiftOutOfRange);
                        }
                        match op {
                            ALU_LSH => a << b,
                            ALU_RSH => a >> b,
                            _ => ((a as i32) >> b) as u32,
                        }
                    }
                    _ => return Some(Halt::IllegalOpcode),
                };
                self.regs[dst] = v;
                *pc += 1;
                None
            }
            CLASS_LDX => {
                if i.dst == REG_FP {
                    return Some(Halt::WriteToFp);
                }
                let addr = self.regs[srcr].wrapping_add(i.off as i32 as u32);
                match self.load(addr, i.opcode & 0x18) {
                    Ok(v) => {
                        self.regs[dst] = v;
                        *pc += 1;
                        None
                    }
                    Err(h) => Some(h),
                }
            }
            CLASS_ST | CLASS_STX => {
                let addr = self.regs[dst].wrapping_add(i.off as i32 as u32);
                let v = if class == CLASS_STX {
                    self.regs[srcr]
                } else {
                    i.imm as u32
                };
                match self.store(addr, v, i.opcode & 0x18) {
                    Ok(()) => {
                        *pc += 1;
                        None
                    }
                    Err(h) => Some(h),
                }
            }
            CLASS_JMP => {
                match op {
                    JMP_EXIT => return Some(Halt::Exit(self.regs[0])),
                    JMP_CALL => {
                        let idx = i.imm as u32;
                        if idx as usize >= N_CAPS {
                            return Some(Halt::BadCapIndex);
                        }
                        let args = [
                            self.regs[1],
                            self.regs[2],
                            self.regs[3],
                            self.regs[4],
                            self.regs[5],
                        ];
                        self.regs[0] = caps.call(idx, args);
                        *pc += 1;
                        return None;
                    }
                    _ => {}
                }
                let a = self.regs[dst];
                let b = if src_is_reg {
                    self.regs[srcr]
                } else {
                    i.imm as u32
                };
                let taken = match op {
                    JMP_JA => true,
                    JMP_JEQ => a == b,
                    JMP_JNE => a != b,
                    JMP_JGT => a > b,
                    JMP_JGE => a >= b,
                    JMP_JLT => a < b,
                    JMP_JLE => a <= b,
                    JMP_JSET => a & b != 0,
                    _ => return Some(Halt::IllegalOpcode),
                };
                if taken {
                    // Backward jumps are admitted; the pc must still land in
                    // range, re-checked here so a loader bug cannot become a
                    // memory-safety bug.
                    let t = (*pc as i64) + 1 + (i.off as i64);
                    if t < 0 {
                        return Some(Halt::PcOutOfRange);
                    }
                    *pc = t as usize;
                } else {
                    *pc += 1;
                }
                None
            }
            _ => Some(Halt::IllegalOpcode),
        }
    }

    /// Bounds-checked load. The check is on the *computed* address, after
    /// wrapping, so an offset cannot be used to wrap past the end.
    #[inline]
    fn load(&self, addr: u32, size: u8) -> Result<u32, Halt> {
        let n = match size {
            SIZE_B => 1usize,
            SIZE_H => 2,
            _ => 4,
        };
        let a = addr as usize;
        if a > MEM_LEN || MEM_LEN - a < n {
            return Err(Halt::MemBounds);
        }
        let mut v: u32 = 0;
        let mut k = 0;
        while k < n {
            v |= (self.mem[a + k] as u32) << (8 * k);
            k += 1;
        }
        Ok(v)
    }

    /// Bounds-checked store.
    #[inline]
    fn store(&mut self, addr: u32, val: u32, size: u8) -> Result<(), Halt> {
        let n = match size {
            SIZE_B => 1usize,
            SIZE_H => 2,
            _ => 4,
        };
        let a = addr as usize;
        if a > MEM_LEN || MEM_LEN - a < n {
            return Err(Halt::MemBounds);
        }
        let mut k = 0;
        while k < n {
            self.mem[a + k] = (val >> (8 * k)) as u8;
            k += 1;
        }
        Ok(())
    }
}
