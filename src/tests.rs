//! Host tests for the VM. Unit tests rather than `tests/` because the crate
//! is `no_std` outside `cfg(test)` and ships a panic handler.

use crate::isa::*;
use crate::loader::*;
use crate::*;

struct NoCaps;
impl Caps for NoCaps {
    fn call(&mut self, _idx: u32, _args: [u32; 5]) -> u32 {
        0
    }
}
struct RecCaps(Vec<(u32, [u32; 5])>);
impl Caps for RecCaps {
    fn call(&mut self, idx: u32, args: [u32; 5]) -> u32 {
        self.0.push((idx, args));
        42
    }
}

fn i(opcode: u8, dst: u8, src: u8, off: i16, imm: i32) -> Insn {
    Insn {
        opcode,
        dst,
        src,
        off,
        imm,
    }
}
fn exit() -> Insn {
    i(CLASS_JMP | JMP_EXIT, 0, 0, 0, 0)
}
fn mov(d: u8, v: i32) -> Insn {
    i(CLASS_ALU | ALU_MOV | SRC_IMM, d, 0, 0, v)
}

const TEST_COSTS: CostModel = CostModel::uniform(1);

fn budget(steps: u32, credits: u32) -> ExecutionBudget {
    ExecutionBudget::new(StepFuel::new(steps), TickCredits::new(credits))
}

fn run(prog: &[Insn]) -> (Halt, Vm) {
    let steps = validate(prog).expect("program must validate").step_fuel();
    let mut vm = Vm::new();
    let outcome = vm.run(
        prog,
        ExecutionBudget::new(steps, TickCredits::new(MAX_STEP_FUEL)),
        &TEST_COSTS,
        &mut NoCaps,
    );
    (outcome.halt, vm)
}

#[test]
fn mov_and_exit() {
    let (h, vm) = run(&[mov(0, 7), exit()]);
    assert_eq!(h, Halt::Exit(7));
    assert_eq!(vm.reg(0), 7);
}

#[test]
fn arithmetic_wraps_rather_than_traps() {
    let p = [
        mov(0, -1),
        i(CLASS_ALU | ALU_ADD | SRC_IMM, 0, 0, 0, 1),
        exit(),
    ];
    assert_eq!(run(&p).0, Halt::Exit(0)); // 0xFFFF_FFFF + 1 wraps to 0
}

#[test]
fn forward_jump_skips() {
    let p = [
        mov(0, 1),
        i(CLASS_JMP | JMP_JA, 0, 0, 1, 0),
        mov(0, 99),
        exit(),
    ];
    assert_eq!(run(&p).0, Halt::Exit(1));
}

/// Loops are admitted by default. Fuel is what stops them, which is what
/// fuel is for.
#[test]
fn backward_jump_admitted_and_bounded_by_fuel() {
    // An unconditional infinite loop.
    let p = [mov(0, 1), i(CLASS_JMP | JMP_JA, 0, 0, -1, 0), exit()];
    assert!(validate(&p).is_ok(), "loops must load");
    let mut vm = Vm::new();
    assert_eq!(
        vm.run(&p, budget(32, 33), &TEST_COSTS, &mut NoCaps).halt,
        Halt::StepFuelExhausted
    );
}

/// A real counting loop -- the thing unrolling was costing us.
#[test]
fn counting_loop_runs_and_terminates() {
    // r0 = 0; r1 = 4; loop { r0 += 1; r1 -= 1; if r1 != 0 goto loop } exit
    let p = [
        mov(0, 0),
        mov(1, 4),
        i(CLASS_ALU | ALU_ADD | SRC_IMM, 0, 0, 0, 1),
        i(CLASS_ALU | ALU_SUB | SRC_IMM, 1, 0, 0, 1),
        i(CLASS_JMP | JMP_JNE | SRC_IMM, 1, 0, -3, 0),
        exit(),
    ];
    assert!(validate(&p).is_ok());
    let mut vm = Vm::new();
    assert_eq!(
        vm.run(&p, budget(64, 64), &TEST_COSTS, &mut NoCaps).halt,
        Halt::Exit(4)
    );
}

/// Forward-only remains available for programs that want their worst-case
/// execution time to be their own length rather than the fuel cap.
#[test]
fn forward_only_mode_still_rejects_backward_jumps() {
    let p = [mov(0, 1), i(CLASS_JMP | JMP_JA, 0, 0, -1, 0), exit()];
    assert!(matches!(
        validate_with(&p, Strictness::ForwardOnly),
        Err(Reject::BackwardJump { at: 1, off: -1 })
    ));
    assert_eq!(
        validate_with(&[mov(0, 1), exit()], Strictness::ForwardOnly),
        Ok(Termination::Length(2))
    );
}

#[test]
fn jump_past_the_end_rejected() {
    let p = [i(CLASS_JMP | JMP_JA, 0, 0, 50, 0), exit()];
    assert!(matches!(
        validate(&p),
        Err(Reject::JumpOutOfRange { at: 0 })
    ));
}

#[test]
fn missing_trailing_exit_rejected() {
    assert!(matches!(
        validate(&[mov(0, 1)]),
        Err(Reject::NoTrailingExit)
    ));
}

/// Deleted constructs must be rejected by the whitelist, not merely unhandled.
#[test]
fn deleted_constructs_are_rejected() {
    for opcode in [
        CLASS_ALU | 0x30,               // div
        CLASS_ALU | 0x90,               // mod
        CLASS_ALU64 | ALU_ADD,          // 64-bit ALU
        CLASS_LD,                       // lddw
        CLASS_JMP | JMP_CALL | SRC_REG, // callx
    ] {
        assert!(!admitted(opcode), "opcode {opcode:#04x} should be deleted");
        assert!(validate(&[i(opcode, 0, 0, 0, 0), exit()]).is_err());
    }
}

#[test]
fn memory_stays_in_bounds() {
    // Store then load at the top of scratch memory.
    let p = [
        mov(1, (MEM_LEN - 4) as i32),
        i(CLASS_ST | SIZE_W, 1, 0, 0, 0xAB),
        i(CLASS_LDX | SIZE_W, 0, 1, 0, 0),
        exit(),
    ];
    assert_eq!(run(&p).0, Halt::Exit(0xAB));
}

#[test]
fn out_of_bounds_access_halts() {
    let p = [
        mov(1, MEM_LEN as i32),
        i(CLASS_LDX | SIZE_W, 0, 1, 0, 0),
        exit(),
    ];
    assert_eq!(run(&p).0, Halt::MemBounds);
}

/// An offset must not be usable to wrap the address past the end.
#[test]
fn offset_cannot_wrap_past_the_end() {
    let p = [mov(1, 0), i(CLASS_LDX | SIZE_W, 0, 1, -4, 0), exit()];
    assert_eq!(run(&p).0, Halt::MemBounds);
}

#[test]
fn frame_pointer_is_read_only() {
    let p = [mov(REG_FP, 0), exit()];
    assert_eq!(run(&p).0, Halt::WriteToFp);
}

/// Shift semantics differ between C, RV32 and eBPF at 32 or more. Refusing is
/// the only answer that needs no arbitration.
#[test]
fn oversized_shift_halts_rather_than_choosing() {
    let p = [
        mov(0, 1),
        i(CLASS_ALU | ALU_LSH | SRC_IMM, 0, 0, 0, 32),
        exit(),
    ];
    assert_eq!(run(&p).0, Halt::ShiftOutOfRange);
}

#[test]
fn capability_call_reaches_the_trusted_side() {
    let p = [mov(1, 5), i(CLASS_JMP | JMP_CALL, 0, 0, 0, 1), exit()];
    let fuel = validate(&p).unwrap().step_fuel();
    let mut vm = Vm::new();
    let mut caps = RecCaps(Vec::new());
    assert_eq!(
        vm.run(
            &p,
            ExecutionBudget::new(fuel, TickCredits::new(MAX_STEP_FUEL)),
            &TEST_COSTS,
            &mut caps,
        )
        .halt,
        Halt::Exit(42)
    );
    assert_eq!(caps.0.len(), 1);
    assert_eq!(caps.0[0].0, 1);
    assert_eq!(caps.0[0].1[0], 5);
}

#[test]
fn capability_index_outside_the_table_rejected_at_load() {
    let p = [i(CLASS_JMP | JMP_CALL, 0, 0, 0, N_CAPS as i32), exit()];
    assert!(matches!(validate(&p), Err(Reject::BadCapIndex { .. })));
}

/// The two bounds are different numbers and must not be conflated: a program
/// can be well within its termination bound and still unaffordable this tick.
#[test]
fn termination_and_work_bounds_are_distinct() {
    let p = [mov(0, 1), mov(0, 2), mov(0, 3), exit()];
    // Default strictness admits loops, so the length is not a termination
    // bound and validate reports the fuel budget instead.
    assert_eq!(validate(&p), Ok(Termination::FuelBounded));
    // Under ForwardOnly the length *is* the bound.
    let term = validate_with(&p, Strictness::ForwardOnly)
        .unwrap()
        .step_fuel();
    assert_eq!(term.get(), 4);

    let mut vm = Vm::new();
    let outcome = vm.run(
        &p,
        ExecutionBudget::new(term, TickCredits::new(2)),
        &TEST_COSTS,
        &mut NoCaps,
    );
    assert_eq!(outcome.halt, Halt::TickCreditsExhausted);
    assert_eq!(outcome.steps_used, 1);
    assert_eq!(outcome.credits_used, 2);
}

/// Fuel bounds *work*. Termination rests on fuel too: loops are admitted, and
/// the fuel cap — not the program's shape — is the termination argument. (The
/// earlier "termination is syntactic" position was reversed; see `lib.rs`.)
#[test]
fn fuel_exhaustion_halts_cleanly() {
    let p = [mov(0, 1), mov(0, 2), mov(0, 3), exit()];
    let mut vm = Vm::new();
    assert_eq!(
        vm.run(&p, budget(2, 100), &TEST_COSTS, &mut NoCaps).halt,
        Halt::StepFuelExhausted
    );
}

/// Under ForwardOnly, termination is the program's own length.
#[test]
fn forward_only_terminates_within_its_length() {
    let progs: Vec<Vec<Insn>> = vec![
        vec![mov(0, 1), exit()],
        vec![
            i(CLASS_JMP | JMP_JEQ | SRC_IMM, 0, 0, 1, 0),
            mov(0, 9),
            exit(),
        ],
        vec![
            mov(0, 1),
            i(CLASS_JMP | JMP_JA, 0, 0, 1, 0),
            mov(0, 2),
            exit(),
        ],
    ];
    for p in progs {
        let fuel = validate_with(&p, Strictness::ForwardOnly)
            .unwrap()
            .step_fuel();
        assert_eq!(fuel.get(), p.len() as u32);
        let mut vm = Vm::new();
        let h = vm.run(
            &p,
            ExecutionBudget::new(fuel, TickCredits::new(p.len() as u32 + 1)),
            &TEST_COSTS,
            &mut NoCaps,
        );
        assert!(
            !matches!(h.halt, Halt::StepFuelExhausted),
            "needed more steps than instructions"
        );
    }
}

#[test]
fn weighted_credits_are_charged_by_instruction_class() {
    let costs = CostModel::new(7, 3, 2, 5, [3, 4, 6], [4, 5, 7], 3, [8, 11, 13], 1, 9);
    let p = [
        mov(0, 3),
        i(CLASS_ALU | ALU_MUL | SRC_IMM, 0, 0, 0, 2),
        i(CLASS_JMP | JMP_CALL, 0, 0, 0, 1),
        exit(),
    ];
    let mut vm = Vm::new();
    let mut caps = RecCaps(Vec::new());
    let outcome = vm.run(&p, budget(4, 22), &costs, &mut caps);
    assert_eq!(outcome.halt, Halt::Exit(42));
    assert_eq!(outcome.steps_used, 4);
    assert_eq!(outcome.credits_used, 22);
}

#[test]
fn unaffordable_capability_is_not_invoked() {
    let costs = CostModel::new(1, 1, 1, 1, [1; 3], [1; 3], 1, [5, 7, 9], 1, 1);
    let p = [i(CLASS_JMP | JMP_CALL, 0, 0, 0, 1), exit()];
    let mut vm = Vm::new();
    let mut caps = RecCaps(Vec::new());
    let outcome = vm.run(&p, budget(2, 7), &costs, &mut caps);
    assert_eq!(outcome.halt, Halt::TickCreditsExhausted);
    assert_eq!(outcome.steps_used, 0);
    assert_eq!(outcome.credits_used, 1);
    assert!(caps.0.is_empty());
}

#[test]
fn step_fuel_constructor_enforces_the_proof_ceiling() {
    assert_eq!(StepFuel::new(u32::MAX).get(), MAX_STEP_FUEL);
}

#[test]
fn forward_only_tick_admission_rejects_an_unaffordable_program() {
    let costs = CostModel::new(12, 2, 2, 5, [3, 4, 6], [4, 5, 7], 3, [8, 11, 13], 1, 9);
    let p = [
        mov(0, 1),
        i(CLASS_ALU | ALU_MUL | SRC_IMM, 0, 0, 0, 2),
        exit(),
    ];
    assert!(matches!(
        validate_for_tick(&p, &costs, TickCredits::new(9)),
        Err(Reject::TickBudgetExceeded {
            required: 10,
            available: 9
        })
    ));
    let admitted = validate_for_tick(&p, &costs, TickCredits::new(10)).unwrap();
    assert_eq!(admitted.instructions, 3);
    assert_eq!(admitted.required_credits, 10);
    assert_eq!(admitted.cost_model_version, 12);

    let mut vm = Vm::new();
    let outcome = vm.run(&p, admitted.execution_budget(), &costs, &mut NoCaps);
    assert_eq!(outcome.halt, Halt::Exit(2));
}

#[test]
fn looping_program_cannot_receive_tick_completion_admission() {
    let p = [i(CLASS_JMP | JMP_JA, 0, 0, -1, 0), exit()];
    assert!(matches!(
        validate_for_tick(&p, &TEST_COSTS, TickCredits::new(100)),
        Err(Reject::BackwardJump { .. })
    ));
}

#[test]
fn provisional_neorv32_table_is_wired_into_tick_admission() {
    let costs = crate::costs::PROVISIONAL_NEORV32_RTL_V1;
    let p = [mov(0, 1), exit()];
    // 416 fixed + 368 ALU + 448 exit.
    assert!(matches!(
        validate_for_tick(&p, &costs, TickCredits::new(1_231)),
        Err(Reject::TickBudgetExceeded {
            required: 1_232,
            available: 1_231
        })
    ));
    let admitted = validate_for_tick(&p, &costs, TickCredits::new(1_232)).unwrap();
    assert_eq!(admitted.required_credits, 1_232);
    assert_eq!(admitted.cost_model_version, 2_026_092_801);
}
