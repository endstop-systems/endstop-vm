//! Runs the interpreter on a real RV32 core model and reports what happened.
//!
//! Built for `riscv32imc-unknown-none-elf` and executed under
//! `qemu-system-riscv32 -machine virt`. That is the instruction set the gate
//! runs, exercised by a core model rather than by the host.
//!
//! **This is not the board.** It says the code executes correctly on the
//! architecture. It says nothing about timing, which needs the FPGA, and
//! nothing about the peripheral map, which is different on NEORV32.
//!
//! The library is `#![forbid(unsafe_code)]`. This crate is not: writing to a
//! UART and setting a stack pointer cannot be done without it, which is
//! exactly why they live out here instead of in there.

#![no_std]
#![no_main]

use endstop_vm::isa::{self, *};
use endstop_vm::loader::{validate, Reject};
use endstop_vm::{Caps, Halt, Vm, MAX_FUEL, MEM_LEN, N_CAPS};


/// Local instruction constructor. The library keeps its own as a test helper
/// rather than public API, and a self-test is not a reason to widen that.
const fn i(opcode: u8, dst: u8, src: u8, off: i16, imm: i32) -> isa::Insn {
    isa::Insn { opcode, dst, src, off, imm }
}

// ------------------------------------------------------------------- entry

core::arch::global_asm!(
    ".section .text.entry",
    ".globl _start",
    "_start:",
    "  la sp, __stack_top",
    "  la t0, __bss_start",
    "  la t1, __bss_end",
    "1:",
    "  bgeu t0, t1, 2f",
    "  sw zero, 0(t0)",
    "  addi t0, t0, 4",
    "  j 1b",
    "2:",
    "  call main",
    "3:",
    "  j 3b",
);

// -------------------------------------------------------------- UART, exit

const UART: usize = 0x1000_0000;
const TEST_FINISHER: usize = 0x0010_0000;

fn putb(b: u8) {
    unsafe { core::ptr::write_volatile(UART as *mut u8, b) }
}

fn say(s: &str) {
    for b in s.bytes() {
        if b == b'\n' {
            putb(b'\r');
        }
        putb(b);
    }
}

fn num(mut n: u32) {
    if n == 0 {
        return putb(b'0');
    }
    let mut d = [0u8; 10];
    let mut i = 0;
    while n > 0 {
        d[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        putb(d[i]);
    }
}

fn quit(failures: u32) -> ! {
    // The `virt` machine's SiFive test device. 0x5555 is pass; anything else
    // shifts the exit code into the upper bits.
    let code: u32 = if failures == 0 { 0x5555 } else { (failures << 16) | 0x3333 };
    unsafe { core::ptr::write_volatile(TEST_FINISHER as *mut u32, code) }
    loop {}
}

// No panic handler here on purpose. The library supplies one for
// `target_os = "none"`, and a second would be a duplicate lang item.

// ------------------------------------------------------------- the machine

const CAP_READ: u32 = 0;
const CAP_PROPOSE: u32 = 1;

struct Machine {
    current: u32,
    proposed: u32,
    calls: u32,
}

impl Caps for Machine {
    fn call(&mut self, idx: u32, args: [u32; 5]) -> u32 {
        self.calls += 1;
        match idx {
            CAP_READ => self.current,
            CAP_PROPOSE => {
                self.proposed = args[0];
                0
            }
            _ => 0,
        }
    }
}

fn machine() -> Machine {
    Machine { current: 100, proposed: 0, calls: 0 }
}

// ------------------------------------------------------------------ checks

fn check(failures: &mut u32, name: &str, ok: bool) {
    say(if ok { "  ok    " } else { "  FAIL  " });
    say(name);
    say("\n");
    if !ok {
        *failures += 1;
    }
}

#[no_mangle]
extern "C" fn main() -> ! {
    let mut bad = 0u32;

    say("\nendstop-vm on riscv32imc-unknown-none-elf, under qemu virt\n");
    say("----------------------------------------------------------\n");

    // A well-formed program loads, runs, reads state and proposes.
    let prog = [
        i(CLASS_JMP | JMP_CALL, 0, 0, 0, CAP_READ as i32),
        i(CLASS_ALU | ALU_ADD | SRC_IMM, 0, 0, 0, 7),
        // SRC_REG must be explicit: without it this is immediate mode and
        // the instruction means `r1 = 0`, which is how this test first failed.
        i(CLASS_ALU | ALU_MOV | SRC_REG, 1, 0, 0, 0),
        i(CLASS_JMP | JMP_CALL, 0, 0, 0, CAP_PROPOSE as i32),
        i(CLASS_JMP | JMP_EXIT, 0, 0, 0, 0),
    ];
    match validate(&prog) {
        Ok(bound) => {
            let mut vm = Vm::new();
            let mut m = machine();
            let halt = vm.run(&prog, bound.fuel(), &mut m);
            check(&mut bad, "a valid program loads and runs", matches!(halt, Halt::Exit(_)));
            check(&mut bad, "it read state and proposed 107", m.proposed == 107 && m.calls == 2);
        }
        Err(_) => {
            check(&mut bad, "a valid program loads and runs", false);
            check(&mut bad, "it read state and proposed 107", false);
        }
    }

    // An effect outside the table is not refused at run time. It does not load.
    let outside = [
        i(CLASS_JMP | JMP_CALL, 0, 0, 0, N_CAPS as i32),
        i(CLASS_JMP | JMP_EXIT, 0, 0, 0, 0),
    ];
    check(&mut bad, "capability 3 never loads",
          matches!(validate(&outside), Err(Reject::BadCapIndex { .. })));

    // A program that loops forever is cut off by fuel.
    let spin = [
        i(CLASS_JMP | JMP_JA, 0, 0, -1, 0),
        i(CLASS_JMP | JMP_EXIT, 0, 0, 0, 0),
    ];
    match validate(&spin) {
        Ok(f) => {
            let mut vm = Vm::new();
            let mut m = machine();
            check(&mut bad, "an infinite loop halts on fuel",
                  matches!(vm.run(&spin, f.fuel(), &mut m), Halt::FuelExhausted));
        }
        Err(_) => check(&mut bad, "an infinite loop halts on fuel", false),
    }

    // A read past the region halts instead of returning data.
    let oob = [
        i(CLASS_ALU | ALU_MOV | SRC_IMM, 1, 0, 0, MEM_LEN as i32 + 64),
        i(CLASS_LDX | SIZE_W, 2, 1, 0, 0),
        i(CLASS_JMP | JMP_EXIT, 0, 0, 0, 0),
    ];
    match validate(&oob) {
        Ok(f) => {
            let mut vm = Vm::new();
            let mut m = machine();
            check(&mut bad, "a read past the region halts",
                  matches!(vm.run(&oob, f.fuel(), &mut m), Halt::MemBounds));
        }
        Err(_) => check(&mut bad, "a read past the region halts", false),
    }

    say("----------------------------------------------------------\n");
    say("failures ");
    num(bad);
    say("\nfuel cap ");
    num(MAX_FUEL);
    say(", memory ");
    num(MEM_LEN as u32);
    say(" bytes, capabilities ");
    num(N_CAPS as u32);
    say("\n");

    quit(bad)
}
