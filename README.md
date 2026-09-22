# endstop-vm

A small Rust interpreter for an admitted eBPF subset, with load-time validation,
bounds-checked scratch memory, a fixed capability table, and instruction fuel.
The library uses `no_std`, has no allocator, and forbids unsafe Rust.

This repository restores the previously published VM snapshot as one initial
commit. It contains the interpreter, validator, host tests, Kani proof harnesses,
and a RISC-V self-test. The separate envelope monitor and hardware integration
are outside this repository.

## Run the host tests

Install Rust through rustup, then run:

```sh
cargo test --locked
cargo build --locked --release --target riscv32imc-unknown-none-elf
```

`rust-toolchain.toml` pins the compiler and RISC-V target. The library has no
external Cargo dependencies.

## Run the RISC-V self-test

With `qemu-system-riscv32` installed:

```sh
cd selftest
cargo run --locked --release
```

The self-test uses QEMU's `virt` machine and diagnostic UART. Running it checks
execution on an instruction-set model; it does not establish physical-board
timing, actuator behavior, or product safety.

## Check the bounded proof harnesses

With Kani installed:

```sh
cargo kani
```

The six harnesses in `src/proofs.rs` cover single-instruction memory safety,
capability-index validation, jump-target validation, forward-only validation,
checked memory accesses, and fuel exhaustion. Each harness states its unwind
bound. These are bounded checks: the single-instruction harness starts from the
VM's reset state, and the results do not establish arbitrary-state safety or
source-to-machine-code refinement. Capability implementations remain the
integrator's responsibility.

## Source layout

| Path | Purpose |
| --- | --- |
| `src/isa.rs` | Instruction encoding and admitted opcodes |
| `src/loader.rs` | Program validation |
| `src/lib.rs` | Machine state and execution |
| `src/tests.rs` | Host regression tests |
| `src/proofs.rs` | Bounded Kani proof harnesses |
| `selftest/` | RISC-V executable and QEMU configuration |

## License

The original [Business Source License 1.1](LICENSE) is retained, including its
additional-use grant for evaluation, auditing, verification, teaching, and
research, and publication of findings. Its change date is August 3, 2030, and
its change license is MIT. See the full license for the applicable terms.

Project: [Endstop](https://endstop.systems/).
