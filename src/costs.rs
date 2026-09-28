//! Target-specific, versioned timing-credit tables.
//!
//! These constants do not turn observed cycle counts into WCET. They are kept
//! separate from the platform-independent VM semantics so their provenance and
//! maturity are visible at every use site.

use crate::CostModel;

/// Deployed-board admission model, version 2026-09-28.01.
///
/// Ordinary-class entries unchanged from the initial no-cache NEORV32 RTL
/// characterization (`evidence/simulation/2026-08-27-neorv32-rtl-fuel-costs-02`;
/// each value an observed class maximum × 1.25 rounded up to 16 cycles) —
/// the 2026-09-27 board rail (`evidence/runs/2026-09-27-ecp5-j4-001/`)
/// confirmed they hold on silicon (71.5–79.4% utilization, board within
/// 0.2–3.6% of the RTL model).
///
/// **Capability entries replaced with deployed-callee measurements**, as the
/// v1 doc below required: the stub entries under-charged the deployed
/// propose by 14.76× and the deployed seal by 57.9×. Sources
/// `evidence/runs/2026-09-27-ecp5-j4-001/` (propose 13,621 cycles/call through
/// the real monitor; sense 1,018) and the 2026-09-28 seal leg
/// (Ed25519 sign, 12,262,800 cycles/call). Same derivation convention:
/// observed maximum × 1.25, rounded up to 16 cycles.
///
/// Still provisional engineering characterization, not WCET; the seal entry
/// bounds one sign of a 32-byte message with the default-features crate
/// configuration (no precomputed basepoint table).
pub const PROVISIONAL_NEORV32_RTL_V1: CostModel = CostModel::new(
    2_026_092_801,
    416,             // fixed Vm::run overhead
    368,             // non-multiply ALU
    352,             // multiply
    [336, 368, 432], // load: byte, half, word
    [320, 368, 400], // store: byte, half, word
    448,             // branch/jump
    [1_280, 17_040, 15_328_512], // sense, propose, seal: deployed-callee bounds
    448,             // exit: conservative ordinary-class maximum, not isolated
    480,             // invalid path: conservative measured-class maximum
);

/// The v1 table as first characterized, retained for the record: its
/// capability entries were harness stubs, and the 2026-09-27 board rail
/// measured them 14.76x (propose) and 57.9x (seal) below the deployed
/// path. Superseded by the entries in `PROVISIONAL_NEORV32_RTL_V1` above;
/// kept so the finding stays reproducible against the table that exhibited it.
pub const PROVISIONAL_NEORV32_RTL_V0_STUB_CALLS: CostModel = CostModel::new(
    2_026_082_701,
    416,
    368,
    352,
    [336, 368, 432],
    [320, 368, 400],
    448,
    [480, 464, 480], // harness-stub call entries, superseded
    448,
    480,
);
