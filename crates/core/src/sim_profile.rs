//! Simulation environment profiles for Gas Killer execution.
//!
//! A [`SimProfile`] pins the EVM environment a tracked function is simulated
//! under. `Chain` mirrors the real chain (today's behaviour everywhere).
//! `Unbounded` is the Gas Killer *unbounded execution* profile: the tracked
//! function is simulated with gas limits far above any real block, so
//! arbitrarily heavy Solidity can be executed off-chain — provided the payload
//! it produces still fits in one on-chain transaction (see
//! [`validate_unbounded_cost`]).
//!
//! The constraint is *priced*, not counted: what has to stay bounded is the gas
//! needed to apply the diff, so a transition may write as many slots as fit
//! under [`UNBOUNDED_PAYLOAD_GAS_BUDGET`]. Consumers whose state is too large
//! for that can commit it into fewer slots — in the limit, the single-slot
//! commitment pattern (solidity-sdk PR #51) — but that pattern is an option for
//! contracts that need it, not a requirement of this mode.
//!
//! # Determinism is protocol-critical
//!
//! The profile's limits are **pinned protocol constants**, not tunables.
//! Every party that re-executes a tracked function must use bit-identical
//! environment overrides:
//!
//! 1. operators, when extracting the state-update payload they sign;
//! 2. this analyzer, when simulating on a user's behalf;
//! 3. the SP1 slashing guest (`docs/SP1_REVM_IMPLEMENTATION_SPEC.md`), when a
//!    slasher re-executes the original function inside the zkVM to prove the
//!    signed updates wrong.
//!
//! If the guest ran with the real header's `gas_limit` while operators
//! simulated under lifted limits, a heavy-but-honest execution would OOG in
//! the guest and produce a *different* update set — falsely slashing honest
//! operators. Conversely, per-operator ad-hoc limits would make quorum
//! signatures diverge on the boundary. So the constants below are a pinned
//! protocol value, not a tuning knob: changing them changes what honest
//! operators produce, and must be rolled out fleet-wide in lockstep with the
//! slashing guest — never as a silent edit.
//!
//! Calldata note: neither revm nor the EVM protocol caps calldata *size*;
//! calldata is bounded only through intrinsic gas (EIP-7623 floor pricing).
//! Lifting the gas limits therefore lifts the effective calldata bound too —
//! multi-megabyte witnesses (e.g. the expanded state behind a single-slot
//! commitment) simulate fine under `Unbounded` even though they could never
//! land in a real transaction. Only the *signed payload* must fit on-chain.

use crate::types::StateUpdate;
use alloy_primitives::{B256, b256};

/// The Gas Killer SDK's `StateTracker` transition-counter slot
/// (`keccak256("gasKiller.stateTracker") - 1`, see solidity-sdk
/// `StateTracker.sol`). Every `trackState` function bumps it, so every
/// extracted diff carries a Store to this slot; `verifyAndUpdate`'s own
/// modifier writes the same value on-chain, making the payload copy
/// idempotent. It is a fixed protocol slot — one per consumer regardless of
/// state size — so it is reported separately from the consumer's own writes.
pub const STATE_TRACKER_SLOT: B256 =
    b256!("0xdebfdfd5a50ad117c10898d68b5ccf0893c6b40d4f443f902e2e7646601bdeaf");

/// Block gas limit for the `Unbounded` profile: 2^40 ≈ 1.1 Tgas,
/// ~24,000× a 45M-gas mainnet block.
///
/// Chosen instead of `u64::MAX` so intrinsic-gas / refund / floor-cost
/// arithmetic (all `u64` in revm and in geth's tracer path) cannot overflow,
/// while still admitting ~27 GB of EIP-7623-priced calldata — far beyond any
/// realistic witness.
pub const UNBOUNDED_BLOCK_GAS_LIMIT: u64 = 1 << 40;

/// Transaction gas limit for the `Unbounded` profile.
///
/// Equal to the block limit: the profile deliberately ignores the EIP-7825
/// per-transaction cap (2^24) — that cap protects real block building and has
/// no purpose in an off-chain simulation whose result is applied on-chain as
/// a Gas Killer payload.
pub const UNBOUNDED_TX_GAS_LIMIT: u64 = UNBOUNDED_BLOCK_GAS_LIMIT;

/// The EVM environment profile a tracked function is simulated under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SimProfile {
    /// Mirror the anchored chain's real environment (header gas limit,
    /// EIP-7825 tx cap where active). This is the historical behaviour and
    /// the right profile whenever the analyzed call must also be *executable*
    /// on-chain as-is.
    #[default]
    Chain,
    /// Gas Killer unbounded execution: simulate with
    /// [`UNBOUNDED_BLOCK_GAS_LIMIT`] / [`UNBOUNDED_TX_GAS_LIMIT`] and require the
    /// extracted payload to cost no more than [`UNBOUNDED_PAYLOAD_GAS_BUDGET`] to apply.
    Unbounded,
}

impl SimProfile {
    /// Transaction-level gas limit override, if this profile lifts it.
    pub fn tx_gas_limit_override(&self) -> Option<u64> {
        match self {
            SimProfile::Chain => None,
            SimProfile::Unbounded => Some(UNBOUNDED_TX_GAS_LIMIT),
        }
    }

    /// Block-level gas limit override, if this profile lifts it.
    pub fn block_gas_limit_override(&self) -> Option<u64> {
        match self {
            SimProfile::Chain => None,
            SimProfile::Unbounded => Some(UNBOUNDED_BLOCK_GAS_LIMIT),
        }
    }

    /// The ceiling this profile places on the on-chain cost of the extracted payload, if any.
    ///
    /// `Chain` needs none: the simulation ran under the real chain's limits, so anything it produced
    /// was already affordable there. `Unbounded` lifts those limits for the simulation and therefore
    /// has to reimpose a bound on the result — see [`validate_unbounded_cost`].
    pub fn payload_gas_budget(&self) -> Option<u64> {
        match self {
            SimProfile::Chain => None,
            SimProfile::Unbounded => Some(UNBOUNDED_PAYLOAD_GAS_BUDGET),
        }
    }
}

/// The sp1-contract-call environment overrides this profile executes under.
///
/// Available with the `sp1-cc` feature. This is the only supported way to turn
/// a [`SimProfile`] into `EnvOverrides`: every party that re-executes a
/// tracked function — operators, this analyzer, the SP1 slashing guest — must
/// use bit-identical limits, and a hand-written `EnvOverrides::gas_limits(..)`
/// at each call site is how they drift apart. Restating the constants also
/// silently collapses the block and transaction limits into one, which is
/// correct only for as long as they happen to be equal.
///
/// The guest binds the active overrides into `chainConfigHash`, so a proof
/// produced under limits other than these cannot satisfy a verifier expecting
/// this profile.
#[cfg(feature = "sp1-cc")]
impl From<SimProfile> for sp1_cc_client_executor::EnvOverrides {
    fn from(profile: SimProfile) -> Self {
        Self {
            block_gas_limit: profile.block_gas_limit_override(),
            tx_gas_limit: profile.tx_gas_limit_override(),
        }
    }
}

/// Ceiling on the on-chain cost of an extracted payload under the `Unbounded` profile: EIP-7825's
/// per-transaction gas cap, `2^24`.
///
/// This is the protocol's own maximum for a single transaction, so a payload priced above it can
/// never be applied by `verifyAndUpdate` on a post-Osaka chain no matter how empty the block is. The
/// profile therefore *lifts* EIP-7825 for the off-chain simulation, where the cap protects nothing,
/// and *enforces* it on the payload, where it is binding. Picking the protocol limit rather than a
/// tuned number also keeps this from becoming a knob: like the gas limits above it is a pinned
/// constant, and changing it changes which payloads honest operators accept.
pub const UNBOUNDED_PAYLOAD_GAS_BUDGET: u64 = 1 << 24;

/// The gas-schedule prices [`UNBOUNDED_COLD_SSTORE_COST`] is built from: EIP-2929's cold-slot
/// access surcharge and EIP-2200's zero→nonzero `SSTORE_SET`. Nothing else reads them — they exist
/// so the gate's price carries its own derivation, and so a repricing fork has exactly one place to
/// land. Editing either changes which payloads honest operators accept; the doc below says why that
/// is deliberate rather than tunable.
const COLD_SLOAD: u64 = 2_100;
const SSTORE_SET: u64 = 20_000;

/// Worst-case cost charged per `Store` by [`estimate_applied_payload_gas`]: a cold slot access plus
/// a zero→nonzero `SSTORE`.
///
/// Deliberately *not* shared with `crate::heuristic`'s reporting estimator. That one approximates
/// the typical cost to produce user-facing savings figures and is tuned over time; this one must be
/// a stable upper bound, because it decides which payloads are valid. If the two shared a
/// definition, tuning a displayed number would silently change what operators accept — and a gate
/// that under-prices a write accepts payloads that do not actually fit. The gate still never
/// prices a write below the reporting heuristic: that one charges each write its traced actual
/// cost, which EIP-2929/2200 cap at exactly this sum, so the bound holds by construction rather
/// than by comparing against a shared definition.
///
/// Stated as that sum rather than as `22_100` for the same reason the old
/// `UNBOUNDED_COLD_SSTORE_COST > heuristic::WARM_SSTORE_COST` assert existed: to keep the gate's
/// price from becoming a number someone can nudge. The assert compared two constants that could
/// drift apart; deleting `WARM_SSTORE_COST` left nothing to compare, but it also left the better
/// option — the definition below cannot drift from the protocol cap because it *is* the protocol
/// cap. What remains checked at test time, and can't be expressed here, is the semantic bound:
/// `analytic_bound_dominates_measured_apply_cost` in `gas-analyzer-estimator` validates this
/// against revm-measured apply cost.
pub const UNBOUNDED_COLD_SSTORE_COST: u64 = COLD_SLOAD + SSTORE_SET;

/// Cost of a `LOG*` op: base, plus per topic, plus per byte of data.
const LOG_BASE: u64 = 375;
const LOG_TOPIC: u64 = 375;
const LOG_BYTE: u64 = 8;

/// Intrinsic cost of the `verifyAndUpdate` transaction that carries the payload.
const TX_BASE: u64 = 21_000;

/// Intrinsic gas per byte of payload calldata: 4 per zero byte, 16 per non-zero byte
/// (EIP-2028 pricing, i.e. 4 gas per EIP-7623 *token*).
const CALLDATA_ZERO_BYTE: u64 = 4;
const CALLDATA_NONZERO_BYTE: u64 = 16;

/// EIP-7623 floor price per calldata token, where a token is one zero byte or a quarter of a
/// non-zero byte. A transaction pays the *larger* of its execution total and this floor, so
/// [`estimate_applied_payload_gas`] has to evaluate both.
const CALLDATA_FLOOR_TOKEN: u64 = 10;
const CALLDATA_FLOOR_NONZERO_TOKENS: u64 = 4;

/// Fixed cost of entering `verifyAndUpdate`'s apply loop: decoding the two outer arrays and
/// setting up memory, independent of what they hold.
///
/// Together with [`UNBOUNDED_APPLY_GAS_PER_PAYLOAD_BYTE`] this covers the difference between an
/// op's raw EVM price and what it costs to *dispatch* that op out of an ABI-encoded payload — a
/// term the reporting estimators never needed, because revm charges it automatically when it
/// executes real calldata.
pub const UNBOUNDED_APPLY_BASE_GAS: u64 = 2_000;

/// Cost of decoding and dispatching one byte of encoded payload inside `verifyAndUpdate`:
/// `calldataload`ing it, copying it into memory, and walking the element it belongs to.
///
/// Charged per payload byte rather than per update because that is what the work is proportional
/// to — an update's decode cost tracks the bytes it occupies, not its existence. Measured against
/// the `StateChangeHandlerGasEstimator` handler across store- and log-shaped payloads at 7.9–12.9
/// gas per byte (the top of that range being logs, which carry more envelope per byte), so 14
/// dominates every observed shape with ≥8% margin.
///
/// `analytic_bound_dominates_measured_apply_cost` in `gas-analyzer-estimator` pins this and
/// [`UNBOUNDED_APPLY_BASE_GAS`] against that measurement, so neither can silently drift below what
/// applying a payload really costs.
///
/// Caveat worth knowing: the measurement is against the estimator handler, which is what this
/// analyzer's own gas figures run through — not the production `verifyAndUpdate` in the
/// solidity-sdk. If that handler's decode loop is materially more expensive, this constant needs
/// re-measuring against it.
pub const UNBOUNDED_APPLY_GAS_PER_PAYLOAD_BYTE: u64 = 14;

/// Summary of a payload that passed [`validate_unbounded_cost`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnboundedCost {
    /// Number of `Store` ops other than the [`STATE_TRACKER_SLOT`].
    pub stores: usize,
    /// Number of `Store` ops to the fixed [`STATE_TRACKER_SLOT`] (0 or 1).
    pub tracker_stores: usize,
    /// Number of `Call` ops. These re-execute **on-chain at real gas prices**
    /// when the payload is applied — unbounded compute inside a `Call` is NOT
    /// killed, and is charged against the budget at the gas the trace measured
    /// for it.
    pub calls: usize,
    /// Number of `Log0`–`Log4` ops.
    pub logs: usize,
    /// Upper bound on the gas needed to apply this payload on-chain: the transaction's intrinsic
    /// cost, the signature-verification floor, each op's execution cost, the intrinsic gas for the
    /// encoded payload's own bytes, and `verifyAndUpdate`'s decode/dispatch overhead. See
    /// [`estimate_applied_payload_gas`].
    pub applied_gas_upper_bound: u64,
}

/// Why a payload is not valid under the unbounded profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnboundedCostViolation {
    /// Applying the payload costs more than [`UNBOUNDED_PAYLOAD_GAS_BUDGET`].
    ///
    /// The unbounded profile's bargain is that *compute* may be unbounded while the payload that
    /// lands on-chain still fits in one transaction. A consumer that writes enough slots to exceed
    /// the cap has not moved work off-chain — it has moved it into a transaction nobody can mine.
    /// Either reduce the state each transition touches, or commit it into fewer slots (for the
    /// extreme case, the single-slot commitment pattern in solidity-sdk PR #51).
    PayloadTooExpensive {
        /// Upper-bound gas to apply the payload.
        estimated: u64,
        /// The ceiling it exceeded.
        budget: u64,
        /// Non-tracker `Store` ops, the usual driver when this trips.
        stores: usize,
    },
    /// `CREATE`/`CREATE2` found. Not a cost question: the struct-log path extracts a
    /// `Create`/`Create2` op carrying initcode to re-execute on replay, and a net diff cannot
    /// reconstruct that, so contract creation is unrepresentable here regardless of price.
    CreateNotAllowed {
        /// Index of the offending op in the update list.
        index: usize,
    },
}

impl core::fmt::Display for UnboundedCostViolation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            UnboundedCostViolation::PayloadTooExpensive {
                estimated,
                budget,
                stores,
            } => write!(
                f,
                "unbounded payload costs up to {estimated} gas to apply, over the {budget} budget \
                 ({stores} storage writes); reduce the state each transition touches or commit it \
                 into fewer slots"
            ),
            UnboundedCostViolation::CreateNotAllowed { index } => write!(
                f,
                "unbounded profile does not allow CREATE/CREATE2 (update #{index}): a net diff \
                 cannot reconstruct replayable initcode"
            ),
        }
    }
}

impl std::error::Error for UnboundedCostViolation {}

/// Upper bound on the gas required to apply `updates` on-chain via `verifyAndUpdate`.
///
/// `external_call_gas` is the measured cost of the payload's `Call` ops, taken from the trace — they
/// re-execute on-chain at real prices, so they are charged at what they actually cost rather than
/// estimated. `signature_floor` is the scheme's verification cost
/// (`SignatureType::turetzky_upper_gas_limit`); pass the larger scheme's when the scheme is not yet
/// known, since the payload is signed independently of it.
///
/// A pure function of its arguments, which is the point: it decides whether a payload is acceptable,
/// so every operator must reach the same verdict from the same payload. Anything that consulted live
/// chain state could put two honest operators on opposite sides of the boundary.
///
/// Three things are priced, and the payload has to carry all of them:
///
/// 1. **Execution** — the raw EVM cost of each op ([`UNBOUNDED_COLD_SSTORE_COST`], the `LOG*`
///    schedule) plus `external_call_gas`.
/// 2. **Transport** — intrinsic gas for the ABI-encoded payload's bytes. This scales with the
///    number of updates, so unlike the reporting estimators (which get it for free from revm
///    executing real calldata) the gate must charge it explicitly or it under-prices every
///    multi-slot payload.
/// 3. **Dispatch** — [`UNBOUNDED_APPLY_BASE_GAS`] plus
///    [`UNBOUNDED_APPLY_GAS_PER_PAYLOAD_BYTE`] for decoding the payload and walking it inside
///    `verifyAndUpdate`.
///
/// The return value is `max(execution + transport, EIP-7623 floor)`, mirroring how a transaction is
/// actually priced: a payload whose bytes dominate its execution pays the floor instead.
pub fn estimate_applied_payload_gas(
    updates: &[StateUpdate],
    external_call_gas: u64,
    signature_floor: u64,
) -> u64 {
    let mut gas = TX_BASE
        .saturating_add(signature_floor)
        .saturating_add(external_call_gas)
        .saturating_add(UNBOUNDED_APPLY_BASE_GAS);
    for update in updates {
        gas = gas.saturating_add(match update {
            StateUpdate::Store(_) => UNBOUNDED_COLD_SSTORE_COST,
            // Charged through `external_call_gas` from the trace.
            StateUpdate::Call(_) => 0,
            StateUpdate::Log0(l) => LOG_BASE + l.data.len() as u64 * LOG_BYTE,
            StateUpdate::Log1(l) => LOG_BASE + LOG_TOPIC + l.data.len() as u64 * LOG_BYTE,
            StateUpdate::Log2(l) => LOG_BASE + LOG_TOPIC * 2 + l.data.len() as u64 * LOG_BYTE,
            StateUpdate::Log3(l) => LOG_BASE + LOG_TOPIC * 3 + l.data.len() as u64 * LOG_BYTE,
            StateUpdate::Log4(l) => LOG_BASE + LOG_TOPIC * 4 + l.data.len() as u64 * LOG_BYTE,
            // Rejected by the caller; priced at zero so the bound stays defined either way.
            StateUpdate::Create(_) | StateUpdate::Create2(_) => 0,
        });
    }

    // Transport and dispatch, both priced off the real encoded payload rather than a per-op
    // approximation: that keeps dense and sparse slot values honest, covers a log's data bytes,
    // and stays correct if the encoding changes. The payload is what a `verifyAndUpdate`
    // transaction carries, bar the selector and attestation, which ride inside `signature_floor`.
    let payload = crate::encoding::encode_state_updates_to_abi(updates);
    gas = gas.saturating_add(
        (payload.len() as u64).saturating_mul(UNBOUNDED_APPLY_GAS_PER_PAYLOAD_BYTE),
    );
    let zero_bytes = payload.iter().filter(|byte| **byte == 0).count() as u64;
    let nonzero_bytes = payload.len() as u64 - zero_bytes;
    let transport = zero_bytes
        .saturating_mul(CALLDATA_ZERO_BYTE)
        .saturating_add(nonzero_bytes.saturating_mul(CALLDATA_NONZERO_BYTE));

    let tokens =
        zero_bytes.saturating_add(nonzero_bytes.saturating_mul(CALLDATA_FLOOR_NONZERO_TOKENS));
    let floor = TX_BASE.saturating_add(tokens.saturating_mul(CALLDATA_FLOOR_TOKEN));

    gas.saturating_add(transport).max(floor)
}

/// Enforce the `Unbounded` profile's payload invariant: applying the extracted updates on-chain must
/// cost no more than `budget`, and must not contain `CREATE`/`CREATE2`.
///
/// This is what makes lifting the simulation gas limit sound. The simulation may burn a terabyte of
/// gas; what lands on-chain still has to fit in a single transaction, so the constraint is priced
/// rather than counted. Writing many slots is fine — writing more than fits is not.
///
/// The [`STATE_TRACKER_SLOT`] is counted in the cost (it is a real write) but reported separately,
/// since every `trackState` diff carries exactly one and `verifyAndUpdate`'s own modifier rewrites
/// it idempotently.
pub fn validate_unbounded_cost(
    updates: &[StateUpdate],
    external_call_gas: u64,
    signature_floor: u64,
    budget: u64,
) -> Result<UnboundedCost, UnboundedCostViolation> {
    let mut cost = UnboundedCost {
        stores: 0,
        tracker_stores: 0,
        calls: 0,
        logs: 0,
        applied_gas_upper_bound: 0,
    };
    for (index, update) in updates.iter().enumerate() {
        match update {
            StateUpdate::Store(store) if store.slot == STATE_TRACKER_SLOT => {
                cost.tracker_stores += 1
            }
            StateUpdate::Store(_) => cost.stores += 1,
            StateUpdate::Call(_) => cost.calls += 1,
            StateUpdate::Log0(_)
            | StateUpdate::Log1(_)
            | StateUpdate::Log2(_)
            | StateUpdate::Log3(_)
            | StateUpdate::Log4(_) => cost.logs += 1,
            StateUpdate::Create(_) | StateUpdate::Create2(_) => {
                return Err(UnboundedCostViolation::CreateNotAllowed { index });
            }
        }
    }
    cost.applied_gas_upper_bound =
        estimate_applied_payload_gas(updates, external_call_gas, signature_floor);
    if cost.applied_gas_upper_bound > budget {
        return Err(UnboundedCostViolation::PayloadTooExpensive {
            estimated: cost.applied_gas_upper_bound,
            budget,
            stores: cost.stores,
        });
    }
    Ok(cost)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::IStateUpdateTypes;
    use alloy_primitives::{Address, Bytes, U256};

    fn store() -> StateUpdate {
        StateUpdate::Store(IStateUpdateTypes::Store {
            slot: B256::ZERO,
            value: B256::ZERO,
        })
    }

    fn call() -> StateUpdate {
        StateUpdate::Call(IStateUpdateTypes::Call {
            target: Address::ZERO,
            value: U256::ZERO,
            callargs: Bytes::new(),
        })
    }

    fn log1() -> StateUpdate {
        StateUpdate::Log1(IStateUpdateTypes::Log1 {
            data: Bytes::new(),
            topic1: B256::ZERO,
        })
    }

    fn create() -> StateUpdate {
        StateUpdate::Create(IStateUpdateTypes::Create {
            value: U256::ZERO,
            initcode: Bytes::new(),
        })
    }

    /// Budget with no signature floor and no call gas, so tests price only the payload ops.
    fn check(updates: &[StateUpdate]) -> Result<UnboundedCost, UnboundedCostViolation> {
        validate_unbounded_cost(updates, 0, 0, UNBOUNDED_PAYLOAD_GAS_BUDGET)
    }

    #[test]
    fn chain_profile_overrides_nothing() {
        assert_eq!(SimProfile::Chain.tx_gas_limit_override(), None);
        assert_eq!(SimProfile::Chain.block_gas_limit_override(), None);
        assert_eq!(SimProfile::Chain.payload_gas_budget(), None);
        assert_eq!(SimProfile::default(), SimProfile::Chain);
    }

    #[test]
    fn unbounded_profile_pins_its_constants() {
        assert_eq!(
            SimProfile::Unbounded.tx_gas_limit_override(),
            Some(UNBOUNDED_TX_GAS_LIMIT)
        );
        assert_eq!(
            SimProfile::Unbounded.block_gas_limit_override(),
            Some(UNBOUNDED_BLOCK_GAS_LIMIT)
        );
        assert_eq!(
            SimProfile::Unbounded.payload_gas_budget(),
            Some(UNBOUNDED_PAYLOAD_GAS_BUDGET)
        );
        // The constants are protocol-pinned: a change here is a consensus
        // break with the SP1 slashing guest and must ship as a new version.
        assert_eq!(UNBOUNDED_BLOCK_GAS_LIMIT, 1 << 40);
        assert_eq!(UNBOUNDED_TX_GAS_LIMIT, 1 << 40);
        // EIP-7825's per-transaction cap — the ceiling a payload must fit under.
        assert_eq!(UNBOUNDED_PAYLOAD_GAS_BUDGET, 1 << 24);
    }

    /// The conversion must carry both limits separately and leave `Chain`
    /// untouched, so a `Chain` execution still resolves to the header and
    /// hashes to the pre-override `chainConfigHash`.
    #[cfg(feature = "sp1-cc")]
    #[test]
    fn env_overrides_carry_the_profile_limits() {
        use sp1_cc_client_executor::EnvOverrides;

        let chain: EnvOverrides = SimProfile::Chain.into();
        assert!(chain.is_unset(), "Chain must not override anything");

        let unbounded: EnvOverrides = SimProfile::Unbounded.into();
        assert_eq!(unbounded.block_gas_limit, Some(UNBOUNDED_BLOCK_GAS_LIMIT));
        assert_eq!(unbounded.tx_gas_limit, Some(UNBOUNDED_TX_GAS_LIMIT));

        // What the EVM and the chainConfigHash both end up using. Pinned
        // against a realistic header limit so a future divergence between the
        // two constants shows up here rather than in a failing proof.
        let resolved = unbounded.resolve(30_000_000);
        assert_eq!(resolved.block, UNBOUNDED_BLOCK_GAS_LIMIT);
        assert_eq!(resolved.tx, UNBOUNDED_TX_GAS_LIMIT);
    }

    #[test]
    fn many_stores_are_valid_while_they_fit() {
        // The point of pricing rather than counting: a consumer that writes far more than one slot
        // is fine, because the payload still fits in a transaction.
        let updates: Vec<StateUpdate> = (0..500).map(|_| store()).collect();
        let cost = check(&updates).expect("500 writes fit under the cap");
        assert_eq!(cost.stores, 500);
        assert!(cost.applied_gas_upper_bound < UNBOUNDED_PAYLOAD_GAS_BUDGET);
    }

    #[test]
    fn a_payload_over_the_budget_is_rejected() {
        let n = (UNBOUNDED_PAYLOAD_GAS_BUDGET / UNBOUNDED_COLD_SSTORE_COST) as usize + 2;
        let updates: Vec<StateUpdate> = (0..n).map(|_| store()).collect();
        let err = check(&updates).unwrap_err();
        let UnboundedCostViolation::PayloadTooExpensive {
            estimated, budget, ..
        } = err
        else {
            panic!("expected PayloadTooExpensive, got {err:?}");
        };
        assert!(estimated > budget);
        assert!(err.to_string().contains("over the"));
    }

    #[test]
    fn the_budget_boundary_is_where_arithmetic_says_it_is() {
        // Exactly at the cap passes; one more store does not. Pins the comparison as `>` rather
        // than `>=`, so a payload that precisely fills a transaction is still usable.
        //
        // The boundary is found by search rather than division: per-store cost is no longer a
        // single constant, since transport depends on how the encoded payload's bytes fall.
        let mut n = 0usize;
        while check(&(0..n + 1).map(|_| store()).collect::<Vec<_>>()).is_ok() {
            n += 1;
            assert!(n < 10_000, "boundary search must terminate");
        }
        assert!(n > 0, "at least one store must fit");

        let updates: Vec<StateUpdate> = (0..n).map(|_| store()).collect();
        let cost = check(&updates).expect("the largest payload that fits must be accepted");
        assert!(cost.applied_gas_upper_bound <= UNBOUNDED_PAYLOAD_GAS_BUDGET);

        let one_more: Vec<StateUpdate> = (0..n + 1).map(|_| store()).collect();
        assert!(
            check(&one_more).is_err(),
            "one store past the cap must fail"
        );
    }

    #[test]
    fn transport_and_dispatch_are_priced_on_top_of_execution() {
        // The terms this gate exists to not forget. A single store's raw EVM cost is the cold
        // SSTORE; what a transaction actually pays also includes the bytes that carry it and the
        // loop that applies it, so the bound must sit strictly above the execution-only figure.
        let updates = vec![store()];
        let execution_only = TX_BASE + UNBOUNDED_COLD_SSTORE_COST;
        let bound = estimate_applied_payload_gas(&updates, 0, 0);
        assert!(
            bound > execution_only + UNBOUNDED_APPLY_BASE_GAS,
            "bound {bound} must exceed execution ({execution_only}) plus the fixed apply cost, \
             leaving room for the payload's own bytes"
        );

        // Transport scales with payload bytes: a log carrying data costs more to carry than an
        // empty one, beyond the 8 gas/byte the LOG opcode itself charges.
        let empty_log = estimate_applied_payload_gas(&[log1()], 0, 0);
        let fat_log = estimate_applied_payload_gas(
            &[StateUpdate::Log1(IStateUpdateTypes::Log1 {
                data: Bytes::from(vec![0xab; 256]),
                topic1: B256::ZERO,
            })],
            0,
            0,
        );
        assert!(
            fat_log > empty_log + 256 * 8,
            "256 data bytes must cost more than the LOG opcode's 8/byte alone: \
             {fat_log} vs {empty_log}"
        );
    }

    #[test]
    fn the_signature_floor_and_call_gas_count_against_the_budget() {
        // A payload that fits on its own can be pushed over by what rides with it on-chain.
        let updates = vec![store()];
        assert!(
            validate_unbounded_cost(&updates, 0, 250_000, UNBOUNDED_PAYLOAD_GAS_BUDGET).is_ok()
        );
        assert!(
            validate_unbounded_cost(
                &updates,
                UNBOUNDED_PAYLOAD_GAS_BUDGET,
                250_000,
                UNBOUNDED_PAYLOAD_GAS_BUDGET
            )
            .is_err(),
            "external call gas is real on-chain cost and must count"
        );
    }

    #[test]
    fn single_store_with_calls_and_logs_is_valid() {
        let updates = vec![call(), store(), log1(), call(), log1()];
        let cost = check(&updates).unwrap();
        assert_eq!(cost.stores, 1);
        assert_eq!(cost.calls, 2);
        assert_eq!(cost.logs, 2);
    }

    #[test]
    fn zero_stores_is_valid() {
        assert_eq!(check(&[call(), log1()]).unwrap().stores, 0);
    }

    #[test]
    fn empty_payload_is_valid() {
        let cost = check(&[]).unwrap();
        assert_eq!(cost.stores, 0);
        // Not bare `TX_BASE`: an empty payload still encodes two array headers — 128 bytes, being
        // two offsets and two zero lengths, of which only the offsets' low bytes are non-zero —
        // and applying it still enters the decode loop. Both are costs a real transaction pays.
        let transport = 126 * CALLDATA_ZERO_BYTE + 2 * CALLDATA_NONZERO_BYTE;
        let dispatch = UNBOUNDED_APPLY_BASE_GAS + 128 * UNBOUNDED_APPLY_GAS_PER_PAYLOAD_BYTE;
        assert_eq!(
            cost.applied_gas_upper_bound,
            TX_BASE + transport + dispatch,
            "an empty payload costs the tx base plus the cost of carrying and decoding two \
             empty array headers"
        );
    }

    #[test]
    fn tracker_slot_store_is_counted_but_reported_separately() {
        // The realistic trackState diff: counter bump + one commitment write + log.
        let tracker = StateUpdate::Store(IStateUpdateTypes::Store {
            slot: STATE_TRACKER_SLOT,
            value: B256::with_last_byte(1),
        });
        let cost = check(&[tracker, store(), log1()]).unwrap();
        assert_eq!(cost.stores, 1);
        assert_eq!(cost.tracker_stores, 1);
        // It is a real write, so it is priced even though it is not counted in `stores`.
        assert!(cost.applied_gas_upper_bound >= TX_BASE + 2 * UNBOUNDED_COLD_SSTORE_COST);
    }

    #[test]
    fn create_is_rejected_at_index() {
        let err = check(&[store(), create()]).unwrap_err();
        assert_eq!(err, UnboundedCostViolation::CreateNotAllowed { index: 1 });
    }

    #[test]
    fn create2_is_rejected() {
        let update = StateUpdate::Create2(IStateUpdateTypes::Create2 {
            salt: B256::ZERO,
            value: U256::ZERO,
            initcode: Bytes::new(),
        });
        let err = check(&[update]).unwrap_err();
        assert!(matches!(
            err,
            UnboundedCostViolation::CreateNotAllowed { index: 0 }
        ));
    }
}
