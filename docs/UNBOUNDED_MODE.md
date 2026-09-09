# Unbounded Simulation Mode (`SimProfile::Unbounded`)

**Status:** Implemented (analyzer side) — guest-side mirroring required before slashing ships
**Related:** [GAS_KILLER_SLASHING_SPEC.md](./GAS_KILLER_SLASHING_SPEC.md), [SP1_REVM_IMPLEMENTATION_SPEC.md](./SP1_REVM_IMPLEMENTATION_SPEC.md), solidity-sdk PR [#51](https://github.com/gas-killer/solidity-sdk/pull/51) (single-slot commitment — open, and not a prerequisite for this mode)

## What it is

Gas Killer's core trade is: **computation happens off-chain, only the net state
diff lands on-chain.** Until now the analyzer simulated tracked functions under
the real chain's environment, so a tracked function was still bounded by the
block gas limit (and post-Osaka, the EIP-7825 2^24 tx cap) — even though nothing
about the *payload* required that bound.

`SimProfile::Unbounded` removes the bound. The tracked function is simulated
under pinned protocol limits ~24,000× a mainnet block:

| Constant | Value | Meaning |
|---|---|---|
| `UNBOUNDED_BLOCK_GAS_LIMIT` | `1 << 40` (~1.1 Tgas) | block env gas limit during simulation |
| `UNBOUNDED_TX_GAS_LIMIT` | `1 << 40` | tx gas limit during simulation (EIP-7825 cap deliberately not applied) |

In exchange, the extracted payload must fit in a single on-chain transaction
(`validate_unbounded_cost`):

| Constant | Value | Meaning |
|---|---|---|
| `UNBOUNDED_PAYLOAD_GAS_BUDGET` | `1 << 24` (16,777,216) | ceiling on the gas needed to apply the payload — EIP-7825's per-transaction cap |
| `UNBOUNDED_COLD_SSTORE_COST` | `22,100` | price charged per `Store`: cold SLOAD (2,100) + zero→nonzero SSTORE (20,000) |
| `UNBOUNDED_APPLY_BASE_GAS` | `2,000` | fixed cost of entering `verifyAndUpdate`'s decode/apply loop |
| `UNBOUNDED_APPLY_GAS_PER_PAYLOAD_BYTE` | `14` | decoding and dispatching one byte of encoded payload |

Applying the payload must come to no more than the budget, counting all three of:

- **Execution** — every `Store`/`Log*` at its EVM price, plus the measured gas
  of any `Call` ops, plus the signature-verification floor.
- **Transport** — the transaction base cost and intrinsic gas for the encoded
  payload's own bytes (4 per zero byte, 16 per non-zero), or the EIP-7623 floor
  where that is larger. This scales with payload size, so a gate that omitted it
  would over-admit every multi-slot payload.
- **Dispatch** — `UNBOUNDED_APPLY_BASE_GAS` plus
  `UNBOUNDED_APPLY_GAS_PER_PAYLOAD_BYTE` per byte, for decoding the payload and
  walking it inside `verifyAndUpdate`.
- **No `CREATE`/`CREATE2`.** Not a cost question: a net diff cannot reconstruct
  replayable initcode, so contract creation is unrepresentable at any price.
- Any number of `Call` / `Log*` ops within budget — but `Call`s re-execute
  on-chain at real gas prices, so compute inside them is *not* killed. They are
  priced at the gas the trace measured, so an expensive call spends the same
  budget a batch of writes would.

So the profile **lifts EIP-7825 for the simulation, where the cap protects
nothing, and enforces it on the payload, where it is binding.**

The result: **unbounded Solidity, on-chain state bounded by what a transaction
can carry.** A tracked function may iterate a million-entry order book, verify a
multi-megabyte witness, or run a whole matching epoch, and write however many
slots it likes — roughly 650 cold writes fit under the cap, a little fewer when
the slots and values are dense (their bytes cost more to carry) — as long as the
diff can actually be mined.

The constraint is *priced*, not counted. Consumers whose state is too large for
one transaction can commit it into fewer slots; in the limit that is the
single-slot commitment pattern of solidity-sdk PR #51, where the expanded state
travels as a calldata witness and only its hash lives in storage. **That pattern
is an option for contracts that need it, not a requirement of this mode.**

### Why the bound is analytic

The gate prices the payload with a pure function of the payload
(`estimate_applied_payload_gas`), not with the revm estimate the same call
computes for reporting. Accept/reject is part of what operators must agree on: a
verdict derived from live-fetched state could put two honest operators on
opposite sides of the boundary and split quorum. For the same reason the gate
carries its own `UNBOUNDED_COLD_SSTORE_COST` rather than reusing the tuned
figure in `gas_analyzer_core::heuristic` — that one approximates typical cost for
user-facing savings numbers, and a gate that under-prices a write would admit
payloads that do not fit.

Payloads are priced against the **more expensive** signature scheme's floor,
since the payload is signed before the scheme is fixed.

That independence has a cost worth being explicit about: the analytic model is a
hand-written reimplementation of something the measured path gets for free.
`estimate_state_changes_gas` runs the real encoded payload through revm, so revm
charges intrinsic calldata gas and the handler's decode loop automatically,
without anyone having to think about them. A hand-written model contains exactly
the terms someone remembered to write down — and the first version of this gate
priced execution only, omitting both transport and dispatch (together ~11% per
store). That is invisible except within a few percent of the ceiling, which is
precisely where an admission gate lives.

So the measured path is used as an *oracle* for the analytic one:
`analytic_bound_dominates_measured_apply_cost` in `gas-analyzer-estimator`
asserts that `estimate_applied_payload_gas` is never below what revm actually
charges to apply the same payload, across store-shaped, log-shaped, and mixed
payloads from 1 to 650 updates, with sparse and dense slot values. It passes the
signature floor as zero on purpose — at 250,000 a fixed floor would mask a
missing per-update term until payloads grew past ~200 updates. Any future dropped
term fails that test instead of shipping as an over-admitting gate.

### Calldata

Neither revm nor the EVM protocol caps calldata *size*; calldata is priced in
gas (EIP-7623 floor). Lifting the gas limits therefore lifts the effective
calldata bound too — `1 << 40` gas admits ~27 GB of floor-priced calldata.
Multi-megabyte witnesses simulate fine even though they could never land in a
real transaction; only the signed payload must fit on-chain.

## How to use it

```rust
use gas_analyzer_core::SimProfile;
use gas_analyzer_evmsketch::{
    EvmSketchExecutorCache, StateEncoding, call_to_encoded_state_updates_with_evmsketch_profiled,
};

let updates = call_to_encoded_state_updates_with_evmsketch_profiled(
    &cache,
    rpc_url,
    tx_request,
    block_number,
    StateEncoding::PrestateNet,
    SimProfile::Unbounded,
).await?;
```

Semantics under `Unbounded`:

1. Both extraction paths (prestate fast path *and* struct-log fallback) run the
   `debug_traceCall` with `tx.gas = 2^40` and `blockOverrides.gasLimit = 2^40`.
   The caller's `gas` field is overridden unconditionally — the profile is a
   pinned protocol environment, not a hint.
2. The extracted updates are priced against the payload budget; a violation is a
   **hard error** — signing a payload that cannot be mined produces a task
   nobody can settle.
3. The **gas estimate still uses the real chain env** — `verifyAndUpdate` lands
   in a real block, so applying the payload is priced under real limits.

### Node requirement

The node serving `debug_traceCall` has the last word on simulation gas:

| Node | Requirement |
|---|---|
| anvil | `--disable-block-gas-limit` |
| geth | `--rpc.gascap=0` (or ≥ the profile limit) |
| reth | `--rpc.gascap` raised accordingly |

This is a **consensus requirement, not a performance setting.** Every operator
must run a cap-lifted node, and a deployment should verify it rather than assume
it.

A clamping node makes heavy calls OOG inside the tracer. The reverted root frame
forces the struct-log fallback classification (PR #165), so the diff is never
*unsound* — but the failure is quieter than that makes it sound, and it is worth
being precise about what a mis-provisioned operator actually produces:

- Extraction **succeeds**. It returns `Ok`, not an error, so no caller can tell a
  clamped result from a real one.
- If the call OOGs before writing anything, the payload is **empty**.
- If it writes and *then* runs out of gas, the payload contains the writes that
  landed before the halt — a **partial** state commitment the real execution
  never ended at. This passes the payload budget — one store is well inside it —
  so the budget gate cannot catch it either.

So a clamped node signs a payload that disagrees with every correctly-provisioned
one. A minority of such nodes is outvoted and simply never reaches quorum. A
majority would form quorum on the empty or partial payload and commit it. Both
cases are pinned by `chain_profile_oog_after_a_write_yields_a_partial_payload`
and `test_unbounded_profile_extracts_beyond_block_gas_limit` in
`crates/evmsketch`.

## Determinism: why the constants are pinned

The environment override is **part of the protocol**, not a local tunable.
Three parties re-execute the same tracked function and must get bit-identical
results:

1. **Operators**, when extracting the update payload they BLS/ECDSA-sign.
2. **This analyzer**, when simulating on a user's behalf.
3. **The SP1 slashing guest** ([SP1_REVM_IMPLEMENTATION_SPEC.md](./SP1_REVM_IMPLEMENTATION_SPEC.md)),
   when a slasher re-executes the original function inside the zkVM to prove
   the signed updates wrong.

If the guest ran with the real header's gas limit while operators simulated
under lifted limits, a heavy-but-honest execution would OOG in the guest,
produce a different update set, and **falsely slash honest operators**.
Conversely, ad-hoc per-operator limits would fragment quorum signatures at the
boundary. Hence:

- The limits are `pub const` in `gas_analyzer_core::sim_profile` — the guest
  crate must import them from there (the crate is pure/WASM-safe and compiles
  in a zkVM guest).
- Changing a value is a **lockstep fleet rollout** across operators and the
  committed guest ELF — never a silent edit. What distinguishes one set of
  limits from another is not the Rust identifier but the values themselves: the
  guest binds the overrides into `chainConfigHash`
  (`ChainConfigWithEnvOverrides`), so a proof produced under different limits
  cannot satisfy a verifier expecting these ones. An operator fleet that has
  half-rolled a change does not produce quietly-divergent proofs; it produces
  proofs that fail verification.

### Fork support (merged)

The mechanism lives in the BreadchainCoop `sp1-contract-call` fork
([#12](https://github.com/BreadchainCoop/sp1-contract-call/pull/12), merged
into `cancun-v1`). `crates/evmsketch` and `crates/core` pin it by exact
revision rather than by branch: these crates carry the EVM semantics every
party re-executes under, so a change to them has to arrive as a reviewed commit
here instead of whenever someone regenerates the lockfile.

Enable `gas-analyzer-core`'s `sp1-cc` feature and convert the profile — never
hand-write the limits:

```rust
use gas_analyzer_core::SimProfile;
use sp1_cc_client_executor::EnvOverrides;

let overrides: EnvOverrides = SimProfile::Unbounded.into();

// Host: prefetch state under the SAME limits the guest will execute with —
// a host that runs out of gas early produces a witness the guest cannot
// complete on.
let out = sketch.call_raw_with_overrides(&input, overrides).await?;
let sketch_input = sketch.finalize().await?;

// Guest: re-execute under the identical env; the overrides are bound into
// `chainConfigHash` (ChainConfigWithEnvOverrides), so a proof under
// different limits cannot satisfy the verifier.
let executor = ClientExecutor::eth(&sketch_input)?;
executor.execute_and_commit_with_overrides(input, overrides);
```

The conversion is the supported path because `EnvOverrides::gas_limits(x)` sets
both limits from one value — correct only while `UNBOUNDED_BLOCK_GAS_LIMIT` and
`UNBOUNDED_TX_GAS_LIMIT` are equal, and silently wrong the day they are not.
`From<SimProfile>` carries them separately and keeps `Chain` overriding
nothing, so a `Chain` execution still resolves to the header and hashes to the
pre-override `chainConfigHash`.

Setting `tx_gas_limit` also lifts revm's EIP-7825 cap (2^24, Osaka onwards) to
the same value, so execution is identical on both sides of the hardfork
boundary. A transaction limit above the block limit additionally raises the
block limit to match, because revm rejects a transaction whose gas limit
exceeds the block's. Regression tests in the fork pin these: a ~40M-gas call
runs out of gas at exactly the header limit without overrides, and succeeds
(burning more than any real block) under lifted limits.

> **Protocol note — the 2^24 cap.** Before #12, sp1-cc assigned the gas limit
> via `modify_tx_chained` on the context, but `Evm::transact` replaces the tx
> env with the converted `ContractInput`, whose `TxEnv::default()` carries
> revm's 2^24 builder default. Every sketch and guest execution ran capped at
> **16,777,216 gas** regardless of the header, so any tracked function above
> ~16.7M gas would have run out of gas in host prefetch and guest
> re-execution even in bounded mode.
>
> **This analyzer's results are unaffected.** gas-analyzer uses `EvmSketch`
> only for its anchor header and provider; extraction runs through
> `debug_traceCall` on the node, and gas estimation through
> `gas-analyzer-estimator`'s own revm, which sets the transaction limit via
> `effective_tx_gas_limit` and is covered by its own above-2^24 regression
> test. No stored baseline, fixture, or digest in this repo was computed under
> the capped path, so none needed re-deriving for the bump
> ([#192](https://github.com/gas-killer/gas-analyzer/issues/192)). Anything
> that *did* drive sp1-cc execution directly is in scope for that check.

Remaining before slashing ships: the slashing guest program (per
`SP1_REVM_IMPLEMENTATION_SPEC.md`) must convert its profile through
`From<SimProfile>` rather than restating the constants, so the limits it
executed under are bound into the `chainConfigHash` its proof commits to.

## What this mode does *not* change

- **Trust model.** The quorum still signs the diff; the proof (when it ships)
  is a fraud proof, not a validity proof. Unbounded mode widens what operators
  can compute, not what users must trust.
- **On-chain application costs.** Applying a payload costs the transaction base,
  the BLS/ECDSA verification floor, and the writes and logs the diff actually
  carries — capped by `UNBOUNDED_PAYLOAD_GAS_BUDGET`, never scaling with
  off-chain compute. A commitment-shaped consumer stays at one SSTORE; a
  consumer that writes 300 slots pays for 300, and one that writes 1,000 is
  rejected rather than made cheap.
- **`Call` op costs.** Calls in the payload re-execute on-chain at real gas, so
  compute inside a `Call` is not killed — it is charged against the payload
  budget at the gas the trace measured.
- **The serialization model.** One transition per `transitionIndex` per
  consumer; a direct on-chain call to a tracked function still invalidates
  in-flight signed updates. Heavy simulations widen this race window
  (extraction + signing + proving all take longer than a cheap call) —
  consumers using unbounded mode should gate direct execution paths.

## Test coverage

`gas_analyzer_core::sim_profile` unit tests cover the profile overrides and the
budget arithmetic: the pinned constants, many stores accepted while they fit, the
exact boundary (largest fitting payload accepted, one store past it rejected),
the signature floor and external call gas counting against the budget, transport
and dispatch priced on top of execution, the tracker slot priced but reported
separately, empty and zero-store payloads, and `CREATE`/`CREATE2` rejection with
the offending index. Under the `sp1-cc` feature they also pin the
`From<SimProfile>` conversion: `Chain` overrides nothing, `Unbounded` carries
both limits separately, and both resolve to the values the guest hashes into
`chainConfigHash`.

`gas-analyzer-estimator`'s `analytic_bound_dominates_measured_apply_cost` is the
one that guards the model rather than its arithmetic — see [Why the bound is
analytic](#why-the-bound-is-analytic). It measures the real cost with revm and
asserts the analytic bound never falls below it, so a dropped term fails a test
instead of loosening the gate.

`gas-analyzer-evmsketch`'s `anvil_integration` module covers the same ground
against a real anvil started with `--disable-block-gas-limit`. These tests are
`#[ignore]`d so a plain `cargo test` without foundry on PATH skips rather than
fails, and CI runs them explicitly (`cargo test -p gas-analyzer-evmsketch
anvil_integration -- --ignored`):

| test | pins |
|---|---|
| `test_unbounded_profile_extracts_beyond_block_gas_limit` | a ~40M-gas busy loop OOGs under `Chain` — classified `Fallback` per #165's revert rule, returning an **empty** payload rather than an error — and reduces to exactly `[Store, Log1]` under `Unbounded` |
| `chain_profile_oog_after_a_write_yields_a_partial_payload` | a clamped node that writes *then* OOGs returns the pre-OOG write: `Ok`, non-empty, and indistinguishable from a correct result |
| `unbounded_profile_accepts_a_multi_slot_payload_that_fits` | a two-slot writer is **accepted** — the gate prices the payload rather than counting its writes |
| `unbounded_profile_rejects_a_payload_over_the_transaction_budget` | a 1,000-slot writer extracts fine and is rejected with `PayloadTooExpensive { stores: 1000 }` |
