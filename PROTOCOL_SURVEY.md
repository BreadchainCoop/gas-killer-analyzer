# Protocol survey — GasKiller candidates beyond Morpho

Measured with this repository's analyzer (`cargo run -- t <hash>`, EvmSketch backend) against Ethereum mainnet. Companion to `MORPHO_CANDIDATES.md` (Morpho) and `CALL_BLOCKED_CANDIDATES.md` (transactions that score zero because of external calls).

Every number in the results tables is analyzer output. Where a figure is my own arithmetic it says so. The appendix at the end indexes the measured transactions by their 4-byte selector, separating keccak-verified function names from labels inferred only from emitted events.

> ### Revised for the new signature floor — 2026-09-04
>
> The Schnorr floor was raised from **27,000 to 50,000 gas** on `main` (`87aaf1c`), derived from a
> Sepolia measurement of a 3-operator 2-of-3 `SchnorrStakeRegistry` (32,066 full participation,
> 45,417 with one non-signer). Gas used and replay cost are unchanged — verified by re-running
> three reference transactions on the rebuilt binary — so all revisions here are arithmetic.
>
> **Six protocols lost every win at the new floor: EigenLayer, Ethena, Euler, Lido, Safe and
> World ID.** Sections below that predate the change are corrected inline where the conclusion
> moved, but treat any percentage in this file as provisional against
> `ALL_TRANSACTION_ANALYSES.md`, which was regenerated wholesale.

## Headline: Railgun

**15 direct calls to the Railgun smart wallet, all trace-measured, all clearing both signature floors.** Schnorr savings range **60.83%–78.72%** (median 72.02%). BLS savings range 19.53%–64.86%.

In aggregate: 15,174,097 gas used on chain becomes 3,765,439 under GasKiller with Schnorr — a saving of **11,408,658 gas (75.2%)**.

Railgun is the only protocol where **every** transaction clears the BLS floor. Aave manages it on 2 of 9 borrows; across the remaining seven protocols, 0 of ~60 transactions cleared it.

### Why it works

Railgun verifies its ZK proofs and computes its Poseidon hashes **in its own contract code**, and leaves behind only commitment and nullifier slots. The diffs are `Store`-dominated with few or no calls — the best result has **11 stores, 3 logs and zero calls**, so 1,085,832 gas of work replays for 181,095.

Contrast the same protocol reached through its RelayAdapt contract. Its diff is 2 stores plus **3 calls**, and the first call is `0xd8ae136a` — the *same* `transact` function the direct transactions call. Replaying it re-runs the entire shielded transaction:

| | direct to smart wallet | via RelayAdapt |
|---|---:|---:|
| gas used | 484,303 – 1,615,755 | 523,496 / 1,120,780 |
| GasKiller cost | 139,722 – 317,840 | 533,777 / 1,116,659 |
| **Schnorr saving** | **65.6–80.8%** | **0%** |

All 3 RelayAdapt transactions analyzed scored zero.

**The good path is also the common path.** Of 704 successful Railgun transactions found in a 40,000-block window, **374 (53%) went directly to the smart wallet** and 273 went via RelayAdapt. That distinguishes Railgun from Privacy Pools (2 direct withdrawals in 17 days) and Chainlink (0 of 242 direct).

### Railgun results

| tx | gas used | GasKiller cost | Schnorr saved | BLS saved | state updates |
|---|---:|---:|---:|---:|---|
| [`0xaa357a48…`](https://etherscan.io/tx/0xaa357a4824001aed7173b3bc7d976f997fc7839def4c56ec070db97ec2121bc4) | 1,085,832 | 181,095 | **854,737** (78.72%) | 654,737 (60.30%) | `Store`×11, `Log1`×3 |
| [`0x32daef80…`](https://etherscan.io/tx/0x32daef80a0c5180dcf45b15130e10ecced485242f0d3305b30942ebeb5aec364) | 1,056,246 | 197,859 | **808,387** (76.53%) | 608,387 (57.60%) | `Store`×12, `Log1`×3 |
| [`0xe7e605b6…`](https://etherscan.io/tx/0xe7e605b6520aaf757f4531a88af4966866d86fee61ec06e93b3423b30a934adc) | 1,615,755 | 317,840 | **1,247,915** (77.23%) | 1,047,915 (64.86%) | `Store`×15, `Log1`×5, `Call`×2 |
| [`0xa2177825…`](https://etherscan.io/tx/0xa21778257ba78ce1354a4ff25a48ee07854e5e858f4facfe3e3c3893d9a1945f) | 1,561,573 | 312,286 | **1,199,287** (76.80%) | 999,287 (63.99%) | `Store`×16, `Log1`×5, `Call`×2 |
| [`0x73a1d71e…`](https://etherscan.io/tx/0x73a1d71e2cfa678b63c934c8c04eb6b6069de89c85faf16d0376241ecabfb0ec) | 1,097,058 | 213,396 | **833,662** (75.99%) | 633,662 (57.76%) | `Store`×14, `Log1`×3 |
| [`0xa3a010fa…`](https://etherscan.io/tx/0xa3a010fa890d910e669fba1ea7b681a4c1f464b754c5b7bff7d62ae15ae25e71) | 1,113,545 | 241,625 | **821,920** (73.81%) | 621,920 (55.85%) | `Store`×12, `Log1`×4, `Call`×2 |
| [`0x04736806…`](https://etherscan.io/tx/0x04736806756593b664eb29591a2ea046b2261c5a4fa1bdd1707a6dc5abf54f07) | 1,136,044 | 266,554 | **819,490** (72.14%) | 619,490 (54.53%) | `Store`×13, `Log1`×4, `Call`×2 |
| [`0x39a67a29…`](https://etherscan.io/tx/0x39a67a2964b675ccd1be1939c513b46f62cae71c3f320bece6acdaf71934b3ae) | 1,131,080 | 266,430 | **814,650** (72.02%) | 614,650 (54.34%) | `Store`×14, `Log1`×4, `Call`×2 |
| [`0xaf36e218…`](https://etherscan.io/tx/0xaf36e2187e095fa88299a8859632963594414b716f36aae541318d4ce71740e6) | 1,177,014 | 282,477 | **844,537** (71.75%) | 644,537 (54.76%) | `Store`×15, `Log1`×4, `Call`×2 |
| [`0x0376edd3…`](https://etherscan.io/tx/0x0376edd36b0c9211b1a38f41e5f1c04233478ca4dcf7d4852ef313deb1c57ade) | 724,515 | 168,652 | **505,863** (69.82%) | 305,863 (42.22%) | `Store`×10, `Log1`×2, `Call`×2 |
| [`0xab44777b…`](https://etherscan.io/tx/0xab44777b4e3a37169ea03163ec5d14dbf668bcb18219c3a95cc2313c2be55a3d) | 736,786 | 177,753 | **509,033** (69.09%) | 309,033 (41.94%) | `Store`×9, `Log1`×2, `Call`×2 |
| [`0x27ce0220…`](https://etherscan.io/tx/0x27ce022039ef027d473c61f3140da32c8e58f0a8daaee826e6f04a58744db447) | 742,727 | 185,294 | **507,433** (68.32%) | 307,433 (41.39%) | `Store`×10, `Log1`×2, `Call`×2 |
| [`0x3d54cfc3…`](https://etherscan.io/tx/0x3d54cfc375e626acd71432b2ab59a94bde2f6ee2490528ca8259417091e3ab97) | 752,878 | 197,812 | **505,066** (67.08%) | 305,066 (40.52%) | `Store`×11, `Log1`×2, `Call`×2 |
| [`0x6837bb8d…`](https://etherscan.io/tx/0x6837bb8d629ee0dce5f045acfc6c1e296df4abe1907897820bf621462dc23425) | 758,741 | 211,644 | **497,097** (65.52%) | 297,097 (39.16%) | `Store`×14, `Log1`×2, `Call`×2 |
| [`0x792a8e57…`](https://etherscan.io/tx/0x792a8e5783cec82cc456d83f0f1703a2bf71eafa05984a17896809bd952567cc) | 484,303 | 139,722 | **294,581** (60.83%) | 94,581 (19.53%) | `Log1`×3, `Store`×2, `Call`×2 |

By function:

- **private transfer / unshield** (`0xd8ae136a`) — 10 txs, 65.6–80.8% Schnorr, gas 484,303–1,615,755. **This selector was not verified**: no signature I constructed matched it, so the name is inferred from the `Nullified` and `Unshield` events it emits, not from the selector.
- **`shield`** (`0x044a40c3`, `shield(((bytes32,(uint8,address,uint256),uint120),(bytes32[3],bytes32))[])`) — 5 txs, 68.5–73.0% Schnorr, gas 724,515–758,741

On the RelayAdapt side, only 1 of the 3 completed a real replay (`0x2d754e6f…`, surplus −10,281). The other two fell back to heuristic — one of them reverted mid-replay against the smart wallet on all 3 attempts. All three scored zero either way, and their heuristic surpluses (+4,121 and +10,372) are well under the floor, so the fallbacks do not change the conclusion.

## All protocols surveyed

Best trace-measured Schnorr saving per protocol, and whether the winning shape is reachable in practice.

| protocol | best measured | BLS | winning shape | how common |
|---|---:|---:|---|---|
| **Kelp** | **83.29%** | **58.85%** | direct `depositETH` — 4 updates, 1 call | **0.36 qualifying txs/day** |
| **Railgun** | **78.72%** | **60.30%** | direct call to smart wallet | 374 of 704 (53%) |
| **Aave** | **59.61%** | **yes (2 txs)** | direct `borrow` (any borrower); `withdraw` if multi-asset | ~25% of txs are direct borrows |
| **Pyth** | **52.06%** | 0% | few feeds written per update; no external calls | **649 of 655 direct (99.1%)** |
| **Chronicle** | **32.64%** | 0% | direct feed poke; 2 updates, no external calls | **17 of 24 measured win; ~90% of traffic direct** |
| **Symbiotic** | **57.04%** | 0% | direct ERC-4626 `withdraw`/`redeem` on a vault | 1.49/day on the one vault measured |
| **Renzo** | *62.97%* | 0% | `claim` via the withdraw contract (**label inferred**) | 1 of 2 measured |
| **Mellow** | **41.55%** | 0% | direct ERC-4626 `withdraw`/`redeem` on a vault | 1.61/day on steakLRT |
| Puffer | *7.06%* | 0% | direct `requestWithdrawal` (**label inferred**) | 1 of 2 measured |
| Swell | 0% | 0% | none — withdrawal routes are call-blocked | 0 of 3 |
| Privacy Pools | 19.47% | 0% | direct call to pool | 2 in 17 days |
| Ether.fi | 11.09% | 0% | EtherFiAdmin oracle report | every ~4 hours |
| EigenLayer | **0%** | 0% | none — checkpoint surplus (23,927–38,841) is under the 50,000 floor | 0 of 13 at the new floor |
| Pendle | 2.60% *(aggregator tx, not Pendle's own)* | 0% | none of Pendle's own entry points clear the floor | 1 of 8 |
| World ID | **0%** | 0% | none — best surplus 35,578, under the floor | 0 of 7 at the new floor |
| Morpho | 0.51% | 0% | bundler multicall reallocation | 1 of 25 |
| Safe | **0%** | 0% | none — best surplus 37,454, under the floor | 0 of 12 at the new floor |
| **Euler** | **0%** | 0% | none — EVC router mandatory | **0 of 191 direct** |
| **Ondo** | **0%** own *(12.09% is an MEV bot that merely touches Ondo)* | 0% | none of Ondo's own mint/redeem clear the floor | 52 mint/burns in 60k blocks |
| Chainlink | 0% | 0% | none — all traffic via forwarder | 0 of 242 direct |
| Lido | **0%** | 0% | none — best surplus 46,558, under the floor | 0 of 13 at the new floor |
| Ethena | **0%** | 0% | none — best surplus 48,699, 1,301 short of the floor | 0 of 22 at the new floor |
| ERC-4337 EntryPoint | *85.18%?* | *60%?* | **suspect — likely estimator false positive** | 2 of 8 measured |
| Panther | 0% | 0% | none — shielded pool is not on mainnet | 0 of 1 |
| **Umbra** | **0%** | 0% | **none — all 8 txs have negative surplus** | 1.4 txs/day (lowest surveyed) |
| **Sky (Maker)** | **0%** | 0% | **none — 0 direct calls to Vat/PSM/Jug in 3h** | ~6,500/day core txs, all indirect |
| Notional | — | — | **nothing to measure — not active on mainnet** | 0 protocol events in 8 days |
| **ENS** | **0%** | 0% | **none — 18 of 18 measured, best is 68% short of the floor** | 877 txs/day, all shapes zero |

## What predicts a good candidate

Two conditions, both necessary. Every result above is explained by them. Aave adds a third dimension: the two conditions can hold for one *function* of a protocol and fail for another — `borrow` clears the floor 9 times out of 9 while `supply` and `repay` never do, because only the former runs a per-reserve health-factor loop. Screen per entry point, not per protocol.

**1. The expensive work must happen in the contract the transaction is sent to.** The sharpest evidence is Aave vs Euler: identical per-asset risk math, 59.61% vs **0%** (Euler's best surplus, 34,191 gas, no longer clears the floor), because Aave permits direct `Pool` calls and Euler mandates the EVC router. The analyzer keeps a regular `CALL` as one instruction and re-executes it on replay, so anything inside it is never stripped (`crates/core/src/trace.rs:255`; `crates/core/src/prestate.rs` documents the same constraint for the net form). Railgun direct vs Railgun RelayAdapt is the same operation on the same contract scoring 80% vs 0% on this alone.

**2. The work must actually be computation, not bookkeeping.** Pendle satisfies condition 1 on its one direct-to-market swap and still scores ~2.7% surplus, because a swap is mostly storage writes. Ether.fi's `claimWithdraw` is the clearest case: its 43,868 gas per claim decomposes as ~25,000 of storage writes + 3,768 of logs + ~15,100 of calls, leaving ~0 for computation.

The winners are cryptographic: Railgun (ZK proofs + Poseidon in its own code), Privacy Pools (Poseidon over a merkle tree), Ether.fi (oracle report processing). Ordinary DeFi arithmetic — swap curves, share conversions, interest accrual — is never large enough to dominate a transaction's gas.

The restaking block adds a third dimension that neither condition captures: **volume**. Kelp's
`depositETH` satisfies both conditions better than anything else measured — 83.29%, the highest
in the survey — and is worth $25/month, because the pool takes 0.36 qualifying deposits a day.
Chronicle at half the percentage is worth 12x more. Across everything surveyed, percentage and
volume have been anti-correlated; screening on the two conditions alone selects for protocols
with no traffic.

ENS is now the sharpest case of condition 2 failing on its own. It satisfies condition 1
comfortably — resolver writes go straight to the resolver with no regular calls at all — and
still scores zero on all 18 transactions, because a naming record *is* a storage write. There
is nothing wrapped around it to remove.

## Aave — `borrow` is a reliable candidate

20 transactions measured, all trace-based. **11 of 20 clear the floor.** What decides it is **which operation is called**, not who calls it:

| operation | measured | clear the floor | Schnorr range |
|---|---:|---:|---|
| **`borrow`** | 9 | **9** | **14.98% – 59.61%** (median 37.77%) |
| `withdraw` | 4 | 1 | 0% – 43.51% |
| `supply` / `supplyWithPermit` / `repay` | 6 | **0** | 0% |
| `liquidationCall` (via 3rd party) | 1 | 0 | 0% |

### Every borrow wins, and reserve count sets how much

| reserves held | gas used | GasKiller cost | Schnorr saved |
|---:|---:|---:|---:|
| 8 | 571,333 | 180,741 | **340,592** (59.61%) |
| 6 | 450,205 | 163,828 | **236,377** (52.50%) |
| 3 | 371,912 | 173,408 | **148,504** (39.93%) |
| 4 | 360,781 | 170,263 | **140,518** (38.95%) |
| 3 | 345,794 | 170,335 | **125,459** (36.28%) |
| 4 | 365,438 | 181,716 | **133,722** (36.59%) |
| 2 | 346,272 | 206,699 | **89,573** (25.87%) |
| 1 | 316,682 | 205,592 | **61,090** (19.29%) |
| 2 | 252,529 | 164,712 | **37,817** (14.98%) |

**GasKiller's cost barely moves: 163,828–206,699, while gas used runs 252,529–571,333.** The diff is effectively fixed and the computation on top varies — the same fixed-diff/variable-workload signature seen in Ether.fi's oracle report and World ID's identity registration.

Two borrows also clear the **BLS** floor (140,592 and 36,377) — only Railgun has managed that elsewhere in this survey.

### Why the operation decides it

`borrow` and `withdraw` must check the health factor, which walks every reserve the user holds and reads an oracle price per asset. Those reads are `STATICCALL`s — real gas that leaves nothing in the diff, and which the extractor ignores entirely (it tracks only `CALL`, `SSTORE`, `LOG*`, `CREATE`). `supply` and `repay` skip the check, because neither can worsen your own health factor.

Median gas by operation and reserve count, across 471 direct-to-Pool transactions, shows the loop clearly — and shows it is absent from `supply` and `repay`:

| operation | 0–1 reserves | 2–3 | 4+ |
|---|---:|---:|---:|
| `withdraw` | 176,867 | 278,596 | **360,926** |
| `borrow` | 303,803 | 284,079 | **387,564** |
| `supply` | 184,880 | 150,987 | 160,388 |
| `repay` | — | 152,022 | 154,444 |

Three `withdraw` calls with **identical diff shapes** (8 stores, 1 call, 3 logs) scored 43.51%, 0% and 0%. Their opcode profiles isolate the mechanism:

| | winner | zero | zero |
|---|---:|---:|---:|
| gas used | 408,792 | 167,589 | 183,126 |
| GasKiller cost | 180,921 | 160,020 | 166,710 |
| `STATICCALL` | **25** | 4 | 4 |
| `SLOAD` | 129 | 47 | 47 |
| total opcodes | 17,929 | 7,038 | 6,980 |
| user's active reserves | **5** | 1 | 0 |
| **Schnorr saved** | **43.51%** | 0 | 0 |

Six times the oracle reads, ~2.5× the opcodes, and the same 12 state updates at the end.

> **Revision.** An earlier version of this section, written from an 8-transaction sample that happened to contain only one `borrow`, claimed savings depend on the borrower's position rather than the operation, and that "single-asset users save nothing". Widening to 20 transactions reversed both: a 1-reserve `borrow` saves 26.55%, and 9 of 9 borrows clear the floor regardless of position size. Reserve count is a multiplier, not the gate.

### Practical significance

In the sampled 3,000-block window, direct-to-Pool `borrow` calls were **120 of 471** classified transactions (~25%). At a median 42.93%, that is a large recurring segment rather than an edge case — and Aave is the largest lending market on mainnet, so ~25% of its flow likely exceeds Railgun's entire volume in absolute gas.

This also corrects a conclusion drawn from Morpho. Morpho's 2.60% suggested lending was structurally poor for GasKiller; Aave shows that was about Morpho's design (storage-optimal, little per-transaction computation), not about lending as a category.

The one liquidation in range (1,165,207 gas) went through a third-party liquidator contract, so its diff is 6 updates dominated by one call — 0%. The Aave transaction with the most computation was reached through a wrapper.
## Safe — not worth pursuing, and the reason is a hard ceiling

12 transactions measured, plus 3 above ~5M gas that could not be measured at all (empty analyzer output on every attempt — a tool limit on very large struct-log traces).

**2 of 12 clear the floor**, both at 5 signatures:

| tx | sigs | gas used | GasKiller cost | surplus | Schnorr saved |
|---|---:|---:|---:|---:|---:|
| [`0xa9eca9f1…`](https://etherscan.io/tx/0xa9eca9f1a7075c8eb971e7ee2a1a3ee514cf3cf6b1077d6ddcc4f60f8ebf4eaa) | 5 | 104,612 | 67,158 | +37,454 | **0** (0.00%) |
| [`0x5c559278…`](https://etherscan.io/tx/0x5c5592787da61ec8c46326d93089c14e667276fab45703077168e72dcbbee99e) | 5 | 115,958 | 78,540 | +37,418 | **0** (0.00%) |
| [`0x8951b058…`](https://etherscan.io/tx/0x8951b058f41486ff7d9c5806d187af52f7d969ae69ddbb85c1e1be04171dae04) | — | 3,251,629 | 3,220,361 | +31,268 | **0** (0.00%) |
| [`0x5688590b…`](https://etherscan.io/tx/0x5688590bc26e704d720d7bb2185b195aabb310ba67dddd944f64509b1cf70513) | 3 | 322,338 | 297,128 | +25,210 | 0 |
| [`0x2666f99a…`](https://etherscan.io/tx/0x2666f99a3b1ad225cf8dcc40fbafb1959a6efb5bb3c561b3d2d5a3b242ca4a29) | 3 | 96,660 | 73,351 | +23,309 | 0 |
| [`0xb286eeb1…`](https://etherscan.io/tx/0xb286eeb15c4cb3445a73e275e89336f7563eb46c2e9ec97a82aeefb5a4485430) | 4 | 463,470 | 442,944 | +20,526 | 0 |
| [`0x909681b5…`](https://etherscan.io/tx/0x909681b5131c5ccc56e6f6791f152efe41cf270172c5a4645fc0067567bd8651) | 4 | 103,575 | 85,519 | +18,056 | 0 |
| [`0xf20b6df4…`](https://etherscan.io/tx/0xf20b6df4702b6537ba520316a35552b6d1da7b696e3c69e34986ed901402bd56) | 2 | 11,414,223 | 11,400,916 | +13,307 | 0 |
| [`0xf6ebba6b…`](https://etherscan.io/tx/0xf6ebba6ba0e5e5f003598b5e05efbb737fb5e00e6a1818e58d1e565316f96b74) | — | 214,221 | 202,578 | +11,643 | 0 |
| [`0x4e13a401…`](https://etherscan.io/tx/0x4e13a40100c52346b4e971697a347030ffd0cc5bd47d521e8b4a9baf1a984872) | 3 | 458,625 | 452,215 | +6,410 | 0 |
| [`0xb2b17e51…`](https://etherscan.io/tx/0xb2b17e51681c60f3d66aa112fa13f070c5ea76c466e794e3ba360c8b833b5a55) | 1 | 75,536 | 70,129 | +5,407 | 0 |
| [`0xdcc894ec…`](https://etherscan.io/tx/0xdcc894ec22dc799bd1cd8c24caa4bcd2a2d7f35ae2ba8ab7c431a07f76e5ba21) | — | 1,004,511 | 1,005,210 | -699 | 0 |

### Safe's own compressible work is capped by owner count

A Safe changes **one slot** — its nonce. Everything else it does is verify signatures (~3,000 gas per owner via `ecrecover`) and emit `ExecutionSuccess`. That caps its surplus regardless of what the transaction does:

| signatures | observed surplus |
|---:|---:|
| 5 | ~37,400 |
| 4 | 18,056 – 20,526 |
| 3 | 6,410 – 25,210 |
| 2 | 13,307 |
| 1 | 5,407 |

**At the 50,000 floor Safe scores zero on all 12 transactions** — its best surplus is 37,454 gas. The analysis below was written against the old 27,000 floor, where 5 signatures was roughly break-even; it is kept because the signature-count relationship is still the right lens, but the break-even no longer exists at any observed signature count. Signature counts across 565 sampled transactions (read from the `signatures` field length in the `execTransaction` calldata):

| signatures | txs | share |
|---:|---:|---:|
| 1 | 282 | 50% |
| 2 | 212 | 38% |
| 3 | 43 | 8% |
| 4 | 4 | 0.7% |
| 5 | 2 | 0.4% |

So Safe's addressable share is roughly **0.4% of its transactions at ~9–10% savings**. Compare Railgun: 53% of transactions at 65–81%.

### The two failures are separable, and only one is the call problem

The clearest single data point in this survey: `0xf20b6df4…` burned **11,414,223 gas** and its surplus is **13,307**. Its diff is *three* state updates. Everything is inside one call, so GasKiller captures 0.1%.

But solving that would not help Safe, because the gas inside the call is never Safe's:

- **Gas inside the call** belongs to whatever the Safe called — third-party contracts in every case checked (one sampled transaction touched 13 contracts including Morpho Blue and Uniswap V4). Those protocols get that saving whether a Safe sits in front of them or not.
- **Safe's own work** is signature verification, capped at ~37,000 by owner count.

Safe is therefore not a blocked candidate but a thin wrapper in front of other candidates. There is no integration to do with the Safe team that produces savings. The longlist calls it a "near-ideal match for aggregate-signature verification"; the measurements do not support that.

## Euler — the architectural counter-example to Aave

5 transactions measured (3 unmeasurable). Best result **1.31%**; the rest zero.

| tx | gas used | GasKiller cost | surplus | Schnorr saved | state updates |
|---|---:|---:|---:|---:|---:|
| [`0x0a06e978…`](https://etherscan.io/tx/0x0a06e9783d4bc563d8b4674112b2dd427597c80a1095c377e6b88e307b31927c) | 548,011 | 513,820 | +34,191 | **0** (0.00%) | 29 |
| [`0x7d1e2345…`](https://etherscan.io/tx/0x7d1e2345c39b884a16eb6b2e06c1c4a4177c5639fe1c91474a356c3eef04fd87) | 2,701,108 | 2,683,478 | +17,630 | 0 | 7 |
| [`0xa32effd3…`](https://etherscan.io/tx/0xa32effd3b31a02343d8cf4362c4fee2e806ea9dcf00fdea5eb1a2b054ae0ea4a) | 499,524 | 482,833 | +16,691 | 0 | 29 |
| [`0x10c755ee…`](https://etherscan.io/tx/0x10c755eea1865f9761e49f2e52dd700d8ecc4e0037057bb2ea05df24bb946095) | 203,620 | 244,538 | −40,918 | 0 | 14 |
| [`0xc3543837…`](https://etherscan.io/tx/0xc3543837e22a84fb06798cb626d7a1cc716329fdf15fb675eafc587911090206) | 1,415,274 | 1,871,874 | **−456,600** | 0 | 158 |

### This is an architectural problem, not a computation problem

Euler does the **same expensive work as Aave** — per-asset risk calculations on every borrow and repay, the exact mechanism that earns Aave's `borrow` 24–64%. The difference is entirely in how users reach it.

Euler V2 mandates the **Ethereum Vault Connector** as its coordination layer. All 20 vaults found in the scan report the same `EVC()` address (`0x0c9a3dd6b8f28529d72d7f9ce918d493519ee383`, discovered on-chain, not from documentation). Users reach vaults through `batch((address,address,uint256,bytes)[])` on the EVC (selector `0xc16ae7a4`, keccak-verified) or through a third-party contract:

| entry point | txs | share |
|---|---:|---:|
| EVC `batch(...)` | 58 | 57% |
| third-party contracts | 44 | 43% |
| **directly to a vault** | **0** | **0%** |

**Zero of 191 borrow/repay transactions called a vault directly.** So the risk calculation sits behind a `CALL` in every single Euler transaction, and the analyzer re-executes it rather than stripping it out.

The two protocols side by side:

| | Aave | Euler |
|---|---|---|
| per-asset risk math on borrow | yes | yes |
| direct calls to the lending contract | **52% of txs** | **0 of 191** |
| borrows clearing the Schnorr floor | 9 of 9 | 1 of 5 |
| best measured | **59.61%** | **0%** |

Same category, same computation, ~49× difference in outcome — decided by whether the protocol lets users call the contract that does the work. Euler belongs in `CALL_BLOCKED_CANDIDATES.md` rather than being written off: the compressible work exists, it is simply unreachable through the current encoder.

Two further observations:

- **Routing through a batcher compounds both problems.** `0xc3543837…` is a large EVC batch producing **158 state updates**, so GasKiller costs 1,871,874 to replay a 1,415,274-gas transaction — a surplus of −456,600, the worst measured anywhere in this survey.
- **Size does not help.** `0x7d1e2345…` burns 2,701,108 gas and yields a 7-update diff with +17,630 surplus. Everything is inside calls.

Three transactions could not be measured: one rate-limited, two reverting reproducibly at a WETH call (`0xC02aaA39…`) during replay on all 3 attempts each.
## Ondo — weak, and the volume is thin

8 transactions measured, all trace-based. Genuine Ondo mint/redeem operations land at **1.08–2.01%**.

| tx | what it is | gas used | GasKiller cost | Schnorr saved |
|---|---|---:|---:|---:|
| [`0x10fdab16…`](https://etherscan.io/tx/0x10fdab165e2a37d70223b9546f80e9f7a248e1a0ccacd6638bbc66d565de8c35) | mint/redeem via manager | 350,502 | 316,467 | **0** (0.00%) |
| [`0x089be390…`](https://etherscan.io/tx/0x089be390aab1f47562520e714e3d96b270c279b0c2a7b2876c933ee390a264b0) | mint/redeem via manager | 447,366 | 413,235 | **0** (0.00%) |
| [`0x23ac6eda…`](https://etherscan.io/tx/0x23ac6eda7ddb46309b5d61628b5f24ced1b1c1cb608470d451f6dfb869fc6242) | mint/redeem via manager | 432,419 | 400,729 | **0** (0.00%) |
| [`0xd8ea9b21…`](https://etherscan.io/tx/0xd8ea9b2158d7bf3407ea618ad07e3f7debc096076e108f6c166ca9fa53e9ec37) | via CowSwap settlement | 519,037 | 542,092 | 0 |
| [`0xfccb2eda…`](https://etherscan.io/tx/0xfccb2eda50342893f6f1e93b0fb08df57dff595d17ac74414a688d1bfe3aaa78) | third-party | 819,503 | 843,764 | 0 |
| [`0xe16fb5bc…`](https://etherscan.io/tx/0xe16fb5bcb8d2d4d2a2a9d3c7b92d7388e8e8af784f771d3bd0f3250daeb54e42) | third-party, 153 logs | 3,611,533 | 3,660,592 | 0 |

### Two results excluded as false attributions

Two transactions in the sample scored higher but **are not Ondo operations** and are excluded from the protocol's figure:

| tx | apparent | why excluded |
|---|---:|---|
| [`0x4551339c…`](https://etherscan.io/tx/0x4551339cc87aabe9c57e492856f0af4c5cc00666be7bbfbd00ee8117d6b2327c) | 13.37% | MEV/arb bot entering through a 133-byte contract; only **4 of 31 logs** are Ondo tokens, across 10 contracts |
| [`0x197c9a14…`](https://etherscan.io/tx/0x197c9a14ed634444154e66fb75bfa167b874dfbba78b463c62f5b390063c8965) | 1.64% | aggregator; only **5 of 190 logs** are Ondo tokens, across 25 contracts |

Their savings come from the bot's own routing work, not from anything Ondo does. Counting them would inflate Ondo to 13.37% on the strength of a transaction that merely touches USDY in passing. Worth noting as a general hazard when a protocol is discovered by token-log scanning: large third-party transactions incidentally touch the token and can dominate a small sample.

### Why it is weak

**Compliance checks are storage reads, not computation.** A tokenised-treasury mint is an allowlist lookup plus a mint — a handful of `SLOAD`s and 2–3 writes. The longlist anticipated "compliance logic" as heavy compute; it is not. This is the same reason the longlist itself correctly flags EAS as a weak fit: the write *is* the payload, with little surrounding computation to strip.

**Volume is thin.** 302 USDY transactions in a 60,000-block window (~8 days), of which 52 involve a mint or burn; OUSG had **8 transactions in total**. Even at a good percentage the absolute gas is orders of magnitude below Aave or Railgun.

On this evidence the RWA category looks unpromising as a whole — Midas, Centrifuge, Maple and Backed share the mint/redeem-plus-allowlist shape that produced 1–2% here.
## EigenLayer — the beacon-chain proofs are the only thing worth anything

13 transactions measured, 2 more too large for the tool to handle at all. **6 clear the floor**, the best at **5.15%**. Everything that isn't a beacon-chain proof loses money.

| tx | function | gas used | GasKiller cost | surplus | Schnorr saved | updates |
|---|---|---:|---:|---:|---:|---:|
| [`0x4ce09132…`](https://etherscan.io/tx/0x4ce0913231fcb4ac1351f81c6632f53165a5a80dc1f44fc7ea9c31021e5c7b04) | *checkpoint-proof verification* | 229,856 | 191,015 | +38,841 | **0** (0.00%) | 11 |
| [`0x03d50d7f…`](https://etherscan.io/tx/0x03d50d7f761256ff7ddcab530c0535f352ad8101d5d2912d67339e65e3c61b5d) | `forwardEigenPodCall` ✓ | 134,366 | 103,398 | +30,968 | **0** (0.00%) | 1 |
| [`0xbbc8abcb…`](https://etherscan.io/tx/0xbbc8abcb0eeb0f311b36ab4274e8629bd2b8c1395ffe79ffdebbcbf4536fbe29) | `forwardEigenPodCall` ✓ | 417,028 | 386,243 | +30,785 | **0** (0.00%) | 1 |
| [`0xc770332c…`](https://etherscan.io/tx/0xc770332c7e516902481cc309756988fbe452f58f89a1144713150fe083c1105e) | `forwardEigenPodCall` ✓ | 417,090 | 386,305 | +30,785 | **0** (0.00%) | 1 |
| [`0x95fa2d07…`](https://etherscan.io/tx/0x95fa2d07b579aaac9fa7e0fbd3545bcdb408c197956e0b4e34b9b29fa0f1cd9c) | *rewards claim* | 108,528 | 81,086 | +27,442 | **0** (0.00%) | 5 |
| [`0x6fa0fbbf…`](https://etherscan.io/tx/0x6fa0fbbf87072c3315c4801db2ac55a1e6c58b009d9ff07234e9c84b7a84801e) | *rewards claim* | 125,638 | 98,174 | +27,464 | **0** (0.00%) | 5 |
| [`0x065a18a2…`](https://etherscan.io/tx/0x065a18a2af1e2d80514ad79067794b7c34e92ba2c2754c5cb7ddb5157eb111b8) | `queueWithdrawals` ✓ | 439,868 | 469,142 | -29,274 | 0 | 24 |
| [`0x22b2c58c…`](https://etherscan.io/tx/0x22b2c58ced9f209d9ec2d21415436e9395067b377764d600927c8b54625f6d4f) | `startCheckpoint` ✓ | 76,444 | 52,517 | +23,927 | 0 | 4 |
| [`0x5ce19358…`](https://etherscan.io/tx/0x5ce19358229301efda44bc79908632dfc69c1609477d52438c3cd9add6950792) | `completeQueuedWithdrawal` ✓ | 190,728 | 190,504 | +224 | 0 | 17 |
| [`0xaa858fcd…`](https://etherscan.io/tx/0xaa858fcd781a6a5afa142ccd9a802d0df1e2f68292f0abf8546426cda3fe6644) | *rewards claim* | 156,150 | 135,165 | +20,985 | 0 | 8 |
| [`0xe5de910b…`](https://etherscan.io/tx/0xe5de910bc96de735b7bc040855d99c5b565baa1de8e14c373af2febb5076d19b) | `completeQueuedWithdrawals` ✓ | 183,232 | 185,594 | -2,362 | 0 | 17 |
| [`0xf09b9b69…`](https://etherscan.io/tx/0xf09b9b69b3640f7b018509045180218c1c7acff17eb665fbc40bb9ad2003ed0b) | `queueWithdrawals` ✓ | 440,373 | 471,942 | -31,569 | 0 | 24 |
| [`0xfb18ffe1…`](https://etherscan.io/tx/0xfb18ffe1164630f6d3a2c818f28404fcdc1782103870eadeaea75aaa0de4f0b9) | `completeQueuedWithdrawals` ✓ | 186,142 | 188,312 | -2,170 | 0 | 17 |

### The proof work is real but it sits on a fixed ceiling

The five EigenPod checkpoint transactions have surpluses of **23,927 / 30,785 / 30,785 / 30,968 / 38,841** regardless of how much gas they burn (76,444 up to 417,090). That is a fixed cost — verifying beacon-chain Merkle proofs and BLS-adjacent balance checks. Against the old 27,000 floor four of five cleared it by 4,000–12,000 gas. **Against the 50,000 floor none of them clear it, and EigenLayer scores zero across all 13 transactions.** The fixed-cost observation is what matters: the surplus does not scale with gas burned, so a higher floor removes the protocol entirely rather than reducing it.

Withdrawals go the other way. `queueWithdrawals` produces 24 state updates for a 440,000-gas transaction, so GasKiller costs **31,569 more** than the transaction did. Share accounting again: many writes, little compute.

### Two more things

- **The two biggest checkpoint proofs could not be measured** — ~3.4M gas and 85 KB of calldata, and the tool produces no output on traces that size. EigenLayer's real ceiling is therefore unknown, and probably above 5.15%.
- **129 of 136 pod transactions in the scan window came through Ether.fi's `EtherFiNodesManager` (`0x8b71140a…`) via `forwardEigenPodCall`**, not from pod owners directly. So most EigenPod traffic already has a wrapper in front of it — the same routing problem that sinks Euler, arriving from a different direction.
## ERC-4337 EntryPoint — a likely false-positive in the analyzer

**This section replaces an earlier conclusion that was wrong.** An initial run of eight
`handleOps` transactions reported 0% across the board and was written up as a structural
blocker. Most of those runs were heuristic fallbacks caused by RPC rate limiting. On clean
re-measurement the picture inverted, and what it exposes is a probable defect in the
estimator rather than a verdict on the protocol.

**Scope caveat.** These are transactions to the shared ERC-4337 EntryPoint
(`0x0000000071727De22E5E9d8BAf0edAc6f37da032` v0.7,
`0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789` v0.6). The wallet vendor behind each userOp
was never identified. (ZeroDev has since been measured separately — see the ZeroDev section.
Nine clean single-userOp Kernel transactions, all 0.00%.)

### The measurements

Cleanly measured, zero rate-limit errors:

| tx | gas used | base estimate | Schnorr | updates |
|---|---:|---:|---:|---:|
| `0x030b4fd3776594fc57df6451e83b61e916554227a0c7208f2f6a039f9a2bc312` | 1,694,622 | **201,100** | **85.18%** | 8 (3C) |
| `0xb752f16bd51240342af289dfffebd5276e28ec313eb12ba8bf4ad654794bd807` | 1,103,781 | **186,440** | **78.58%** | 8 (3C) |
| `0x112f2b10d8e6fc37032a3103957c8324db6cee480bf030da56bbbcc5bec5816e` | 2,137,036 | 2,205,725 | 0% | 8 (3C) |
| `0x989497784755fae4ffaefe945aa8309269455dc966784e3d0a8a8224cf5c27a4` | 1,141,959 | 1,208,050 | 0% | 8 (3C) |
| `0xe64e4eb1fc3306f4eb081b65fc8b3bdf3e2e21c7478980fa9c13aa70540e8e2b` | 177,986 | 228,198 | 0% | 9 (4C) |
| `0xf177394e40b6e52101c309fa9be07aa66711250e6e981c996c2080324a1a9c89` | 177,986 | 228,174 | 0% | 9 (4C) |
| `0x92f6ec5bede29c44849b7bd1f12f86ff4965022525ada840029eaa676c4ceedb` | 165,688 | 207,785 | 0% | 9 (4C) |
| `0x773e691ea71b9e0b99e8599fa29e9ea9097c73de92e66d25bad564f17a264dad` | 145,170 | 183,888 | 0% | 9 (4C) |

`0xb752f16b…` was measured twice in independent runs and returned a base of **186,440 both
times** — the result is deterministic, not flaky.

### Why the two 80%+ results should not be trusted

`0x030b4fd3…` (86.54%) and `0x112f2b10…` (0%) are **structurally identical**: eight state
updates each, same ordering, same three calls, same selectors — `0x19822f7c`
(`validateUserOp`) into the smart account and `0x0042dc53` (`innerHandleOp`) back into
EntryPoint. Same shape, same protocol, same code path.

Yet one replays for 201,100 gas and the other for 2,205,725. A **10x divergence between
transactions with no structural difference** is not a property of the workload. It means
the replay is not doing the same work in both cases.

The most likely explanation is EntryPoint's own error handling. EntryPoint is *designed*
to catch a failing userOp rather than revert — it emits `UserOperationRevertReason` and
continues. During replay the state updates are applied before `innerHandleOp` runs, so the
userOp's inner execution can fail on already-consumed nonces or already-moved balances.
EntryPoint swallows that failure and returns successfully and cheaply. The estimator sees a
successful call and a small gas number, and records a large apparent saving.

If that is right, the implication is general and matters well beyond 4337: **any contract
that try/catches internally can produce a false saving under this estimator**, because a
silently-caught failure during replay is indistinguishable from cheap success. Nothing in
the current output flags it — no revert is reported, and the run is labelled
`measured via StateChangeHandler`.

This is unresolved. It needs someone with the estimator internals to confirm or refute,
and it should be treated as a **known-suspect result**, not as an 86% win to take to a
customer.

### What still holds

EntryPoint is immutable, shared, unowned infrastructure. Even if the savings were real,
there is no counterparty who can integrate it — not ZeroDev, not any wallet vendor, not a
customer. Volume is genuine (23,336 userOps in 10,000 blocks on v0.7) but unreachable
commercially.

## Ethena — one win in 309, and a lesson about the tool

**22 transactions measured, 19 of them cleanly. One real win: 8.99%.**

`EthenaMinting.mint` (`0x96eea750`, selector unverified) reduces to four storage writes,
one `Log4`, and two calls — a token `transferFrom` and a USDe `mint`. Both calls are plain
ERC-20 operations, so nothing large is hiding inside them. The measured surplus really is
Ethena's own compute: the EIP-712 check over the signed order, plus order bookkeeping.

Across 11 cleanly measured mints that surplus sits in a tight band of **10,565–18,063**,
against the Schnorr floor. **At 50,000 Ethena's single win disappears** — its best surplus is 48,699 gas, 1,301 short. Ethena is not blocked by external calls and not blocked by
write-heaviness. It simply does not do enough work.

| tx | gas used | base estimate | surplus | Schnorr |
|---|---:|---:|---:|---:|
| `0x5055ea7ff088407138215ddbe45b9cedfc334cda7e791d0eba4061aea819015c` | 241,268 | 192,569 | **+48,699** | **0.00%** |
| `0xb3a29f2bdcb1573d2f3b7d613a08415854df6ea60d356c9611248856474a8a21` | 219,295 | 204,750 | +14,545 | 0% |
| `0xae6a3e25f711d88ab06a1729ec60acf771c33e83877b2ac7885661cfe0d4d253` | 210,560 | 192,497 | +18,063 | 0% |
| `0xd2475759c71f278896ea7ff15ca213bb17dc9c3e0b29ddfdc8e1e01424995ae0` | 208,058 | 190,820 | +17,238 | 0% |
| `0x91e950a3e5497de1908db495bd8432a9068865314a8bba6e2ee3f800eb9c0e41` | 208,046 | 190,808 | +17,238 | 0% |
| `0x2bdf664447b22de7c275becd81ff56775417e0544812417ee0dadc95232a6fd4` | 207,927 | 192,581 | +15,346 | 0% |
| `0xe6f15a94892f1ec9a52263ba0a8869c081db57bc9c48558b31e9cc1e3609e126` | 205,401 | 190,844 | +14,557 | 0% |
| `0xba225f3ef9ad52f911771e967f5e81e83fc0cdebe5eb1cd996012e4aa543ef21` | 202,207 | 187,626 | +14,581 | 0% |
| `0xe67e1c8420c330116b81cb6e9bd73d5016058267d390701dd8fab89e592877d0` | 202,195 | 187,602 | +14,593 | 0% |
| `0x1c4c1779b4b03b196c1e2891be88fb9771f33931fc356597ae5be7f54433b264` | 200,589 | 186,044 | +14,545 | 0% |
| `0xaf1a2df790dc89d457abe7cfb14a5be4e6d32d92a547e2f991479dcbdd7321f3` | 200,023 | 189,422 | +10,601 | 0% |
| `0x0e4976bf08241feb978fc57172e36ea04a066b0bd242c3952ce06fabfd03ade8` | 200,023 | 189,422 | +10,601 | 0% |
| `0x2b762d27b09d8f0b8a221a71bc3e3544e55b7c34d9a44edfd566fa5ebc739ed7` | 200,011 | 189,446 | +10,565 | 0% |
| `0xcfea9cfa79f814a7ff93a431c56dde3b9feeb10a86e8dde41c00ce3adf6d7ec2` | 185,047 | 170,454 | +14,593 | 0% |

Staking is lighter still and several rows are net-negative: `cooldownShares` (`0x9343d9e1`,
keccak-verified) at 89,471 gas measures a base of 103,472, and `deposit(uint256,address)`
(`0x6e553f65`, keccak-verified) at 88,423 gas measures 99,316. GasKiller would cost more
than the transaction does.

### The one win is a statistical freak, not a segment

`0x5055ea7f…` is real — measured via `StateChangeHandler`, and reproduced with identical
numbers on a second independent run. Its surplus is 48,699, more than triple the
next-highest. The difference is order size: **900 bytes of calldata against the usual 836**,
one extra collateral asset. The state-update shape is unchanged (8 updates, 2 calls), so
the extra ~33,000 gas is pure verification work that writes nothing — precisely what the
co-processor strips.

That sounds like a targetable segment until you count them. Over 30,000 blocks
(25,854,266–25,884,265), **309 mints: 308 at 836 bytes, exactly one at 900 bytes.**

**0.3%.** One freak order in a month. Ethena is a no.

### What this cost to find out — a warning about `heur` rows

Nine of the first twenty-one runs fell back to the heuristic estimator, and every one of
them reported a large, plausible-looking saving. All were false:

| tx | heuristic said | true measured value |
|---|---:|---:|
| `0xae6a3e25…` | 36.96% | **0%** |
| `0xaf1a2df7…` | 34.99% | **0%** |
| `0xd2475759…` | 33.91% | **0%** |
| `0x91e950a3…` | 33.90% | **0%** |
| `0xb3a29f2b…` | 30.95% | **0%** |
| `0x6f12cb87…` | 3.94% | **0%** |

The cause was not a defect in the transactions. It was **RPC rate limiting** — the provider
returned `HTTP 429, 50/second request limit reached` while replaying preceding
transactions, the replay aborted, and the tool silently substituted the heuristic. The
heuristic prices `Call` at zero gas, so it always errs toward *overstating* savings; on
`0xaf1a2df7…` it was wrong by 86,378 gas.

Two consequences worth acting on:

1. **Never report a `heur` row as a result.** Re-run it serially first. Every one of the six
   above collapsed to 0% on retry.
2. **The 16 `heur` rows carried in `ALL_TRANSACTION_ANALYSES.md` from earlier protocols are
   suspect for the same reason** and may be recoverable as real measurements. They were
   produced under the same throttling conditions, some of them while two analyzer batches
   ran concurrently.

## Panther — the target is not on this chain

Panther's MASP runs on Polygon. On Ethereum mainnet only the ZKP token is live, and its
traffic is overwhelmingly bridge deposits (`0xe3dec8fb` to the Polygon PoS bridge) and
router swaps — that is, the token *leaving* for the chain where the protocol actually runs.

Across 200,000 blocks (~27 days): the staking contract
`0xf4d06d72dACdD8393FA4eA72FdcC10049711F899` saw **one** transaction and RewardMaster
`0x347a58878D04951588741d4d16d54B742c7f60fC` saw **none**.

That single transaction (`0x63338b98cb3c6bf3390a7f7dcb84e25766424b7a1c6444b4b1b3c89f9059d134`,
selector `0x7f678334`) measured **0%** — 207,193 gas used against a 226,374 base estimate,
from eight storage writes, one `Log3`, and two calls. Staking bookkeeping, no computation.

Not a technology-fit failure. There is simply nothing on mainnet to target.

## Lido — the biggest transactions in the survey, and almost all bookkeeping

**13 transactions, all measured cleanly (zero heuristic fallbacks). Best result: 1.13%.**

Lido was the last plausible source of heavy per-transaction math on the longlist, and it
has by far the largest transactions and the highest volume measured anywhere here. It is
still a no, and the reason is clean enough to be useful as a rule.

### The 5.9M gas transaction is a write, not a computation

`addSigningKeysOperatorBH(uint256,uint256,bytes,bytes)` (`0x805911ae`, keccak-verified) on
NodeOperatorsRegistry `0x55032650b14df07b85bF18A3a3eC8E0Af2e028d5` is the single largest
transaction in the survey — **5,887,344 gas**, run 20 times in 20,000 blocks.

It produces **306 state updates**. Node operators are submitting validator signing keys in
bulk, and storing those keys *is* the transaction. The replay costs 6,739,086 against
5,887,344 actually used, so GasKiller would cost more than the status quo.

This is the "too many writes" blocker at maximum scale, and it is worth stating plainly
because transaction size is such a tempting proxy for opportunity: **5.9M gas of writing
things down is worth nothing, while 200k gas of thinking is worth 60%.** Screen on the
ratio of computation to state, never on gas used.

### The oracle report is the only thing that pays, and it pays 1.13%

| tx | function | gas used | base estimate | surplus | Schnorr |
|---|---|---:|---:|---:|---:|
| `0xf9a0c48463e92a01347aadfefbf9349ec72858550a8fa162e894f61e9e99a499` | *oracle report* `0x11a78d23` | 1,729,395 | 1,682,837 | +46,558 | **0.00%** |
| `0x1bad343834044681f393485bcf131863801ff082da4fe24a2095629a7332d517` | *oracle report* `0x11a78d23` | 1,721,688 | 1,675,339 | +46,349 | **0.00%** |

Consistent across both daily reports, and genuinely measured. For contrast, Ether.fi's
equivalent oracle report returned 18.99% on a far smaller transaction — the difference is
that Lido's report is dominated by writing per-operator results, not by deriving them.

### Everything user-facing is zero

Every withdrawal-queue entry point measures 0%, and every one has a base estimate *above*
the gas actually used. All selectors keccak-verified.

| tx | function | gas used | base estimate | Schnorr |
|---|---|---:|---:|---:|
| `0x6e2453d1b4b55a31ffb9fd94b38a6475c6fc68727e83edbc30078829274b4446` | `claimWithdrawals` ✓ `0xacf41e4d` | 261,492 | 275,614 | 0% |
| `0xdfbaead0d3c07378a6265a5093d029987518e7c75ede86ceb7b41d7f6fead305` | `claimWithdrawals` ✓ `0xacf41e4d` | 261,468 | 275,626 | 0% |
| `0x07dfd9551205d17c73cd997e2ccf76708f60eae947999636a7e96b5f45f908f2` | *wstETH withdrawal* `0x7951b76f` | 258,886 | 276,945 | 0% |
| `0x8af05a00ef89fdbc3c3cd246e5274c935f7a45869cba96ebbfd1aaea451db50f` | `requestWithdrawals` ✓ `0xd6681042` | 215,719 | 225,836 | 0% |
| `0x954e6c05327ab8ac475eb27d646450b600826ed279ca5c99ca3ab90e1f953177` | `requestWithdrawals` ✓ `0xd6681042` | 215,683 | 225,752 | 0% |
| `0x9f51864813f2f5744a5114d7345653ef2c1b8d87b9e479317020a14153e9b490` | `claimWithdrawals` ✓ `0xe3afe0a3` | 131,269 | 171,727 | 0% |
| `0x076a9688c14bf3e1af823eb525fe3243176492d5c246567cbe6b5680bdef7844` | `claimWithdrawals` ✓ `0xe3afe0a3` | 81,977 | 80,590 | 0% |
| `0x341d60b7870a57c2fa6d31a6935bfa143f0cff41685fa038661fd8721e7b4a92` | *registry* `0x8f73c5ae` | 978,934 | 1,038,649 | 0% |
| `0x0df2c7332dd34a84ee404631b5431648ecce7e791ddb93f37c3fd9a3ce7206c9` | *registry* `0x8f73c5ae` | 978,934 | 1,038,632 | 0% |
| `0x69d40f3d0e599963cd619a61cbf60a1c3e847e9f2f87796a139561b53cec4424` | `addSigningKeysOperatorBH` ✓ | 5,887,344 | 6,739,086 | 0% |
| `0x21fa690fbbbbefec96c3fb533b2e0b6a275e9f0bad3fa7f6c71ccec9de398461` | `addSigningKeysOperatorBH` ✓ | 5,887,248 | 6,739,014 | 0% |

Volume is not the problem — `claimWithdrawal` alone runs 317 times per 10,000 blocks. The
work simply is not computational.

### A fifth confirmation of the heuristic trap

The two `0x8f73c5ae` transactions used **identical gas — 978,934 each**. One measured
cleanly at 0%. The other fell back to the heuristic and reported **25.84%**. Retried
serially it measured 0%, matching its twin.

That is the fifth instance in this survey of the same signature: when two runs of the same
function disagree sharply, the heuristic one is wrong, and it is wrong in the direction of
overstating savings.

## Pyth — 28% to 64%, and the driver is writes, not gas

**13 transactions measured cleanly. Every one still saves at the 50,000 floor. Range 16.20%–52.06% Schnorr.**

`updatePriceFeedsIfNecessary(bytes[],bytes32[],uint64[])` (`0xb9256d28`, keccak-verified)
and `executeGovernanceInstruction(bytes)` (`0xb6ed701e`, keccak-verified) on
`0x4305FB66699C3B2702D4d05CF36551390A4c69C6`.

| tx | gas used | calldata | updates | base | Schnorr |
|---|---:|---:|---:|---:|---:|
| `0x8874d5a5dd22f4be257985b269f6c6ded6f28e08f0a572280d49d2db9a3a347a` | 279,375 | 2884B | 12 | 113,369 | **41.52%** |
| `0xbf4835576f7677f4d93a6f96fe75671c0dd19362652bb1cf5c8622cec1d54fb9` | 278,401 | 2884B | 12 | 113,441 | **41.29%** |
| `0x616ba1cd828ee4f0e63a5be3e09df5d8ef28e0661e8c396f45658cdca477fea9` | 193,725 | 1636B | **3** | 42,864 | **52.06%** |
| `0xf8800e04ea63017f9a4ffe500a4399c72a5606f243230a351c5758828568757b` | 192,005 | 1636B | **3** | 42,864 | **51.63%** |
| `0xa8ae70119c42ea2fb646f18a81b58f4263ae9cce624e0d44301abee3960ba7d4` | 194,705 | 1028B | 3 | 55,548 | **45.79%** *(governance)* |
| `0xab2984424844b5a4120660896eddea19589458b583b7a7279b8d951ddb2e90db` | 195,034 | 2148B | 12 | 113,393 | 28.02% |
| `0x329131473471b39de257f0392204b6ddc7ac7560c94e8d2407d4d33590f420f9` | 194,986 | 2148B | 12 | 113,357 | 28.02% |
| `0xfd6656e58db697736c638a01a1abe0d3065a1b72627a1c9368b108e052cb03e3` | 195,031 | 2148B | 12 | 113,405 | 28.01% |
| `0xacc36012498cc4c26e3e79d5f6ee1d0bc579e2ccf03828f34c1b60f77c5e239c` | 194,992 | 2148B | 12 | 113,369 | 28.01% |
| `0xe2795d246d11e909653880ca648a00e2b658b4c252dcf9bfd237cd41bab1112f` | 195,007 | 2148B | 12 | 113,393 | 28.01% |
| `0x3862ae1b964adcdc8932bfd4583854ad2fb749ed85cce0ae8d0e85440f41a571` | 195,004 | 2148B | 12 | 113,393 | 28.01% |
| `0x90b34b5df172d1d050f207ab34da927e4f81f7e710ae1edc1aa945e0fbc887d9` | 194,995 | 2148B | 12 | 113,405 | 28.00% |
| `0x9f3e08104c3a853674bb012ae9331fccb6f00dacd90c0661bf5d3de97079c7ee` | 194,989 | 2148B | 12 | 113,405 | 27.99% |

BLS is 0% on every row — the surplus never approaches the 250,000 BLS floor. Schnorr only.

### A predictive model for Pyth

The base estimate tracks the **state-update count and nothing else**. Twelve updates cost
113,357–113,441 across ten transactions whose gas ranged from 194,986 to 279,375. Three
updates cost 42,864 twice, exactly.

Fitting the two clusters:

```
base ≈ 19,350 + 7,840 × (state updates)
savings = gas_used − base − 50,000
```

`updatePriceFeedsIfNecessary` verifies the whole signed batch regardless of outcome, but
only *writes* the feeds that are actually stale. Verification is pure computation that
writes nothing — fully strippable. Writes are not. So:

**The best case is a large batch verified and few feeds written.** The 1636B transactions
verify a decent batch and write one feed: 63.9%. The 2148B transactions verify slightly
more and write four: 28%.

This also means gas used is a *bad* predictor here. The 192,005-gas transaction saves more
(63.61%) than the 279,375-gas one (49.76%).

### Correction to the earlier figure

An earlier version of this section reported Pyth as a flat 28.01% across 8 transactions.
That sample was drawn from a single 20,000-block window and happened to contain only the
12-update shape. Widening to 120,000 blocks (16.7 days, 655 transactions) exposed gas
ranging 192,005–279,375 and calldata 1028–2884B, and a second entry point.

Two of the 13 rows above were also recovered from heuristic fallbacks: `0x8874d5a5dd…`
claimed 65.79% and measured 49.76% at the old floor (41.53% at 50,000); `0x616ba1cd82…` claimed 69.08% and measured 63.94% (52.06% at 50,000).
Two further transactions could not be measured after retries and are excluded rather than
reported.

### Reachability — the best in the survey

Over 16.7 days and 655 transactions touching the Pyth contract, **649 were direct calls
(99.1%)**. Only 6 arrived via another contract, one of them Multicall3. There is no
router, forwarder or bundler in the path — the problem that made Chainlink (0 of 242) and
Euler (0 of 191) unreachable.

Two entry points total: 645 price updates and 4 governance instructions. That is an
unusually small integration surface.

### Honest read on which figure to quote

The 8-transaction random sample from one window landed entirely on the 28% shape. The 49%
and 64% rows were found by deliberately hunting the gas extremes. So **28% is likely the
common case and 64% the tail**, though the true distribution of write-counts across all
645 transactions has not been measured — doing so would require tracing every one.

Quote 28% as typical, cite 63.9% as demonstrated best, and do not present the mean of the
13 rows above as an average: the sample is deliberately biased toward outliers.

## ENS — the write is the payload, and there is nothing around it

Picked as the highest-volume protocol left on the longlist. The longlist rates it a good
candidate ("high-volume registrations, renewals, and resolver writes at predictable,
repeated cost: a good candidate for rebate-style savings passed to users"). That rating is
wrong, and this is the cleanest negative result in the survey.

**18 transactions, 9 functions, 5 contracts, all trace-measured, all 0.00%.**

### Volume, for context

Enumerated by `eth_getLogs` across 7 ENS contracts over blocks 25,796,435–25,896,434
(13.94 days): **12,227 distinct ENS-touching transactions = 877/day.** That is the highest
transaction rate of anything surveyed. The dominant contract is the current
`ETHRegistrarController` at `0x59e16fcc…` — 6,203 txs over the window (445/day), and it
handles exactly two entry points:

| selector | function | share of 213 sampled | gas | calldata |
|---|---|---:|---|---|
| `0xef9c8805` | `register((string,address,uint256,bytes32,address,bytes[],uint8,bytes32))` | 108 | 140,288–524,112 (med 218,814) | 388–2564B |
| `0x18026ad1` | `renew(string,uint256,bytes32)` | 105 | 80,866–88,200 (med 83,013) | 164B fixed |

Both selectors keccak-verified locally. Note this is *not* the controller at
`0x253553366D…` that most ENS documentation still lists; that one took 2 of 220 sampled
transactions. The current one adds a `bytes32 referrer` argument to both entry points.

### Results

| contract | function | gas used | replay cost | surplus | Schnorr |
|---|---|---:|---:|---:|---:|
| Controller | `renew` | 88,200 | 72,142 | **+16,058** | 0% |
| Controller | `register` | 140,288 | 124,344 | +15,944 | 0% |
| Controller | `register` | 455,003 | 440,380 | +14,623 | 0% |
| Controller | `renew` | 83,013 | 69,415 | +13,598 | 0% |
| Controller | `register` | 524,112 | 511,783 | +12,329 | 0% |
| Controller | `renew` | 80,866 | 69,331 | +11,535 | 0% |
| Controller | `register` | 207,083 | 195,854 | +11,229 | 0% |
| PublicResolver | `setText` | 63,971 | 57,713 | +6,258 | 0% |
| PublicResolver | `setAddr` | 66,214 | 61,851 | +4,363 | 0% |
| PublicResolver | `multicall` | 95,617 | 92,644 | +2,973 | 0% |
| PublicResolver | `setText` | 110,303 | 108,030 | +2,273 | 0% |
| PublicResolver | `setContenthash` | 48,536 | 51,625 | −3,089 | 0% |
| PublicResolver | `multicall` | 86,903 | 92,644 | −5,741 | 0% |
| NameWrapper | `setSubnodeRecord` | 142,491 | 150,080 | −7,589 | 0% |
| PublicResolver | `multicall` | 171,817 | 181,469 | −9,652 | 0% |
| Registry | `setSubnodeRecord` | 76,480 | 86,787 | −10,307 | 0% |
| BaseRegistrar | `safeTransferFrom` | 128,799 | 146,761 | −17,962 | 0% |
| NameWrapper | `setRecord` | 53,596 | 74,883 | −21,287 | 0% |

**Best surplus: 16,058 gas against a 50,000-gas floor — 68% short. Mean surplus across all
18: 1,975 gas. Seven of the 18 are negative**, meaning replaying the recorded state changes
costs more than the original transaction did.

### Why it fails, and why more volume cannot fix it

An ENS transaction's gas is storage writes plus logs, and almost nothing else. GasKiller must
perform the identical writes and emit the identical logs, so none of that cost is removed. All
it strips is the surrounding compute — namehash, string handling, the USD price lookup, the
commitment check — and that is worth 11,000–16,000 gas, every time, regardless of the
transaction.

The decisive observation is that **surplus does not scale with transaction size**:

- 524,112-gas `register` → 12,329 gas surplus
- 88,200-gas `renew` → 16,058 gas surplus

A transaction six times smaller yields *more* surplus. The large registrations spend their gas
in sub-calls to the registry, the NFT and the resolver — 6 of their 8 recorded updates are
`Call`s — and every one of those is re-executed on replay (`crates/core/src/trace.rs:255`).
So the usual route to clearing the floor, "find a bigger transaction," is closed here: bigger
ENS transactions are bigger because they make more sub-calls, which adds to replay cost as
fast as it adds to gas used.

`PublicResolver.multicall` looked like the exception before measurement — it uses
`DELEGATECALL` internally, which the tracer follows transparently, and all its authorisation
checks are `view` (so `STATICCALL`, ignored). It therefore records **zero** external calls.
It still scores zero, and two of the three measured are negative. Batching more records into
one multicall makes the transaction more expensive to replay, not less.

This is precisely the objection the longlist itself raises about EAS — "a plain `attest()`
call is mostly a single storage write plus one keccak256 hash, and the write is the payload,
so there's little surrounding compute to strip out." ENS is the same shape. **Its longlist
rating should be revised down to match EAS's.**

### It is not the external calls — the relationship is inverted

The usual reason a transaction scores zero in this file is external calls. That is **not**
what happens with ENS — the relationship runs backwards:

| | zero external calls | has external calls |
|---|---:|---:|
| transactions | 8 | 10 |
| best surplus | **+6,258** gas | **+16,058** gas |
| mean surplus | **−1,615** gas | **+4,848** gas |

The eight transactions with no external calls at all have a *negative* mean surplus, and
their best case is four times short of the floor. Removing every external call from ENS
would not produce a single win.

The clean ones are resolver writes — `setAddr`, `setText`, `multicall` — which are a storage
write plus a log and nothing else. `register` and `renew` score higher *despite* having 2–6
calls each, because they are the only ENS functions doing real computation: namehash, string
validation, the commitment check, and the USD price lookup (a `STATICCALL`, so the tracer
ignores it and its gas lands in the surplus). Even so they top out at 16,058.

So ENS fails the second screening condition, not the first. That distinction matters for how
you would treat it: Euler scores zero because of a mandatory router, which is a fixable no.
ENS is an unfixable no — a naming record *is* a storage write, and there is nothing wrapped
around it to remove.

### Ceiling if the signature were free

26,319 transactions/month × 1,975 gas mean surplus, at the 0.107 gwei median effective gas
price these transactions actually paid, ETH at $2,396.31 (Chainlink aggregator, read
on-chain): **$13/month.** At 20 gwei, $2,491/month. With the real 50,000-gas floor it is $0
at any gas price.

For comparison, Pyth clears the floor on every transaction and is worth $12–25/month at the
same fee levels. ENS has 30× Pyth's transaction volume and is worth nothing — which is the
single best illustration in this survey that volume is necessary but not sufficient.

### One methodological finding worth carrying forward

8 of the 18 first-pass runs hit `HTTP 429` and fell back to the heuristic estimator. Retrying
serially recovered all 8, though `0x707689e3…` took four separate retry rounds. **All 8 collapsed to 0%**, and the largest
error was 125,611 gas — the heuristic reported 51.78% on a transaction whose replay is
actually *more expensive* than the original.

Crucially, four of those eight had **zero external calls**. The known failure mode — the
heuristic prices `Call` at zero — cannot explain them. The cause is a second one:
`crates/core/src/heuristic.rs:40` charges `WARM_SSTORE_COST` 5,000 per storage write, while a
write to a previously empty slot really costs about 20,000. ENS resolver records are mostly
fresh slots, so the heuristic underpriced replay by roughly 15,000 gas per write.

So "this row has no external calls" is **not** a reason to trust a `heur` figure. Only
re-measurement is.

## Chronicle — heavy verification, two-update payload, every direct poke wins

Chronicle runs Sky/Maker's oracle network. Selected as the last unchecked protocol on the
longlist whose on-chain work is cryptographic verification rather than bookkeeping. The
prediction held: it is the strongest new candidate in this survey.

**24 transactions, all trace-measured, no heuristic fallbacks. 21 of 24 save.**

### How the contracts were found

No address list was needed. Chronicle's Scribe emits `Poked(address,uint128,uint32)` and the
legacy Maker medians emit `LogMedianPrice(uint256,uint256)`; filtering `eth_getLogs` on those
two topics with no address filter enumerates every live feed contract on mainnet. Over blocks
25,846,619–25,896,618 (6.97 days):

| event | txs | rate | direct-to-contract |
|---|---:|---:|---:|
| `Poked` (Scribe) | 718 | 103/day | 81 of 90 sampled (90%) |
| `LogMedianPrice` (legacy Median/OSM) | 672 | 96/day | 90 of 90 (100%) |

Four entry points, all keccak-verified locally:

| selector | function | gas | calldata |
|---|---|---|---|
| `0x00000082` | `poke_optimized_7136211((uint128,uint32),(bytes32,address,bytes))` | 121,309–129,099 | 260B |
| `0x2f529d73` | `poke((uint128,uint32),(bytes32,address,bytes))` | 127,899–128,819 | 260B |
| `0x89bbb8b2` | `poke(uint256[],uint256[],uint8[],bytes32[],bytes32[])` | 73,493–89,949 | 1124–1444B |
| `0x18178358` | `poke()` | 80,034–103,090 | 4B |

`poke_optimized_7136211` is a mined function name: Chronicle brute-forced it so the selector
begins with three zero bytes, saving calldata gas. They optimise aggressively.

### Results

| contract | function | gas used | replay cost | surplus | Schnorr |
|---|---|---:|---:|---:|---:|
| Scribe | `poke_optimized` | 129,099 | 36,964 | +92,135 | **32.64%** |
| Scribe | `poke` | 128,819 | 36,964 | +91,855 | **32.49%** |
| Scribe | `poke` | 127,899 | 36,940 | +90,959 | **32.02%** |
| Scribe | `poke_optimized` | 127,643 | 36,964 | +90,679 | **31.87%** |
| Scribe | `poke_optimized` | 127,655 | 37,036 | +90,619 | **31.82%** |
| Scribe | `poke_optimized` | 126,087 | 36,988 | +89,099 | **31.01%** |
| Scribe | `poke_optimized` | 125,951 | 36,940 | +89,011 | **30.97%** |
| Scribe | `poke_optimized` | 125,663 | 37,036 | +88,627 | **30.74%** |
| Scribe | `poke_optimized` | 124,495 | 36,940 | +87,555 | **30.17%** |
| Scribe | `poke_optimized` | 124,507 | 36,988 | +87,519 | **30.13%** |
| Scribe | `poke_optimized` | 124,507 | 36,988 | +87,519 | **30.13%** |
| Scribe | `poke_optimized` | 124,519 | 37,012 | +87,507 | **30.12%** |
| Scribe | `poke_optimized` | 121,309 | 36,988 | +84,321 | **28.29%** |
| OSM | `poke()` | 103,090 | 36,022 | +67,068 | **16.56%** |
| OSM | `poke()` | 103,080 | 36,022 | +67,058 | **16.55%** |
| Median | `poke(...sigs)` | 89,949 | 35,974 | +53,975 | **4.42%** |
| Median | `poke(...sigs)` | 89,937 | 35,974 | +53,963 | **4.41%** |
| OSM | `poke()` | 80,034 | 35,974 | +44,060 | **0.00%** |
| OSM | `poke()` | 80,034 | 35,974 | +44,060 | **0.00%** |
| Median | `poke(...sigs)` | 73,567 | 36,022 | +37,545 | **0.00%** |
| Median | `poke(...sigs)` | 73,493 | 36,022 | +37,471 | **0.00%** |
| Multicall3 | `aggregate3` | 897,296 | 911,985 | −14,689 | 0% |
| Multicall3 | `aggregate3` | 569,896 | 579,405 | −9,509 | 0% |
| Multicall3 | `aggregate3` | 243,479 | 247,819 | −4,340 | 0% |

### Why the shape is close to ideal

Every direct poke records exactly **two state updates — one storage write and one log** — and
**zero external calls**. Replay therefore costs about 37,000 gas regardless of feed or
transaction: across 13 Scribe measurements the base estimate varies by 96 gas. Everything
above it — mean **89,031 gas** — is removable work.

The analyzer reports the size of that surplus, not what it consists of. Attributing it to
signature verification is an inference from Scribe's `poke` path (decode, staleness check,
Schnorr verify, signer-registry lookup, write), where verification is by far the largest item
and the 260-byte calldata is mostly signature. **Not decomposed, not verified.**

This is the precise inverse of ENS, measured in the same session. ENS is a large payload with
nothing around it (best surplus 16,058 gas, never clears the floor). Chronicle is a tiny
payload with a lot around it (surplus 37,471–92,135 gas, always clears it). Same floor,
opposite outcome — the cleanest illustration in this survey of what condition 2 actually
measures.

### Worth in dollars

189 qualifying transactions/day (92.7 Scribe direct + 96.4 legacy Median/OSM), mean saving
62,031 gas for Scribe and 23,650 for Median/OSM = **240.9M gas/month**. At the **1.007 gwei**
median effective gas price these transactions actually paid, ETH $2,419.40 (Chronicle
aggregator, on-chain): **$304/month.** At 20 gwei, $6,041/month.

Third by money behind Aave ($1,392) and Railgun ($876), and **~25x Pyth** despite a lower
headline percentage than Pyth's best. Two reasons, both worth carrying into the ranking
method: Chronicle has ~6x Pyth's qualifying volume, and its transactions pay roughly **10x
the gas price** ENS and Pyth pay, because an oracle update must land promptly and bids for
inclusion. Gas *price paid* is a ranking input, not just gas used.

### Two objections that belong in any pitch

**1. Scribe is already a Schnorr multi-signature oracle.** Its repository describes it as
"an efficient Schnorr multi-signature based Oracle": validator signatures are already
aggregated off-chain and one signature is verified on-chain. GasKiller would replace one
aggregate-signature check with another, and its 50,000-gas floor is charged against a contract
built specifically to minimise that cost. The argument has to be narrow and quantitative —
*the measured removable surplus averages 89,031 gas; GasKiller's own signature check costs
50,000* — not "we remove your computation." Both should be quoted for what they are: 50,000 is
a constant in this repo (`crates/core/src/encoding.rs:21`), 89,031 is gas used minus the
measured replay cost.

**2. Optimistic settlement changes the security model for a price feed.** GasKiller writes the
result and permits a challenge afterwards. A lending market reading that price to trigger
liquidations treats "verified now" and "challengeable later" very differently. This is not a
gas question and I have not evaluated it, but it is the strongest counter to the largest win
measured here, and Chronicle will raise it before anything else.

**Batching is the one technical blocker.** About 10% of Scribe traffic arrives via Multicall3
`aggregate3`, a keeper poking several feeds at once. All three measured score 0% with negative
surplus: each inner poke becomes an external call that must be re-executed. An integration
should keep pokes as separate direct transactions.

## Umbra — a value transfer plus an event, and nothing else

Next entry on the longlist after the other three privacy protocols. The longlist rates it
"smaller compute footprint than shielded pools but high transaction frequency, useful
reference for volume-based rebate pitch." Both halves of that turn out to be wrong in the
same direction.

Found by event topic, no address guessing: `Announcement(address,uint256,address,bytes32,bytes32)`
resolves to a single live contract, `0xfb2dc580…`.

**8 transactions, 4 functions, all trace-measured. All 0.00% — and every one has negative
surplus.**

| function | gas used | replay cost | surplus |
|---|---:|---:|---:|
| `sendEth` ✓ `0xbeb9addf` | 62,261 | 69,749 | **−7,488** |
| `sendEth` ✓ `0xbeb9addf` | 62,261 | 69,773 | −7,512 |
| `withdrawTokenOnBehalf` ✓ `0x81ab0fcd` | 70,497 | 79,463 | −8,966 |
| `withdrawTokenOnBehalf` ✓ `0x81ab0fcd` | 70,613 | 79,861 | −9,248 |
| `sendToken` ✓ `0xb9bfabe1` | 83,712 | 93,356 | −9,644 |
| `sendToken` ✓ `0xb9bfabe1` | 83,724 | 93,380 | −9,656 |
| `sendToken` ✓ `0xb9bfabe1` | 75,873 | 85,673 | −9,800 |
| *batch send* `0x7d703ead` | 505,078 | 531,727 | −26,649 |

The best case is **−7,488 gas**. Umbra therefore joins Chainlink and Panther in the group that
scores zero **at any floor, including a floor of zero** — a lower signature floor
cannot rescue it, because there is no surplus to recover.

**Why.** A stealth payment is a value transfer plus an event. The transfer is recorded as a
`Call` update, which GasKiller has to re-execute verbatim; the event has to be re-emitted.
Both are irreducible payload, and neither is computation. The recorded state changes are 1–3
updates of which 1–2 are always `Call`s, so replay reproduces essentially the whole
transaction and then adds wrapper overhead on top — hence the negative surplus. Note this is
the *only* protocol surveyed where every single transaction is negative.

`withdrawTokenOnBehalf` was the one plausible candidate: a relayer-sponsored withdrawal that
verifies an ECDSA signature. It measures −8,966 and −9,248. One `ecrecover` is ~3,000 gas —
nowhere near enough to matter against a 50,000-gas floor.

**There is no shield transaction, by design.** Every `PUSH4` constant in the contract's 7,110
bytes of bytecode resolves to one of: `sendEth`/`sendToken`, four `withdrawToken*` variants,
seven toll/fee admin functions, `tokenPayments`, and Ownable's three. Three selectors are
unresolved. Nothing resembles a shield, deposit, commitment, nullifier or proof verifier.
Umbra is a stealth-address scheme, not a shielded pool: funds go straight to a fresh one-time
address derived from the recipient's published keys, and the `Announcement` event exists only
so the recipient can scan for it. Privacy comes from address unlinkability, not from hiding
amounts in a pool — so there is no merkle tree to update and no proof to verify. That is why a
payment costs 62,000 gas and why there is nothing to remove. The longlist says as much
("smaller compute footprint than shielded pools"); the measurement confirms it.

**And the frequency claim is wrong.** Enumerating *every* transaction that touches the Umbra
contract in a 27.88-day window (200,000 blocks, filtered on address **and** topic): **38
transactions = 1.36/day** — 15 `sendToken`, 15 `withdrawTokenOnBehalf`, 6 batch sends,
2 `sendEth`. That is the lowest of anything surveyed with a live deployment, and the
highest-gas Umbra transaction among all 38 is the 505,078-gas batch send already measured at
−26,649 surplus, so no heavier shape exists outside the sample.

> **Correction.** An earlier version of this section reported 291 transactions / 10.4 per day.
> That came from filtering the `Announcement` topic *without* an address filter, which swept in
> dozens of unrelated contracts emitting the same event signature. The real figure is 7.6x
> lower. The conclusion is unchanged and strengthened.

There is no volume-based rebate pitch to make: even at a hypothetical 100% saving, 1.4
transactions a day at 2.079 gwei is a rounding error. **Umbra's longlist entry should be
removed, not just revised down.**

The 6 batch sends arrive through a separate helper contract (`0xdbd0f5eb…`), not Umbra itself;
they appear in the table below under Umbra because that is the protocol they serve.

## The restaking block — best percentages in the survey, almost no money

Six longlist entries measured together: Mellow, Renzo, Kelp, Puffer, Symbiotic, Swell.
21 transactions, all trace-measured.

**I predicted this block would be weak and I was wrong.** The reasoning was that EigenLayer
(5.15%), Ether.fi (18.99%) and Lido (1.13%) had all scored low, and vault accounting is the
bookkeeping shape. In fact **Kelp's `depositETH` is the highest measured saving in this
entire file at 83.29%**, ahead of Railgun's 78.72%.

| protocol | function | best | n measured | winning |
|---|---|---:|---:|---:|
| **Kelp** | `depositETH` ✓ `0x72c51c0b` | **83.29%** | 5 | 4 |
| **Renzo** | `claim` ✓ `0xddd5e1b2` | *62.97%* | 2 | 1 |
| **Symbiotic** | `withdraw`/`redeem` (ERC-4626) | 57.04% | 4 | 4 |
| **Mellow** | `withdraw`/`redeem` (ERC-4626) | 41.55% | 5 | 5 |
| **Puffer** | `requestWithdrawal` ✓ `0xef027fbf` | *7.06%* | 2 | 1 |
| **Swell** | `createWithdrawRequest` ✓ `0x74dc9d1a` | 0.00% | 3 | 0 |

Kelp is remarkably consistent: 83.29%, 82.55%, 80.90%, 80.90% across four deposits. Each
burns 843,973–881,047 gas and records **four state updates** — a reentrancy-guard write, one
`mint` call on rsETH, one `ETHDeposit` log, and the guard reset. Replay costs 97,229–114,353.

**Why it wins.** Kelp's deposit path prices the pool by iterating over node delegators and
strategies. Those are `view` calls, so they compile to `STATICCALL`, which the tracer ignores
— their gas lands in the surplus and none of it has to be replayed. It is the Aave `borrow`
pattern (a per-asset loop in the contract you call directly) with an even smaller payload.

**Verification.** This is the largest claim in the file, and a large win with few recorded
updates is exactly the shape of the ERC-4337 false positive. I checked each result against its
receipt: every Kelp deposit's receipt contains **only 2 logs**, and the trace accounts for both
(one recorded log, plus the `mint` call that emits the other). Nothing was dropped, and no
revert appears in any trace. The selector and the `ETHDeposit(address,uint256,uint256,string)`
event were both confirmed by hashing locally. One Mellow row (`0x7bcd05f1…`, 22.22%) has 8 of
10 receipt logs unaccounted for by its 2 recorded calls and is **flagged unverified** in the
table.

### Attribution check — which labels are verified

Because these six were measured in one batch off entry points discovered from each protocol's
token logs, the protocol labels are worth auditing separately from the numbers. For each of the
21 transactions I checked the `to` address against a list of verified protocol contracts and
against which tokens the receipt actually moved:

| label | `to` | status |
|---|---|---|
| **Kelp** (4 rows incl. the 83.29%) | `0x036676389e…` LRTDepositPool | **verified** — own deposit pool, mints rsETH |
| **Mellow** (5 rows) | `0xbeef69ac78…` steakLRT vault | **verified** — the vault itself |
| **Symbiotic** (4 rows) | `0x7a4effd87c…` vault | **verified by association** — interacts with Symbiotic's wstETH default collateral |
| **Renzo** (the 62.97% row) | `0x5efc9d10e4…` | **inferred only** — contract unidentified; moves ezETH |
| **Puffer** (the 7.06% row) | `0xdda0483184…` | **inferred only** — contract unidentified; moves pufETH |
| **Swell** (2 rows) | `0x58749c46ff…`, `0x289d600447…` | inferred only; both score 0%, so nothing rests on them |

**The headline is safe** — Kelp's 83.29% goes directly to Kelp's own pool. **Renzo's 62.97% and
Puffer's 7.06% should not be quoted as those protocols' own numbers** until someone confirms
what those two contracts are. They are ezETH- and pufETH-related, which is not the same as
being Renzo's or Puffer's own entry point. This is the same failure mode as the earlier
mislabelling of the ERC-4337 EntryPoint as "ZeroDev", caught earlier this time.

**Mellow and Symbiotic are not independent.** The steakLRT vault deposits into Symbiotic's
wstETH default collateral, so a Mellow withdrawal is partly Symbiotic activity. Adding their
volumes together double-counts, which makes the $47/month figure above slightly optimistic.

### And now the money

| | qualifying txs/day | mean saving | **$/month** | at 20 gwei |
|---|---:|---:|---:|---:|
| Kelp `depositETH` | **0.36** | 705,520 gas | **$25** | $372 |
| Symbiotic withdraw/redeem | 1.49 | 198,041 gas | **$14** | $432 |
| Mellow withdraw/redeem | 1.61 | 93,559 gas | **$3** | $221 |
| | | | **$42** | **$1,025** |

**The best percentage in the survey is worth $25 a month.** Kelp's pool takes 6 qualifying
deposits per 16.7 days. Chronicle, at a lower percentage, is worth about 12x more because it runs
189 qualifying transactions a day instead of 0.36.

This is the exact mirror of ENS — 877 txs/day and no surplus, versus 0.36 txs/day and the
largest surplus measured. Neither is a business. **Percentage and volume have been anti-
correlated across everything surveyed**, and the restaking block is the sharpest illustration.

Caveats: Symbiotic runs many vaults and only one (`0x7a4effd8…`) was measured, so its volume
is understated by an unknown factor — it is the one entry here that might scale. Mellow
likewise runs many vaults; only steakLRT was measured. Three rows in the table are **other
people's traffic** — a Paraswap route touching pufETH, and two aggregators touching ezETH and
rswETH — flagged in the notes and excluded from the per-protocol figures above.

## Sky (Maker) — thousands of transactions a day, none of them reachable

The last remaining longlist entry with Aave-scale mainnet volume, and the reason it was worth
checking. **9 transactions measured, all 0.00%, every one with negative surplus.** Sky joins
Chainlink, Panther and Umbra in scoring zero at any floor including zero.

The result is not about gas efficiency. It is about routing.

### The volume is real and it is all indirect

Scanned 899 consecutive blocks (3.0 hours) of full block receipts — Maker's `Vat` emits no
events, so a log-based scan misses the core entirely and I had to walk receipts instead.

| contract | txs/day | direct calls | median gas |
|---|---:|---:|---:|
| **LitePSM (USDC)** | **3,836** | **0** | 670,471 |
| **Vat** (the core ledger) | **2,531** | **0** | 679,968 |
| Jug (stability fees) | 200 | **0** | 735,969 |
| sUSDS | 296 indirect | **96 direct** | 826,081 / 135,872 |

**Not one direct call to the Vat, the PSM or the Jug in three hours.** Every PSM swap and every
CDP operation arrives inside someone else's contract — arbitrage bots, aggregators, and in the
two cases measured here a market maker's Gnosis Safe (`execTransaction`, verified by hashing).
The analyzer keeps a regular `CALL` as one instruction and re-executes it on replay
(`crates/core/src/trace.rs:255`), so none of that work is ever removable.

This is the Euler result at ten times the scale. Euler scored 1.31% with 0 of 191 direct calls
because the EVC router is mandatory; Sky scores 0.00% with 0 of ~6,500 daily core transactions
direct, because the PSM and the Vat are plumbing that only other contracts call.

### What is directly callable measures negative

| function | gas used | replay cost | surplus |
|---|---:|---:|---:|
| Safe `execTransaction` *(third-party)* | 902,223 | 902,671 | **−448** |
| Safe `execTransaction` *(third-party)* | 982,548 | 985,574 | −3,026 |
| sUSDS `transfer` | 56,380 | 62,836 | −6,456 |
| USDS `transfer` | 56,336 | 62,836 | −6,500 |
| DaiUsds `daiToUsds` | 132,007 | 151,437 | −19,430 |
| sUSDS `redeem` | 148,203 | 174,502 | −26,299 |
| sUSDS `withdraw` | 148,058 | 174,490 | −26,432 |
| sUSDS `deposit` | 145,878 | 177,107 | −31,229 |
| sUSDS `deposit` | 145,585 | 177,095 | −31,510 |

The only Sky-native operations users call directly are sUSDS deposits and redemptions (96/day)
and token transfers. Every one is negative: an sUSDS deposit records 9–10 updates of which 3
are `Call`s, so replay reproduces the transaction and adds overhead. Interesting detail — the
two third-party Safe executions come *closest* to breaking even (−448) despite being the
largest transactions here, because almost all their gas sits in calls that replay at the same
price.

**Note this is the opposite failure from ENS.** ENS was directly callable with nothing to
remove; Sky's core is not directly callable at all. But see the census below before reading that
as untapped value — Sky's own share of those large indirect transactions is only 12,000–48,000
gas per call. Of the two, Sky's is the more interesting problem, because a routing change
is at least conceivable where a missing computation is not.

### Function-level census — what "no savings" actually covers

9 transactions across 6 functions is thin for a system Maker's size, so the claim was checked
against a full function-level census. `debug_traceTransaction` with `callTracer` is available on
this endpoint, so every call *into* a Sky contract can be enumerated, including nested ones.
70 Sky-touching transactions traced (of 473 found in 260 blocks), yielding **32 distinct
contract/function pairs**, all selectors resolved by local hashing.

**Every core Maker function is nested-only — never once invoked at top level:**

| contract | function | calls | at top level | gas of that call |
|---|---|---:|---:|---:|
| Vat | `move(address,address,uint256)` | 19 | **0** | 12,843 |
| Vat | `frob(bytes32,address,address,address,int256,int256)` | 2 | **0** | 33,803 |
| Vat | `suck(address,address,uint256)` | 1 | **0** | 44,764 |
| Vat | `fold(bytes32,address,int256)` | 1 | **0** | 14,632 |
| LitePSM | `buyGem(address,uint256)` | 6 | **0** | 48,418 |
| LitePSM | `sellGem(address,uint256)` | 5 | **0** | 39,036 |
| LitePSM | `sellGemNoFee(address,uint256)` | 1 | **0** | 49,021 |
| Jug | `drip(bytes32)` | 1 | **0** | 47,347 |
| DaiUsds | `daiToUsds` / `usdsToDai` | 2 | **0** | 130,551 / 89,372 |
| DAI/USDS | `mint` / `burn` | 19 | **0** | 10,346–28,157 |

The only functions ever called at top level are token operations — `transfer`, `transferFrom`,
`approve` on DAI, USDS and SKY — plus `sUSDS.deposit`. Nothing else.

**This corrects a claim made earlier in this section.** An earlier version said Sky has "a median
670,000 gas of removable work and no way to reach it". That was wrong: the 670,000-gas median
belongs to the *arbitrage bot's* transaction, not to Sky. Each individual Sky call consumes
12,000–48,000 gas, so Sky's own share of one of those transactions is under 10% of it.

That makes the negative stronger, not weaker. Even if the routing problem were solved and
`buyGem` were directly callable, 48,418 gas has to clear a 50,000-gas floor from a base that
already contains its own storage writes and logs — there is no room. The supporting evidence is
`daiToUsds`, the largest single Sky function in the census at 130,551 gas: it *was* measured
directly, and came out at **−19,430 surplus**.

Coverage of the 32 pairs: 8 are `view` functions and cannot be transactions at all
(`balanceOf`, `allowance`, `ilks`, `urns`, `tout`, `to18ConversionFactor`); 6 were measured;
the remaining 18 are either token operations nearly identical to ones measured, or the
nested-only core functions above, none of which exceeds 49,021 gas per call.

**One transaction could not be measured**: an sUSDS `deposit` (`0x2f6a9995…`, 110,061 gas, 0
logs) failed after 6 attempts and is listed with the other unmeasurable transactions.

## Notional — no measurable activity on Ethereum mainnet

Nothing was measured, because nothing was found to measure. Recorded here so the entry is
closed rather than skipped.

Three independent checks agree:

| check | result |
|---|---|
| 8 Notional protocol event signatures, scanned **topic-only** (no address filter) over 60,000 blocks (~8 days) | **0 logs anywhere on mainnet** |
| NOTE token transfers over the same window — contract verified as genuine (`name()` = "Notional", `symbol()` = "NOTE", 8 decimals) | **4 transfers, all DEX routers** (MetaMask Swap, 1inch v6, CoW Protocol, one other) |
| Candidate V3 router `0x1344A36A…` | **not Notional** — a live proxy with an owner and implementation, but every Notional view function reverts, and zero logs in probes going back 3.6M blocks |

Notional V3 is deployed primarily on Arbitrum. This is the same situation as Panther: the
protocol is real and the mainnet target is not there. NOTE exists on mainnet as a tradeable
token only.

**Stated limitation:** I could not locate a live Notional V3 entry point on mainnet, so the
honest claim is "no measurable activity found", not "definitively zero". If someone supplies a
confirmed mainnet address the census takes about ten minutes to run against it. The event-topic
scan is the stronger of the three checks because it needs no address at all — but it does rely
on my event signatures being right, and those were reconstructed rather than taken from an ABI.

## Frax — a router saves nothing, and the tokens are never called directly

Frax was the next name on the longlist. It is a negative, and unlike most of the negatives in
this file it fails on *both* screening conditions at once, for two different sets of
transactions. Ten transactions measured, none saved anything.

**Addresses verified before any volume claim.** Six of seven candidate addresses returned
non-zero codesize; the FPI address carried in the longlist returned codesize 0 and was dropped
rather than counted. This check exists because Notional's first pass reported "0 txs in 27.9
days" from an address that turned out not to be Notional.

**The volume figure is smaller than it first looks.** A 600-block census found 58 transactions
touching a Frax contract — 696/day — but only 4 of them called one directly. A wider 4,000-block
scan (13.3 hours) put the direct rate at **59.4/day**. The gap is the whole point: the other
~640/day are other protocols' transactions that happen to move a Frax token, and
`crates/core/src/trace.rs:255` drops everything nested inside a regular `CALL`. That work is
invisible to the analyzer and is credited to whichever contract was actually called. "Touching"
and "directly called" are different numbers and only the second one can be replaced.

(This distinction is recorded because getting it wrong is easy: the Umbra volume in an earlier
draft of this file was overstated 7.6× by matching an event signature without an address filter.)

**Composition kills most of what remains.** Of the 33 direct transactions found, 22 were
`approve` — 16 of them byte-identical at 46,619 gas, which reads as a single bot looping. An
`approve` is one `SSTORE` and one log: the state change *is* the transaction, so there is no
surplus to remove. That is screening condition (2) — the work must be computation, not
bookkeeping.

**The router fails structurally, not marginally.** The Fraxswap swaps were the one genuinely
promising candidate: top-level, 208,660 gas, and a swap is computation. The measurement:

| | gas used | base estimate | surplus |
|---|---|---|---|
| `swapExactTokensForTokens` | 217,674 | 221,917 | **-4,243** |
| `swapExactTokensForTokens` | 213,167 | 217,410 | **-4,243** |
| `swapExactTokensForTokens` | 208,660 | 212,903 | **-4,243** (×3) |

The recorded state-update program for a Fraxswap swap is **three `Call`s and nothing else** — no
`Store`s, no `Log`s. A router does no work of its own; it calls the pair contracts, and
everything inside those calls is dropped. GasKiller's replacement program still has to make the
same three external calls, so it costs *more* than the original transaction. The surplus is
identical to the gas across all five (-4,243), confirming these are one bot on one code path —
one observation, not five.

This is the same shape as Pendle (2.60%, aggregator) and the Ondo MEV-bot row. No floor change
affects it: the surplus is negative before the floor is applied, so Frax scores 0.00% at a floor
of zero.

> **Correction.** The first version of this section concluded from the above that "a pure router
> is structurally disqualified from this scheme." That over-claims. A wider census (below) found
> that the work is not absent — it is one `CALL` deeper, in the pair contract, and the current
> encoder cannot see it. The router rows belong on the call-blocked watchlist, not in the
> written-off pile. See `CALL_BLOCKED_CANDIDATES.md`.

**The wider census — 38 more contracts, and the reason the router number is misleading.**
The first pass tested six contracts. Frax's live surface is much larger, so all of it was
censused: veFXS, sFRAX, the frxETH redemption queue, FraxFerry, the AMO minter, the unified
farm, the Fraxlend deployer, the Fraxswap factory and all **29 Fraxswap pairs** enumerated from
that factory. Over 2,500 blocks (8.33 hours):

```
scanned 2500 blocks (8.33h): 35 touching txs = 101/day  (direct 0)
```

**Zero** direct top-level calls to any of the 38. Every selector came back `TOP=0`. But the
pairs are busy when reached through the router, and what they are doing matters:
`executeVirtualOrders(uint256)` (`0x2e0ae375`) — TWAMM long-term order grinding — runs at a
**123,468-gas median**, with one observed pair call at **802,548 gas**. That is genuine
computation of exactly the kind this scheme exists to remove, and the router's -4,243 surplus
is measuring its own inability to reach it, not its absence.

Priced properly against the real state diff (13 slots, of which only 3 are fresh; 3 contracts;
7 logs; 13,626 of log cost; 50,000 floor) a call-aware encoder would unlock **+37,748 (17%)**
on the largest swap and +28,734 (14%) on the typical one. Real, but roughly a fifth of what the
Railgun and Morpho entries on that watchlist would unlock — and behind a direct rate of ~59/day
that is mostly `approve` spam.

**The token and vault operations fail the other way.** sfrxETH `redeem` (78,365 gas, base
97,929), FXS `transfer` (128,870 / 152,949), frxETH `approve` (46,619 / 55,564) — all
bookkeeping, all with `base_estimate` above `gas_used`.

The `approve` was run as a control, expected to return 0%. It did. That is what licenses
trusting the rest of the column.

**Two transactions are excluded, not counted as zeros.** `0xace12218…` and `0xefa82f36…` would
not come off the heuristic estimator after four attempts each. A `heur` row is not evidence —
16 of 18 heuristic fallbacks re-measured elsewhere in this survey collapsed to 0%. They are
excluded from the ten. Separately, `0xefa82f36…` carries 0 logs on a nominally successful
208k-gas swap, which usually means it reverted; it is not counted either way.

**Prior stated before measurement, and it held:** Frax migrated most activity to Fraxtal, its
own L2, so mainnet was expected to be thin. It is — but the result does not rest on that. Even
at high volume the router saves nothing, because replaying three external calls costs more than
making them.

## Aragon — real savings, but they are the plugin's bookkeeping around a replayed call

Aragon OSx is live on mainnet and it does save gas: **all six** measured `execute` transactions
clear the 50,000 floor, the best at **24.15%** (295,062 gas) and the largest at 468,738 gas
absolute. No other entry point saves anything (19 measured in total).
That is the first non-zero result since Chronicle. It is still not a candidate, for two reasons
that are worth separating.

**Discovery.** No address was assumed. Scanning 200,000 blocks (~28 days) for OSx event topics
found the registry (`0x7a62da7b…`, 4 `DAORegistered`), the plugin repo registry
(`0x5b3b36bd…`) and 93 `Executed` logs across a handful of DAOs. Of 81 distinct executing
transactions, **0 were sent directly to a DAO** — every one enters through a plugin. Three of
those plugins answer `dao()` and use `execute(uint256)` (`0xfe0d94c1`); the rest of the `to`
addresses were Safe multisigs and unrelated contracts and were excluded rather than counted as
Aragon.

**The wins are call-dominated.** Every winning row has the identical recorded program —
**1 `Store`, 1 `Call`, 1 `Log2`** — while the receipt carries 14 to 124 logs. The base estimate
is 94% of gas used because replaying that single `CALL` re-executes the entire proposal at full
price. What GasKiller removes is only the plugin's own proposal bookkeeping sitting outside the
call: marking the proposal executed, emitting `ProposalExecuted`. The percentage therefore
falls as the proposal grows — 21.59% on an 846k-gas execution, 5.60% on an 8.4M-gas one. It is
a real saving under the tool's model, not a replay artifact (the inner call reproduces the rest
of the state), but it does not scale with the work being done.

The three zero rows are the opposite shape: a plugin that writes **38 `Store`s** of its own,
where replay costs more than execution. (Those three were first recorded as `execute`; they are
in fact `createProposal` — `0xfbd56e41`, verified locally. The label is corrected in
`ALL_TRANSACTION_ANALYSES.md`.)

**Every other Aragon transaction type was then measured, and none of them saves anything.**
The first pass covered only `execute(uint256)`. An address-filtered log scan across 18 Aragon
addresses over 200,000 blocks found 98 transactions, 50 of them direct, spanning three more
entry points — and `execute` is not even the common one:

| type | selector | n | median gas | result |
|---|---|---:|---:|---|
| `approve(uint256,bool)` | `0x747442d3` | 25 | 81,408 | +2,024 surplus, **under the floor** |
| `createProposal(...)` | `0xfbd56e41` | 14 | up to 4,933,009 | **replay costs more**, every one |
| `execute(uint256)` | `0xfe0d94c1` | 10 | 1,419,945 | the only type that saves — 6 of 6 measured |
| *unidentified* | `0xe978afe5` | 1 | 413,213 | **replay costs more** |

`createProposal` is the interesting negative. At 4.9M gas it is the largest Aragon transaction
on mainnet, and its recorded program is **265 `Store`s and a single `Log3`** — writing the
proposal's actions into storage and nothing else. There is no computation to remove; the
transaction *is* its state change, so replaying it costs 5,583,640 against 4,933,009 used. The
pattern holds across all seven measured, from 34 stores at 674,728 gas to 265 at 4.9M.

`approve` — the most common Aragon transaction at 25 of 50 direct — is 2 `Store`s and a log,
with a surplus of ~2,000 gas against a 50,000 floor. It would need the floor to fall by 25×.

So across 19 measured transactions and four entry points, savings exist only in `execute`, only
because a `CALL` hides the real work, and only at 0.357 plugin executions/day.

**On the excluded rows.** Five transactions across Frax and Aragon would not come off the
heuristic estimator and were excluded rather than scored. Re-running them to see what the
heuristic had claimed: three agreed with their measured siblings at 0.00%, one
(`0xefa82f36…`, the 0-log Fraxswap swap) turned out to be a **reverted transaction** the
analyzer refuses outright (`Error: transaction failed`), and one — Aragon `0x9a11baf5…` —
claimed **25.78%**. That last one was worth chasing: eight retries got it measured at
**24.15%**, making it Aragon's best row. The heuristic had overstated it by 1.63 points,
understating the base by ~20,000 gas, consistent with its known optimistic bias (`Call` priced
at zero, fresh `SSTORE`s charged 5,000 against ~20,000 actual). Notably the Frax swap
`0xace12218…` came back at 0.00% from a heuristic base **14,000 below** its measured siblings'
— a negative that survives its own error term.

**The volume is negligible.** The qualifying rate is **0.357/day** — 10 direct plugin
`execute` calls in 28 days. At 301,614 gas mean saving across the six, that is 3.2M gas/month
= **$3.62/month** at the 0.453 gwei median these transactions actually paid, or $160/month at
20 gwei. Governance execution is inherently low-frequency; this is a rounding error next to
Aave's $1,392/month.

> **Correction.** An earlier version of this section put the rate at 2.89/day and the value at
> $18/month, taking all 81 transactions that emit an OSx `Executed` log over 28 days. That is
> wrong by 8×: only 10 of those enter through an Aragon plugin. The other 71 arrive via Safe
> `execTransaction` and other third-party entry points, where the Aragon work is nested inside
> a `CALL` and the transaction scores as a Safe (0%). Only the plugin-entry calls qualify.

| | qualifying txs/day | mean saving | **$/month** | at 20 gwei |
|---|---:|---:|---:|---:|
| Aragon | 0.357 (`execute` only) | 301,614 gas | **$3.62** | $160 |

## ZeroDev — measured at last, and it is a clean negative

The ERC-4337 section of this file carried a scope caveat: those eight rows are transactions to
the shared EntryPoint, the wallet vendor behind each userOp was never identified, and **ZeroDev
specifically had not been measured**. It has now.

**Identifying ZeroDev without guessing.** A userOp's sender is a smart account, so the vendor is
whatever sits in the account's ERC-1967 implementation slot. Reading that slot and calling
`eip712Domain()` on each implementation returns the wallet's own name — `"Kernel"` for ZeroDev,
against `"Coinbase Smart Wallet"`, `"LightAccount"` and `"SmartWallet"` for the others. Four live
Kernel implementations were confirmed this way: v3.1 (`0xbAC849bB…`), v3.0 (`0x94F097E1…`),
v2.4 (`0xd3F582F6…`) and `0xd830d15d…`. In a 13-hour sample, **105 of 6,534** sender accounts
were Kernels — about 1.6% of mainnet userOp traffic.

Only **single-userOp** transactions were measured. A bundle mixing a Kernel op with a Coinbase
op cannot be credited to either vendor, and mis-attribution of exactly this kind is what forced
the earlier rows to be relabelled from "ZeroDev" to "ERC-4337 EntryPoint".

**The result.** Nine measured, zero savings, and not one is close:

| gas used | base estimate | surplus |
|---:|---:|---:|
| 622,870 | 679,189 | -56,319 |
| 594,900 | 668,985 | -74,085 |
| 474,560 | 565,299 | -90,739 |
| 429,858 | 487,060 | -57,202 |
| 332,571 | 402,041 | -69,470 |
| 211,416 | 252,106 | -40,690 |
| 182,649 | 224,499 | -41,850 |
| 162,270 | 200,964 | -38,694 |
| 145,146 | 183,816 | -38,670 |

`base_estimate` exceeds `gas_used` on all nine, so this is floor-independent: ZeroDev scores
0.00% at a floor of zero. Every row has the identical shape — **4 `Store`s, 4 `Call`s, 1 `Log1`**
— which is the EntryPoint's own accounting (deposit debit, nonce bump, `UserOperationEvent`)
wrapped around calls whose contents are dropped. The account's actual work happens inside those
calls and is invisible; what remains is bookkeeping that costs more to replay than to execute.

**This also bears on the two suspect rows.** The ERC-4337 section flags two wins at 85.18% and
81.88% as probable replay artifacts, marked do-not-quote. Nine clean measurements of the same
transaction type, all strongly negative, are consistent with those two being artifacts rather
than real. It is not proof — a different bundler and a different account shape — but nothing
here supports an 85% win on a `handleOps` transaction.

One transaction stayed on the heuristic estimator after four attempts and is excluded.

## EAS — an attestation is its own state change

Ethereum Attestation Service is the purest bookkeeping negative in this survey. Eleven
transactions measured, every one of the four live entry points covered, nothing saved, and no
row needed excluding.

**Volume first.** A 28-day log scan over the EAS core and the SchemaRegistry found 44
transactions — **1.6/day**, of which 41 are direct. Attribution is clean (EAS is called
directly, not through routers), but the ceiling is lower than Aragon's before percentages are
even considered.

| type | selector | n | median gas | result |
|---|---|---:|---:|---|
| `attest` | `0xf17325e7` | 24 | 327,202 | replay costs more |
| `multiTimestamp` | `0xe71ff365` | 9 | 46,657 | replay costs more |
| `register` (SchemaRegistry) | `0x60d7a278` | 7 | 139,211 | replay costs more |
| `multiAttest` | `0x44adc90e` | 1 | 2,546,830 | replay costs more |

**Why every one fails.** An attestation is data written to storage. `multiAttest` at 2,546,830
gas records **100 `Store`s, 4 `Log4`s and 1 `Call`**; a 545,839-gas `attest` records **23
`Store`s and 1 `Log4`**. There is no verification step, no proof check, no computation of any
kind to remove — the transaction *is* its state change, and GasKiller's replacement program has
to perform every one of those writes itself. `base_estimate` exceeds `gas_used` on all eleven,
by 22,954 to 259,385 gas.

This is floor-independent. EAS scores 0.00% at a floor of zero, and would still score 0.00% if
signature verification were free.

It is worth stating plainly because EAS looks superficially attractive — large transactions,
millions of gas, a clear protocol identity, direct calls. Size is not surplus. What matters is
the ratio of computation to bookkeeping, and for an attestation service that ratio is zero by
design.

## Gitcoin Passport — not on this chain; Gitcoin on mainnet is a token

The longlist entry is "Gitcoin Passport". **Passport does not run on Ethereum mainnet.** Its
decoder address returns codesize 0 here; the system lives on Optimism and Base, where its
stamps are EAS attestations. There is nothing to measure on this chain, and the longlist entry
should be read as out of scope rather than as a negative result.

What Gitcoin does have on mainnet is the GTC token — and only the token. A 28-day log scan
across GTC, the Gitcoin Governor, the Timelock and the TokenDistributor found 5,439
transactions touching them (194/day, 1,883 direct), but **the Governor, Timelock and
TokenDistributor had zero direct transactions in the entire window**. Every direct call is an
ERC-20 operation:

| type | selector | n | median gas |
|---|---|---:|---:|
| `transfer` | `0xa9059cbb` | 1,095 | 39,918 |
| `approve` | `0x095ea7b3` | 703 | 46,540 |
| `transferFrom` | `0x23b872dd` | 79 | 38,023 |
| `delegate` | `0x5c19a95c` | 6 | 95,579 |

Five measured, none saving. `delegate` was the only one worth checking — it writes voting
checkpoints, so it is the closest thing here to computation — and it still replays above cost
(95,579 used against 111,457). The transfers behave like every other ERC-20 transfer in this
survey.

This is the same shape as Sky and the Frax token rows: a token contract's transaction *is* its
state change. It is recorded for completeness, not because a token was ever a plausible
candidate.

## Snapshot — the vote is off-chain, so only the delegation record is here

Snapshot's voting is off-chain by design. Its entire mainnet surface is one contract, the
DelegateRegistry (`0x469788fE…`), with exactly two functions in 28 days: `setDelegate` (125
calls, ~46,900 gas) and `clearDelegate` (24 calls, ~24,300). That is **5.32 direct
transactions/day**.

Two measured, both 0.00%. `setDelegate` records **1 `Store` and 1 `Log4`** — one slot and one
event — for 46,927 gas used against a 55,776 replay cost. There is no computation on this chain
to remove because the computation (tallying votes) never happens on this chain. One transaction
stayed on the heuristic estimator and is excluded.

**An attribution split worth recording.** The first scan of "Snapshot delegate registries"
returned 745 transactions and 655 direct calls — 26.61/day, which would have made Snapshot one
of the busier protocols in this survey. It is wrong. Only 149 of those belong to Snapshot. The
other 506 belong to **delegate.xyz** (`0x0000…Bed493`), a different protocol that shares the
"delegate registry" description but not the codebase: its selectors are `delegateAll`,
`delegateERC721` and `delegateContract`, verified locally. Counting them as Snapshot would have
inflated its volume 4.4× and attributed 186,000-gas transactions to a protocol whose own
transactions are 24,000–47,000.

## delegate.xyz — measured in passing, and it fails the same way

Since the scan surfaced it, delegate.xyz was measured rather than discarded. It is a real
mainnet protocol at **18 direct transactions/day** — more than Snapshot, EAS and Aragon
combined — and considerably larger per transaction (124,000–204,000 gas).

Three measured, all 0.00%. Every one records **8 `Store`s and 1 `Log4`** and replays about
29,000 gas above cost. A delegation registry writes a delegation; that is the whole
transaction. It is the same structural negative as EAS, at a larger size. Two transactions
stayed on the heuristic estimator and are excluded.

## What this is actually worth in dollars

Every figure above is a percentage. Percentages were the wrong unit, and this section is
the correction. **At the gas prices prevailing when this was measured, the entire
opportunity across the three best protocols is roughly $2,600 per month.**

Measured 2026-09-02. Mainnet base fee was **0.15–0.35 gwei**, with blocks running
11–42M gas against a 60M limit — abundant spare capacity, so gas is nearly free.
ETH/USD $2,386, read from the Chainlink aggregator on-chain.

| protocol | best % | qualifying txs/day | gas saved each | **savings/month** | at 20 gwei |
|---|---:|---:|---:|---:|---:|
| Aave V3 | 59.61% | 555 | 107,000 | **$1,392** | $84,986 |
| Railgun | 78.72% | 106 | 854,737 | **$876** | $130,162 |
| Pyth | 28.01% | 29 | 54,614 | **$12** | $2,245 |
| | | | | **~$2,600** | **~$239,000** |

Note how the ranking inverts. Railgun has the best percentage by a wide margin and saves
*less money* than Aave, because Aave qualifies 5x more transactions per day. And Pyth —
the cleanest, most uniform, most reachable result in the survey — is worth twelve dollars
a month.

### The single most important sentence in this document

**The product's value is a leveraged bet on gas prices, not on the percentage saved.**

A 28% saving and an 80% saving are both worth approximately nothing at 0.15 gwei. The same
integrations are worth $103k and $134k a month at 20 gwei. Nothing about the engineering
changes between those two worlds; only the fee market does.

That reframes what the survey was for. Screening protocols by percentage — which is what
every section above does — optimises the wrong variable. The variables that actually move
the dollar figure are, in order:

1. **The fee market.** Two orders of magnitude, and entirely outside anyone's control.
2. **Qualifying transactions per day.** Aave beats Railgun on money while losing badly on
   percentage.
3. **Gas saved per transaction** — the absolute number, not the ratio.
4. The percentage, which is a *presentation* of #3 and carries no independent information.

### Method and caveats

Sampling: one 9,999-block window (~1.39 days) per protocol; all transaction hashes touching
the contract enumerated from its logs, then 180 sampled at random to establish what
fraction call the contract **directly** (the GasKiller-eligible ones) and the median
effective gas price actually paid. Extrapolated to 30 days.

- **An earlier version of this calculation undercounted Aave by 119x** by capping the hash
  scan at 400 and treating the survivors as the whole population. The figures above use
  full enumeration plus random sampling. Anyone re-running this should check the same trap.
- **Aave's inputs are the softest.** The 25% qualifying share and 130,000 gas saved per
  transaction are carried over from the earlier per-function work, not re-measured here.
  Railgun's 53% and 877,737 are from measured runs; Pyth's 100% and 54,614 are exact.
- A 180-transaction sample puts roughly ±7pp of uncertainty on each direct-call fraction.
- One ~1.4-day window extrapolated to a month will miss weekly and volatility-driven
  cycles. Gas spikes are exactly when the product is worth most, and a quiet window will
  understate the average.
- Gas fees are paid by whoever sends the transaction — borrowers, wallet users, price
  submitters — not by the protocol. Even where savings are large, they are the *users'*
  money, which affects who the counterparty in a deal actually is.

## Limitations

- **Opportunistic samples.** Railgun is the largest at 15 direct transactions from one 40,000-block window; the others are 7–20 transactions each. None is a systematic survey and none should be read as a population statistic.
- **Contract addresses came from web search, then were verified on chain.** For each protocol, event topic0 values and function selectors were matched against keccak hashes computed locally (pure-Python keccak, self-tested against the empty-string digest and the ERC-20 `Transfer` topic) before any conclusion was drawn. Unmatched selectors are named as unidentified rather than guessed.
- **Some transactions cannot be measured at all**, independent of rate limits: senders with EIP-7702 delegation designators are rejected by the simulator (`RejectCallerWithCode`), and some transactions reproducibly revert mid-replay. See `MORPHO_CANDIDATES.md`.
- **The prestate/net-form encoder was not exercised.** The CLI's `t` command uses the struct-log encoder. The net form collapses repeated writes to the same slot, which materially changes batched transactions — Ether.fi's `batchClaimWithdraw` has 65 struct-log stores but only 5 net changed slots. Everything measured here is the struct-log path.
- **Savings are the analyzer's cost model**, not on-chain outcomes; nothing was executed through a deployed GasKiller.
- **Some very large transactions cannot be measured.** Three Safe transactions (5.9M, 6.4M and 6.5M gas, each with 250–500 logs) produced empty analyzer output on every attempt, apparently a struct-log trace size limit. Size alone is not the trigger — an 11.4M-gas Safe transaction measured fine — but any survey weighted toward large batched transactions will be biased by this.
- **Aave's 25% traffic-share figure is a single-window estimate.** Direct-to-Pool borrows were 120 of 471 classified transactions in one 3,000-block window. Borrow share will vary with market conditions, and the 20 analyzed transactions are not a random sample of them — they were chosen to span the operation/reserve-count space.

## Appendix — every successfully measured transaction, by function

All 114 transactions that produced a number, labelled with the 4-byte selector actually present in their calldata.

A **✓** means the selector was confirmed by matching a locally computed keccak-256 hash of a candidate signature against the calldata prefix. An *italic* label was inferred from the transaction's emitted events only — the selector never matched any signature I could construct, and I did not decompile the callee. Treat those names as descriptions of observed effects, not verified function identities.

`heur` marks a heuristic fallback rather than a real `StateChangeHandler` replay; those figures are much softer.

| protocol | tx | function (4-byte) | gas used | GasKiller cost | Schnorr saved |
|---|---|---|---:|---:|---:|
| Railgun | [`0xaa357a48…`](https://etherscan.io/tx/0xaa357a4824001aed7173b3bc7d976f997fc7839def4c56ec070db97ec2121bc4) | `0xd8ae136a` *Railgun private transfer / unshield* | 1,085,832 | 181,095 | **854,737** (78.72%) |
| Railgun | [`0x32daef80…`](https://etherscan.io/tx/0x32daef80a0c5180dcf45b15130e10ecced485242f0d3305b30942ebeb5aec364) | `0xd8ae136a` *Railgun private transfer / unshield* | 1,056,246 | 197,859 | **808,387** (76.53%) |
| Railgun | [`0xe7e605b6…`](https://etherscan.io/tx/0xe7e605b6520aaf757f4531a88af4966866d86fee61ec06e93b3423b30a934adc) | `0xd8ae136a` *Railgun private transfer / unshield* | 1,615,755 | 317,840 | **1,247,915** (77.23%) |
| Railgun | [`0xa2177825…`](https://etherscan.io/tx/0xa21778257ba78ce1354a4ff25a48ee07854e5e858f4facfe3e3c3893d9a1945f) | `0xd8ae136a` *Railgun private transfer / unshield* | 1,561,573 | 312,286 | **1,199,287** (76.80%) |
| Railgun | [`0x73a1d71e…`](https://etherscan.io/tx/0x73a1d71e2cfa678b63c934c8c04eb6b6069de89c85faf16d0376241ecabfb0ec) | `0xd8ae136a` *Railgun private transfer / unshield* | 1,097,058 | 213,396 | **833,662** (75.99%) |
| Railgun | [`0xa3a010fa…`](https://etherscan.io/tx/0xa3a010fa890d910e669fba1ea7b681a4c1f464b754c5b7bff7d62ae15ae25e71) | `0xd8ae136a` *Railgun private transfer / unshield* | 1,113,545 | 241,625 | **821,920** (73.81%) |
| Railgun | [`0x04736806…`](https://etherscan.io/tx/0x04736806756593b664eb29591a2ea046b2261c5a4fa1bdd1707a6dc5abf54f07) | `0xd8ae136a` *Railgun private transfer / unshield* | 1,136,044 | 266,554 | **819,490** (72.14%) |
| Railgun | [`0x39a67a29…`](https://etherscan.io/tx/0x39a67a2964b675ccd1be1939c513b46f62cae71c3f320bece6acdaf71934b3ae) | `0xd8ae136a` *Railgun private transfer / unshield* | 1,131,080 | 266,430 | **814,650** (72.02%) |
| Railgun | [`0xaf36e218…`](https://etherscan.io/tx/0xaf36e2187e095fa88299a8859632963594414b716f36aae541318d4ce71740e6) | `0xd8ae136a` *Railgun private transfer / unshield* | 1,177,014 | 282,477 | **844,537** (71.75%) |
| Railgun | [`0x0376edd3…`](https://etherscan.io/tx/0x0376edd36b0c9211b1a38f41e5f1c04233478ca4dcf7d4852ef313deb1c57ade) | `0x044a40c3` `shield` ✓ | 724,515 | 168,652 | **505,863** (69.82%) |
| Railgun | [`0xab44777b…`](https://etherscan.io/tx/0xab44777b4e3a37169ea03163ec5d14dbf668bcb18219c3a95cc2313c2be55a3d) | `0x044a40c3` `shield` ✓ | 736,786 | 177,753 | **509,033** (69.09%) |
| Railgun | [`0x27ce0220…`](https://etherscan.io/tx/0x27ce022039ef027d473c61f3140da32c8e58f0a8daaee826e6f04a58744db447) | `0x044a40c3` `shield` ✓ | 742,727 | 185,294 | **507,433** (68.32%) |
| Railgun | [`0x3d54cfc3…`](https://etherscan.io/tx/0x3d54cfc375e626acd71432b2ab59a94bde2f6ee2490528ca8259417091e3ab97) | `0x044a40c3` `shield` ✓ | 752,878 | 197,812 | **505,066** (67.08%) |
| Railgun | [`0x6837bb8d…`](https://etherscan.io/tx/0x6837bb8d629ee0dce5f045acfc6c1e296df4abe1907897820bf621462dc23425) | `0x044a40c3` `shield` ✓ | 758,741 | 211,644 | **497,097** (65.52%) |
| Railgun | [`0x792a8e57…`](https://etherscan.io/tx/0x792a8e5783cec82cc456d83f0f1703a2bf71eafa05984a17896809bd952567cc) | `0xd8ae136a` *Railgun private transfer / unshield* | 484,303 | 139,722 | **294,581** (60.83%) |
| Railgun | [`0x6f534f5a…`](https://etherscan.io/tx/0x6f534f5af7fa26b66e0c6a5f49505f7125665e88b0d1af23efca86da88109f27) `heur` | `0x28223a77` *unidentified* | 1,297,603 | 1,287,231 | 0 |
| Railgun | [`0x7c731150…`](https://etherscan.io/tx/0x7c731150234add278ecae3ee9b6bcd35ee50435cc69bc47cce1a008e54c1f2ce) `heur` | `0x28223a77` *unidentified* | 1,120,780 | 1,116,659 | 0 |
| Railgun | [`0x2d754e6f…`](https://etherscan.io/tx/0x2d754e6f8a34058e5d07596e627cbc70e0c704279e9f745a4c0baef80389cca7) | `0x28223a77` *unidentified* | 523,496 | 533,777 | 0 |
| Aave | [`0xa7a8c34f…`](https://etherscan.io/tx/0xa7a8c34fee3795db241bcdf3e5c0b8b279dcb78f62ceee2f3530c9f38dd1ebec) | `0xa415bcad` `borrow` ✓ | 571,333 | 180,741 | **340,592** (59.61%) |
| Aave | [`0xa36db142…`](https://etherscan.io/tx/0xa36db1427faa3a36a7461bf00e80bc12bd07d9d7c87fbab54ee49bec92b9fec7) | `0xa415bcad` `borrow` ✓ | 450,205 | 163,828 | **236,377** (52.50%) |
| Aave | [`0x1b708eba…`](https://etherscan.io/tx/0x1b708eba95e753a84558374c488f1557907935272fabc2ffe91f6d8844c06370) | `0x69328dec` `withdraw` ✓ | 408,792 | 180,921 | **177,871** (43.51%) |
| Aave | [`0xa70a6bbd…`](https://etherscan.io/tx/0xa70a6bbd833f973defbcc4a0b1ad281f4708fa1960a39635d784a855a8fac9e1) | `0xa415bcad` `borrow` ✓ | 371,912 | 173,408 | **148,504** (39.93%) |
| Aave | [`0xc62d052c…`](https://etherscan.io/tx/0xc62d052c8385a546ab9f2f4d6a9fc194e45c3c9c7bf69e22454e38d9c55cb0cb) | `0xa415bcad` `borrow` ✓ | 360,781 | 170,263 | **140,518** (38.95%) |
| Aave | [`0xe73dcebf…`](https://etherscan.io/tx/0xe73dcebf75429339193a24c45a37e377948bf6f69fa77b8f50931d1e26ebeeea) | `0xa415bcad` `borrow` ✓ | 345,794 | 170,335 | **125,459** (36.28%) |
| Aave | [`0x000d4a32…`](https://etherscan.io/tx/0x000d4a32a076758c9ca1271e2909e2c4e1acaf988ff36ac8e8dc513f5fa64332) | `0xa415bcad` `borrow` ✓ | 365,438 | 181,716 | **133,722** (36.59%) |
| Aave | [`0x2cab2e0f…`](https://etherscan.io/tx/0x2cab2e0f215f22a30249a1198f6604bdcfcc131183aeaaa7c1257fb939ec239f) | `0xa415bcad` `borrow` ✓ | 346,272 | 206,699 | **89,573** (25.87%) |
| Aave | [`0xe65a59b9…`](https://etherscan.io/tx/0xe65a59b9f5d42dfd18018dd8c42850e6ea38c49d4a61718888c072e4f13dcc77) | `0xa415bcad` `borrow` ✓ | 316,682 | 205,592 | **61,090** (19.29%) |
| Aave | [`0xb33162e1…`](https://etherscan.io/tx/0xb33162e1275b4e14a4a0de3d327949fb520949cadd898d17718bb813547ca0fb) | `0xa415bcad` `borrow` ✓ | 252,529 | 164,712 | **37,817** (14.98%) |
| Aave | [`0xeff004bd…`](https://etherscan.io/tx/0xeff004bd1fb2851258ac5aa69997def87176f40716ecd4fe3d68904e1d6c3669) `heur` | `0x69328dec` `withdraw` ✓ | 211,120 | 160,699 | **421** (0.20%) |
| Aave | [`0x9287f808…`](https://etherscan.io/tx/0x9287f80894eeeacc8af236609401da9f14ce0e655cbb9748e0db2e405aeb2ef5) | `0x7e809076` *third-party liquidator bot* | 1,165,207 | 1,156,574 | 0 |
| Aave | [`0x324633c1…`](https://etherscan.io/tx/0x324633c1f5cf10b86a58aad0d48ac39673afd6ee24e2b391488ac84e4c6baaa0) | `0x02c205f0` `supplyWithPermit` ✓ | 206,695 | 207,356 | 0 |
| Aave | [`0x4eba5f8d…`](https://etherscan.io/tx/0x4eba5f8de29afdcac5703668d41a1f4bee734545dcdb37a129c6341b41c6ea44) | `0x617ba037` `supply` ✓ | 183,352 | 178,041 | 0 |
| Aave | [`0x9905c35e…`](https://etherscan.io/tx/0x9905c35e963d0c36e66b33d6f2319085daebf2920a8572ce26c01e201d0bbc16) | `0x69328dec` `withdraw` ✓ | 183,126 | 166,710 | 0 |
| Aave | [`0x52b373f5…`](https://etherscan.io/tx/0x52b373f5701425f48c42e3779527b6b7da51e7c764317c07cb40446377113649) | `0x02c205f0` `supplyWithPermit` ✓ | 179,856 | 179,187 | 0 |
| Aave | [`0xe41dd331…`](https://etherscan.io/tx/0xe41dd331b63a80add54ec1ef340f252c623538cfe35b69a65b190651aa636691) | `0x69328dec` `withdraw` ✓ | 167,589 | 160,020 | 0 |
| Aave | [`0x7f281bd6…`](https://etherscan.io/tx/0x7f281bd663289348bccaeb5c1616459ab424f557a65eaebfb603a1d445267ad4) | `0x617ba037` `supply` ✓ | 155,576 | 150,490 | 0 |
| Aave | [`0x055c232c…`](https://etherscan.io/tx/0x055c232ce489f003f64d5f05a5f77706c8a282f921d60a4264b5eeb21a6c6736) | `0x617ba037` `supply` ✓ | 147,675 | 142,925 | 0 |
| Aave | [`0x6b7563d1…`](https://etherscan.io/tx/0x6b7563d1e117aa90cc1e65b19b10ee525da3bdc89a26d0498a2a7084ab7867b1) | `0x573ade81` `repay` ✓ | 144,130 | 142,631 | 0 |
| Privacy Pools | [`0xe894abc7…`](https://etherscan.io/tx/0xe894abc79ca19fae8e3ef2a98b9570da0037d6f47ce531351002770d16ffe11f) | `0x30c0766d` `withdraw` ✓ | 587,069 | 422,768 | **114,301** (19.47%) |
| Privacy Pools | [`0x67deaa0e…`](https://etherscan.io/tx/0x67deaa0e50f0db65925f464c05168927db7ce336079334100aba5cdbeb701e64) | `0x30c0766d` `withdraw` ✓ | 576,177 | 430,907 | **95,270** (16.53%) |
| Privacy Pools | [`0x15082298…`](https://etherscan.io/tx/0x150822981204592e4cfa340ba2e63e607a1c6ded490b988f9a8bd37c1f2b46d0) | `0x8a44121e` `relay` ✓ | 620,208 | 632,053 | 0 |
| Privacy Pools | [`0x03ebad9a…`](https://etherscan.io/tx/0x03ebad9a10bc3dc5ad36613de80975b7ee8061d7fa74367f1a9aa04e77cc1524) | `0x8a44121e` `relay` ✓ | 604,245 | 616,114 | 0 |
| Privacy Pools | [`0xad4ac41d…`](https://etherscan.io/tx/0xad4ac41d7ad3ba9792d7c426631dba0d46a31e271f5105dbb6aa6df349c891a5) | `0x8a44121e` `relay` ✓ | 604,233 | 616,066 | 0 |
| Privacy Pools | [`0x4d8f00ee…`](https://etherscan.io/tx/0x4d8f00ee277c67f95049a43dfe604418d0a408fed40a6473bd5b154045c2e2e2) | `0x8a44121e` `relay` ✓ | 577,042 | 588,768 | 0 |
| Privacy Pools | [`0x2766c992…`](https://etherscan.io/tx/0x2766c992f22f5aec9bdfc1f16e394d4c4ed6b996bd002f64235b5234e9269cd2) | `0x8a44121e` `relay` ✓ | 558,846 | 571,008 | 0 |
| Privacy Pools | [`0x53e6375e…`](https://etherscan.io/tx/0x53e6375e0156f40d6917e8d48d26f0af6e1fd197d54d0042b96138dfc449660f) | `0x0efe6a8b` `deposit` ✓ | 393,615 | 402,757 | 0 |
| Privacy Pools | [`0x46a8ff4b…`](https://etherscan.io/tx/0x46a8ff4b10a52df709860a908f1749cd66523b5e6a3b18e7eeb901f8b7cd97eb) | `0xb6b55f25` `deposit` ✓ | 381,540 | 387,061 | 0 |
| Privacy Pools | [`0xb120146b…`](https://etherscan.io/tx/0xb120146b4dd84f30f7c44cfb6f9fb5fca7c0b10f051a6259edd5c5c7b40d9da6) | `0x71235b34` `ragequit` ✓ | 279,732 | 287,612 | 0 |
| Privacy Pools | [`0x0b27aa2c…`](https://etherscan.io/tx/0x0b27aa2ce30ee4e0f9e34a3f28537115d38c5a5fd499937b04fe437cfa3537f8) | `0x87bf00f0` `updateRoot` ✓ | 149,961 | 163,803 | 0 |
| Ether.fi | [`0xab780dc7…`](https://etherscan.io/tx/0xab780dc7c7c59d079462a88428b4e172c84a05eeec892195a02787a856214583) | `0x2e03931e` *EtherFiAdmin oracle-report execution* | 259,254 | 208,906 | **235,906** (23348.00%) |
| Ether.fi | [`0xdce4440b…`](https://etherscan.io/tx/0xdce4440b1e1cd6ae69eaa3331085bcbe38c6ab23c8d53401f7c49c63d7ec06ce) `heur` | `0x24fccdcf` `batchClaimWithdraw` ✓ | 205,965 | 174,295 | **201,295** (4670.00%) |
| Ether.fi | [`0xc3081e6f…`](https://etherscan.io/tx/0xc3081e6f850f214a3df7ccf069f0233a4d07fd08fede69f3e904c45e644789cf) | `0x146ee74d` *third-party aggregator* | 4,904,702 | 4,956,803 | **4,983,803** (0.00%) |
| Ether.fi | [`0x87b26753…`](https://etherscan.io/tx/0x87b26753364ee01e9c442fbf5c2a37443f28e00d3e34591cd4a9147611fe4eb7) | `0x24fccdcf` `batchClaimWithdraw` ✓ | 679,714 | 878,853 | **905,853** (0.00%) |
| Ether.fi | [`0x7ee0a346…`](https://etherscan.io/tx/0x7ee0a34642b5380eea636f02ce6ee35f109390a95bd2d19b8ff1794512829bb1) | `0x397a1b28` `requestWithdraw` ✓ | 193,099 | 198,205 | **225,205** (0.00%) |
| Ether.fi | [`0x4964cf5a…`](https://etherscan.io/tx/0x4964cf5adfaaf0e7d0d48d4cd2cc02bf792493653550293dbb22aa7909a18eda) | `0x397a1b28` `requestWithdraw` ✓ | 193,075 | 198,133 | **225,133** (0.00%) |
| Ether.fi | [`0xd6ec9fc5…`](https://etherscan.io/tx/0xd6ec9fc5c359167794fd0c692b578a346ae978b73ed8dc503aa5e6350ed84b63) | `0xb13acedd` `claimWithdraw` ✓ | 153,292 | 144,419 | **171,419** (0.00%) |
| Ether.fi | [`0xd14eb830…`](https://etherscan.io/tx/0xd14eb830b3308feb3dee287e11752e9400d4aaf8b1c85cacb04d1ef9321a2a84) | `0xea598cb0` `wrap` ✓ | 134,730 | 130,194 | **157,194** (0.00%) |
| Ether.fi | [`0x2cc9a112…`](https://etherscan.io/tx/0x2cc9a112936e0cfda1b4e9afd88ac5a861f2392cb9e20d2598f255a509b6d929) | `0xde0e9a3e` `unwrap` ✓ | 122,474 | 117,487 | **144,487** (0.00%) |
| Ether.fi | [`0xbe33787e…`](https://etherscan.io/tx/0xbe33787eb89c203cacaee0fb05da574bfef9c0aef4b80bcd8eed779a57f86222) | `0xd0e30db0` `deposit` ✓ | 120,178 | 128,056 | **155,056** (0.00%) |
| Safe | [`0xa9eca9f1…`](https://etherscan.io/tx/0xa9eca9f1a7075c8eb971e7ee2a1a3ee514cf3cf6b1077d6ddcc4f60f8ebf4eaa) | `0x6a761202` `execTransaction` ✓ | 104,612 | 67,158 | **0** (0.00%) |
| Safe | [`0x5c559278…`](https://etherscan.io/tx/0x5c5592787da61ec8c46326d93089c14e667276fab45703077168e72dcbbee99e) | `0x6a761202` `execTransaction` ✓ | 115,958 | 78,540 | **0** (0.00%) |
| Safe | [`0x8951b058…`](https://etherscan.io/tx/0x8951b058f41486ff7d9c5806d187af52f7d969ae69ddbb85c1e1be04171dae04) | `0x6a761202` `execTransaction` ✓ | 3,251,629 | 3,220,361 | **0** (0.00%) |
| Safe | [`0xf20b6df4…`](https://etherscan.io/tx/0xf20b6df4702b6537ba520316a35552b6d1da7b696e3c69e34986ed901402bd56) | `0x6a761202` `execTransaction` ✓ | 11,414,223 | 11,400,916 | 0 |
| Safe | [`0xdcc894ec…`](https://etherscan.io/tx/0xdcc894ec22dc799bd1cd8c24caa4bcd2a2d7f35ae2ba8ab7c431a07f76e5ba21) | `0x6a761202` `execTransaction` ✓ | 1,004,511 | 1,005,210 | 0 |
| Safe | [`0xb286eeb1…`](https://etherscan.io/tx/0xb286eeb15c4cb3445a73e275e89336f7563eb46c2e9ec97a82aeefb5a4485430) | `0x6a761202` `execTransaction` ✓ | 463,470 | 442,944 | 0 |
| Safe | [`0x4e13a401…`](https://etherscan.io/tx/0x4e13a40100c52346b4e971697a347030ffd0cc5bd47d521e8b4a9baf1a984872) | `0x6a761202` `execTransaction` ✓ | 458,625 | 452,215 | 0 |
| Safe | [`0x5688590b…`](https://etherscan.io/tx/0x5688590bc26e704d720d7bb2185b195aabb310ba67dddd944f64509b1cf70513) | `0x6a761202` `execTransaction` ✓ | 322,338 | 297,128 | 0 |
| Safe | [`0xf6ebba6b…`](https://etherscan.io/tx/0xf6ebba6ba0e5e5f003598b5e05efbb737fb5e00e6a1818e58d1e565316f96b74) | `0x6a761202` `execTransaction` ✓ | 214,221 | 202,578 | 0 |
| Safe | [`0x909681b5…`](https://etherscan.io/tx/0x909681b5131c5ccc56e6f6791f152efe41cf270172c5a4645fc0067567bd8651) | `0x6a761202` `execTransaction` ✓ | 103,575 | 85,519 | 0 |
| Safe | [`0x2666f99a…`](https://etherscan.io/tx/0x2666f99a3b1ad225cf8dcc40fbafb1959a6efb5bb3c561b3d2d5a3b242ca4a29) | `0x6a761202` `execTransaction` ✓ | 96,660 | 73,351 | 0 |
| Safe | [`0xb2b17e51…`](https://etherscan.io/tx/0xb2b17e51681c60f3d66aa112fa13f070c5ea76c466e794e3ba360c8b833b5a55) | `0x6a761202` `execTransaction` ✓ | 75,536 | 70,129 | 0 |
| Pendle | [`0x75aceefb…`](https://etherscan.io/tx/0x75aceefb54f607c4de446308146e0b84ff405ec56a6e5bc24ccb88b3b5397991) | `0xc685f647` *third-party aggregator* | 1,719,271 | 1,624,535 | **44,736** (2.60%) |
| Pendle | [`0xa2c6de73…`](https://etherscan.io/tx/0xa2c6de73e89c7bd707a9fe308d09c54eb16d2ddf9e3ff09f866d8a68e3948afd) | `0xc685f647` *third-party aggregator* | 1,183,159 | 1,157,967 | 0 |
| Pendle | [`0x8bd2985a…`](https://etherscan.io/tx/0x8bd2985af25143dbf0d3aa60f0e36bc50195d2702e4beeaf1576f8f4464200d7) | `0x60fc8466` *Pendle router action* | 1,018,948 | 1,020,097 | 0 |
| Pendle | [`0xa01ba5b6…`](https://etherscan.io/tx/0xa01ba5b6e8c9f78e7d4d324bd2b03da78a7d02cdf9fa852aa82b60dc400a586c) | `0xed48907e` *Pendle router action* | 768,674 | 762,631 | 0 |
| Pendle | [`0x90476689…`](https://etherscan.io/tx/0x9047668966adcd340cf4b69b727a17c5df6c6f34d4bad1994f9cf5331e2329f7) | `0xed48907e` *Pendle router action* | 531,449 | 524,603 | 0 |
| Pendle | [`0xa3ec8aea…`](https://etherscan.io/tx/0xa3ec8aea5dd4b01271f7dd979830a444ec2b3fa618f5e0afc550a2bd03af65a3) | `0xed48907e` *Pendle router action* | 370,167 | 359,084 | 0 |
| Pendle | [`0xec4d1fdf…`](https://etherscan.io/tx/0xec4d1fdf22d55bdde9d358e329af22a6c3345032ce969c79afb9d5dea8487556) | `0x594a88cc` *Pendle router action* | 205,329 | 213,408 | 0 |
| Pendle | [`0xc503cb6f…`](https://etherscan.io/tx/0xc503cb6f653908693bc666cf764b7fbd18d25d1f2982bde550107e98c81559a0) | `0x5b709f17` `swapSyForExactPt` ✓ | 153,140 | 148,995 | 0 |
| World ID | [`0xa447c2d3…`](https://etherscan.io/tx/0xa447c2d3d0786a32f8b23c0f571e714e91d4d812b575d7bee27864c7c3e8c556) | `0x2217b211` `registerIdentities` ✓ | 298,629 | 263,051 | **0** (0.00%) |
| World ID | [`0x36c09544…`](https://etherscan.io/tx/0x36c095445eb96f2ccaa2a2ec9544ac2cf72aa524c36c0ce23c0aecc2cf36b8b7) | `0x2217b211` `registerIdentities` ✓ | 285,261 | 263,075 | 0 |
| World ID | [`0x6b2fb8d3…`](https://etherscan.io/tx/0x6b2fb8d32c1fc927e5c37ae0ca52d17cb122b949ec0140f75a8212164911f494) | `0x2217b211` `registerIdentities` ✓ | 282,573 | 263,039 | 0 |
| World ID | [`0xb2f5ba58…`](https://etherscan.io/tx/0xb2f5ba588077025662acd44f62ead62c4dc6da4faa30890d658542aedcaef3c5) | `0x2217b211` `registerIdentities` ✓ | 281,457 | 263,051 | 0 |
| World ID | [`0xcd404a27…`](https://etherscan.io/tx/0xcd404a27462a9e60fdd5a17c024d758d809f860ad2da9f1709882d497276375a) | `0x2217b211` `registerIdentities` ✓ | 281,445 | 263,051 | 0 |
| World ID | [`0x04ca8194…`](https://etherscan.io/tx/0x04ca81943592e11ddbce6e4fac96c0f84debb12c8d972bd3f910dc8bf77274de) | `0xea10fbbe` `deleteIdentities` ✓ | 271,876 | 263,087 | 0 |
| World ID | [`0x2fee0848…`](https://etherscan.io/tx/0x2fee084888a10a8cf80c30b36bf511e8ba499e517d49dbc0ca2a97d4c4e160e6) | `0xea10fbbe` `deleteIdentities` ✓ | 271,816 | 263,075 | 0 |
| Morpho | [`0x80329618…`](https://etherscan.io/tx/0x80329618f5c5261829097e2a8a079c765c6ae0ce35f6d98e09a4d246a694c8bf) | `0xac9650d8` `multicall` ✓ | 380,049 | 343,154 | **0** (0.00%) |
| Morpho | [`0x4e547494…`](https://etherscan.io/tx/0x4e547494fcf332b50465117a6467c8cb097787e4b54fd5b97ff6ff5cfec96ceb) | `0x642ba7a7` *flash-loan leverage* | 1,779,190 | 1,720,040 | **9,150** (0.51%) |
| Morpho | [`0x16a0a31c…`](https://etherscan.io/tx/0x16a0a31c0547f2f35018c38f0c2fa3bdcf1320e6a75f998caaa957747e9dc568) `heur` | `0x2f5066dd` *flash-loan deleverage* | 1,312,558 | 1,577,595 | 0 |
| Morpho | [`0xb1bf36be…`](https://etherscan.io/tx/0xb1bf36beaf1aeeb69e575a1230468d917ef4646c6416ab465201bca70d8c7a72) | `0xac9650d8` `multicall` ✓ | 1,278,050 | 1,457,568 | 0 |
| Morpho | [`0x1c71eb76…`](https://etherscan.io/tx/0x1c71eb76549cc6a80467e06e8bc938b7fc1e67e9575c2aece8d98345243bb218) | `0xeb7499cf` *9-market reallocation* | 725,295 | 699,768 | 0 |
| Morpho | [`0x09fd0f6e…`](https://etherscan.io/tx/0x09fd0f6eb66388ce7cdc484b2020d300b5c6d519df89c5bddc73307d9e68bd80) `heur` | `0x1a28e979` *liquidator bot* | 619,024 | 733,358 | 0 |
| Morpho | [`0x9a08a526…`](https://etherscan.io/tx/0x9a08a526e05f5fe827840f0ec4e3d1ce31906fa5a7a9bda7677098e4d78903df) `heur` | `0x03f00196` *flash-loan MEV bot* | 420,293 | 414,721 | 0 |
| Morpho | [`0xbeffded8…`](https://etherscan.io/tx/0xbeffded8df725752edea428f171d8ec2a842dcdb645977ea9cf5bedba14ca414) | `0x7299aa31` `reallocate` ✓ | 416,744 | 451,366 | 0 |
| Morpho | [`0x1338ba16…`](https://etherscan.io/tx/0x1338ba16b0a7f61988caf43896fde0e32edac97cd7dab32bb6136bf9e77f0302) | `0x99999999` *flash-loan MEV bot* | 405,201 | 423,289 | 0 |
| Morpho | [`0xe520cf76…`](https://etherscan.io/tx/0xe520cf761e3fd61b115b0f31bd7f182a9cce43ec747b1aeaf77bf3457ebdc91f) | `0xac9650d8` `multicall` ✓ | 366,689 | 393,924 | 0 |
| Morpho | [`0x3dffb38b…`](https://etherscan.io/tx/0x3dffb38b03f52c07073a0ad32f336c5d3106640c2462f72204c9d6fe02534ed1) | `0xac9650d8` `multicall` ✓ | 360,323 | 371,754 | 0 |
| Morpho | [`0xcd59750e…`](https://etherscan.io/tx/0xcd59750e91859ec6af4209c588997b61962dcec2aad6c549ef35324476870bdf) | `0x7299aa31` `reallocate` ✓ | 324,608 | 349,625 | 0 |
| Morpho | [`0x8e4616ac…`](https://etherscan.io/tx/0x8e4616acfaf812a41b471e139924a1bc906e03e8e1203760ae6117113682b760) | `0xac9650d8` `multicall` ✓ | 312,814 | 314,184 | 0 |
| Morpho | [`0x50305a21…`](https://etherscan.io/tx/0x50305a216cbeabbc02ad2262619090e91c6928ecc30def46af4eaab7bde99e9b) | `0xac9650d8` `multicall` ✓ | 179,644 | 183,470 | 0 |
| Morpho | [`0x8d0c4018…`](https://etherscan.io/tx/0x8d0c40187a36dd2de2b64800b87d8db9b235624479d35202a11c2b2fb98fd76a) | `0xac9650d8` `multicall` ✓ | 157,756 | 161,582 | 0 |
| Morpho | [`0xdc74e020…`](https://etherscan.io/tx/0xdc74e020e296fbb968edfc2ffd630bad47d557c71dabe901938315be6329c5c9) `heur` | `0x374f435d` *router* | 134,366 | 148,620 | 0 |
| Morpho | [`0x441cd851…`](https://etherscan.io/tx/0x441cd85183e88986305c0721c98bdd3c25edbe5ecc4578baeb964f09b8b42686) | `0x8720316d` `withdrawCollateral` ✓ | 132,478 | 158,129 | 0 |
| Morpho | [`0x2d7cebfe…`](https://etherscan.io/tx/0x2d7cebfe726192fe692ccfa905b401fdedb108f5a3ecdf34aff20d2e77b3c320) `heur` | `0x374f435d` *router* | 122,812 | 126,798 | 0 |
| Morpho | [`0x4419f117…`](https://etherscan.io/tx/0x4419f1176b254fa8b1f0cb0daa7093b223379894701addb921fa02f00f373f8d) | `0x5c2bea49` `withdraw` ✓ | 111,792 | 142,279 | 0 |
| Morpho | [`0x8a27bff6…`](https://etherscan.io/tx/0x8a27bff6e7606ee0f89b63f01241c1a6a8d5cff37d726ee413df165b243c2f64) | `0xa99aad89` `supply` ✓ | 99,912 | 130,941 | 0 |
| Chainlink | [`0xff646682…`](https://etherscan.io/tx/0xff6466828843a8e795e4b6ae1b29644a148141dd48784b4be99c58b0ad3be268) | `0x6fadcf72` `forward` ✓ | 716,016 | 718,282 | 0 |
| Chainlink | [`0x6fc803ec…`](https://etherscan.io/tx/0x6fc803ecc426f8d20c9bcbdcc6c8118a1d8f22395a9702a7145fd7586adf4d80) | `0x6fadcf72` `forward` ✓ | 183,165 | 185,665 | 0 |
| Chainlink | [`0x0937e5c9…`](https://etherscan.io/tx/0x0937e5c9c7070b119608b28b836efc1c435ce7327f78ff00fff7fcc9ac1eef5f) | `0x6fadcf72` `forward` ✓ | 182,433 | 184,933 | 0 |
| Chainlink | [`0x973a53f5…`](https://etherscan.io/tx/0x973a53f585cbf82e951c96c24b58f1639a88f2935e6964ef4ac084ea10fcd278) | `0x6fadcf72` `forward` ✓ | 145,183 | 147,547 | 0 |
| Chainlink | [`0x9da346d0…`](https://etherscan.io/tx/0x9da346d0b79f055e1ac769f289ec0d449c4a20711c86300fa9230e817e069c95) | `0x6fadcf72` `forward` ✓ | 145,015 | 147,379 | 0 |
| Chainlink | [`0x4b8d2ac4…`](https://etherscan.io/tx/0x4b8d2ac44a640f4ce2b9fb274f5d1e3760ca324395aeaa3774190e99e41a10c9) | `0x6fadcf72` `forward` ✓ | 136,406 | 138,725 | 0 |
| Chainlink | [`0xf200bdfd…`](https://etherscan.io/tx/0xf200bdfd609fdb4228a02f6279e2968da2fc4c27590a3eadf5371843c5b5c6d0) | `0x6fadcf72` `forward` ✓ | 136,394 | 138,713 | 0 |
| Chainlink | [`0xa676c243…`](https://etherscan.io/tx/0xa676c24374af6324558937b595e3a94fca0fb817823fd22a24ea0f783ebffc6c) | `0x6fadcf72` `forward` ✓ | 136,046 | 138,365 | 0 |

### Verified signatures in full

Selectors above marked ✓, with the signature whose keccak hash matched:

| 4-byte | signature |
|---|---|
| `0x02c205f0` | `supplyWithPermit(address,uint256,address,uint16,uint256,uint8,bytes32,bytes32)` |
| `0x044a40c3` | `shield(((bytes32,(uint8,address,uint256),uint120),(bytes32[3],bytes32))[])` |
| `0x0efe6a8b` | `deposit(address,uint256,uint256)` |
| `0x2217b211` | `registerIdentities(uint256[8],uint256,uint32,uint256[],uint256)` |
| `0x24fccdcf` | `batchClaimWithdraw(uint256[])` |
| `0x30c0766d` | `withdraw((address,bytes),(uint256[2],uint256[2][2],uint256[2],uint256[8]))` |
| `0x397a1b28` | `requestWithdraw(address,uint256)` |
| `0x573ade81` | `repay(address,uint256,uint256,address)` |
| `0x5b709f17` | `swapSyForExactPt(address,uint256,bytes)` |
| `0x5c2bea49` | `withdraw((address,address,address,address,uint256),uint256,uint256,address,address)` |
| `0x617ba037` | `supply(address,uint256,address,uint16)` |
| `0x69328dec` | `withdraw(address,uint256,address)` |
| `0x6a761202` | `execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)` |
| `0x6fadcf72` | `forward(address,bytes)` |
| `0x71235b34` | `ragequit((uint256[2],uint256[2][2],uint256[2],uint256[4]))` |
| `0x7299aa31` | `reallocate(((address,address,address,address,uint256),uint256)[])` |
| `0x8720316d` | `withdrawCollateral((address,address,address,address,uint256),uint256,address,address)` |
| `0x87bf00f0` | `updateRoot(uint256,string)` |
| `0x8a44121e` | `relay((address,bytes),(uint256[2],uint256[2][2],uint256[2],uint256[8]),uint256)` |
| `0xa415bcad` | `borrow(address,uint256,uint256,uint16,address)` |
| `0xa99aad89` | `supply((address,address,address,address,uint256),uint256,uint256,address,bytes)` |
| `0xac9650d8` | `multicall(bytes[])` |
| `0xb13acedd` | `claimWithdraw(uint256)` |
| `0xb6b55f25` | `deposit(uint256)` |
| `0xd0e30db0` | `deposit()` |
| `0xde0e9a3e` | `unwrap(uint256)` |
| `0xea10fbbe` | `deleteIdentities(uint256[8],bytes,uint256,uint256)` |
| `0xea598cb0` | `wrap(uint256)` |

### Selectors that could not be identified

Present in measured transactions but never matched. Labels in the table come from emitted events:

- `0x03f00196` — flash-loan MEV bot (from `FlashLoan`)
- `0x146ee74d` — third-party aggregator
- `0x1a28e979` — liquidator bot (from `Liquidate`)
- `0x28223a77` — Railgun RelayAdapt entry point; its first inner call is `0xd8ae136a` on the smart wallet, i.e. it wraps the same operation the direct transactions perform
- `0x2e03931e` — EtherFiAdmin oracle-report execution (from `Rebase`)
- `0x2f5066dd` — flash-loan deleverage (from events)
- `0x374f435d` — router (from events)
- `0x594a88cc` — Pendle router action
- `0x60fc8466` — Pendle router action
- `0x642ba7a7` — flash-loan leverage (from events)
- `0x7e809076` — third-party liquidator bot
- `0x99999999` — flash-loan MEV bot (from `FlashLoan`)
- `0xc685f647` — third-party aggregator
- `0xd8ae136a` — Railgun private transfer / unshield (from `Nullified`+`Unshield`)
- `0xeb7499cf` — 9-market reallocation (from events)
- `0xed48907e` — Pendle router action

