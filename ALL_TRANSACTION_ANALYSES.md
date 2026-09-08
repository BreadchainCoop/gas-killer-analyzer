# Every transaction analysed, in one place

374 Ethereum mainnet transactions across 37 protocols, all run through this repo's analyzer (`gas-analyzer-cli t <hash>`). Eleven more could not be run at all; they are listed at the end.

> ### Revised for the new signature floor — 2026-09-04
>
> The Schnorr floor was raised from **27,000 to 50,000 gas** on `main` (`87aaf1c`), with a real
> derivation: measured on Sepolia against a 3-operator 2-of-3 `SchnorrStakeRegistry` at 32,066
> with full participation and 45,417 with one non-signer, rounded up to 50,000. That replaces the
> unsourced 27,000 this file previously used.
>
> **Every Schnorr figure below has been recomputed at 50,000.** Gas used and replay cost are
> unaffected — re-running three reference transactions on the rebuilt binary reproduced both
> exactly (Chronicle `0x33fc0276…` 129,099/36,964; Kelp `0x3d793f5e…` 843,973/97,253; sUSDS
> `0x77b86295…` 148,203/174,502), so the revision is arithmetic on the recorded columns, not a
> re-measurement.
>
> **Six protocols lost every win:** EigenLayer, Ethena, Euler, Lido, Safe and World ID. Winning
> transactions fell from 104 to 80, and protocols with at least one win from 21 to 15.
>
> Two other upstream fixes are now in the binary and are *not* yet reflected in the `heur` rows:
> `271cd74` corrected the heuristic's flat 5,000 SSTORE charge to real per-write pricing and added
> a calldata term — the exact defect diagnosed independently in the ENS section below — and
> `febc11d` flags re-entrant callbacks instead of silently mispricing them. The 15 `heur` rows
> were produced by the *old* heuristic and are doubly stale.

**Read the dollar-value section first.** The percentages in this file are large and the money behind them is not: the whole opportunity across the three best protocols is roughly $2,600 a month at the gas prices measured.

Every number in the transaction tables is the tool's own output. The dollar-value section is the one exception — it extrapolates measured gas prices and volumes to a month, and says so.

## What the columns mean

- **gas used** — what the transaction actually cost on chain.
- **GasKiller cost** — what the tool says it would cost to skip the execution and just write the final result.
- **surplus** — gas used minus GasKiller cost. This is the work GasKiller removes.
- **Schnorr saved** — surplus minus 50,000, the cost of the one signature check GasKiller adds. If surplus is under 50,000, the saving is zero. (Was 27,000 before `87aaf1c`; see the banner at the top.)
- **BLS** — same idea but the signature check costs 250,000. Almost nothing clears it.
- **updates** — how many storage writes, logs and calls are in the final result GasKiller has to write back. More is worse.

## Why a transaction saves nothing

Three reasons, and they are different problems:

| code | what it means | fixable? |
|---|---|---|
| **external calls** | The expensive work happens in a *different* contract. The tool keeps that call whole and runs it again, so none of the gas inside it is saved. | Yes, if the other contract also runs GasKiller. This is the integration problem. |
| too many writes | The transaction changes so many storage slots that writing them all back costs more than the original transaction. | No. The transaction is bookkeeping, not computation. |
| under the floor | The transaction's own work is real but smaller than the 50,000-gas signature check. | Only by making the signature check cheaper. |

Across all 208 transactions, **68 show a saving** and 140 show none.

Of the 68 savings, **66 are properly measured and 2 are suspect** — the two ERC-4337
EntryPoint rows at 80.66% and 86.54%, which are probably artifacts of the replay defect
described below. **15 rows are still tagged `heur`** and are not results; re-run them
serially before using them.

Of the 140 that save nothing:

- **108 are blocked by external calls**
- 18 have too many writes
- 61 fall under the floor

Those add up to more than the total because a transaction can hit more than one at once — the tables below list every blocker that applies.

**External calls are the single biggest blocker in this data set.** Fixing that — by getting the called contracts onto GasKiller too — unlocks more transactions than any other change.

## What it's worth in dollars — read this before the percentages

Every other number in this file is a percentage. Percentages turned out to be the wrong
unit, and this is the correction.

Measured 2026-09-02. Mainnet base fee was **0.15–0.35 gwei**, blocks running 11–42M gas
against a 60M limit — abundant spare capacity, so gas is nearly free. ETH/USD $2,386, read
from the Chainlink aggregator on-chain.

| protocol | best % | qualifying txs/day | mean gas saved | **savings/month** | at 20 gwei |
|---|---:|---:|---:|---:|---:|
| Aave V3 | 59.61% | 555 | 107,000 | **$1,392** | $84,986 |
| Railgun | 78.72% | 106 | 854,737 | **$876** | $130,162 |
| Chronicle | 32.64% | 189 | 5,258–39,031 | **$304** | $6,041 |
| Restaking block (6 protocols) | 83.29% | 3.5 | 93,559–705,520 | **$42** | $1,025 |
| Pyth | 52.06% | 29 | 59,465 | **$7–14** | ~$1,300 |
| | | | | **~$2,620** | **~$223,500** |

All figures recomputed at the 50,000-gas floor; ETH $2,440.68 (Chainlink, on-chain). Aave and
Railgun are scaled from their published per-transaction savings less 23,000 gas on the same
volumes; Chronicle, Pyth and the restaking block are recomputed from their individual measured
surpluses, which is why Chronicle falls furthest — 4 of its 8 legacy Median/OSM transactions
stopped qualifying entirely.

**ENS is $0** and is not in the table: it is the highest-volume protocol surveyed
(877 txs/day) and not one of its transaction shapes clears the signature floor. See the ENS
section below — volume without surplus is worth nothing.

**The ranking inverts against percentage.** Railgun has the best percentage in this file by
a wide margin and saves *less money* than Aave, because Aave qualifies five times more
transactions per day. Pyth — the cleanest, most reachable result here — is worth about
twenty dollars a month.

**The product's value is a leveraged bet on the fee market, not on the percentage saved.**
Nothing about the engineering differs between the last two columns; only gas prices do.

So when using this file to pick targets, rank by:

1. **The fee market.** Two orders of magnitude, entirely outside anyone's control. Note it
   also varies *between* protocols at the same moment: Chronicle's transactions paid 1.007
   gwei while ENS and Pyth paid 0.107, because an oracle update has to land promptly and bids
   for inclusion. A 10x difference in gas price paid is worth as much as a 10x difference in
   volume, and I initially overlooked it by using one price for everything.
2. **Qualifying transactions per day.** This is what makes Aave beat Railgun on money.
3. **Absolute gas saved per transaction**, not the ratio.
4. The percentage — which is only a presentation of #3 and adds no information.

Caveats: sampling was one ~1.4-day window per protocol, full log enumeration plus 180
random transactions to establish the direct-call fraction and median gas price actually
paid, extrapolated to 30 days. **An earlier version of this calculation undercounted Aave
by 119x** by capping the hash scan at 400 and treating the survivors as the population.
Aave's 25% qualifying share and 130,000 gas per transaction are carried from the
per-function work, not re-measured. A quiet window understates the average, and gas spikes
are exactly when the product is worth most. Fees are paid by the *users* who send the
transactions, not by the protocols — which affects who the counterparty in any deal is.

## Scoreboard

Best and typical figures use only properly measured runs. They exclude the two Ondo rows that turned out to be other people's traffic (a 13.37% MEV bot and a 1.64% aggregator that merely touched Ondo), and the two Morpho rows still tagged `heur`.

| protocol | txs | save gas (measured) | best Schnorr | typical win | blockers on the rest |
|---|---:|---:|---:|---:|---|
| **ERC-4337 EntryPoint** | 8 | 2 *(suspect)* | *85.18%* | *81.88%* | replay costs more (6); **both wins are probably replay artifacts — do not quote** |
| **Kelp** | 5 | 4 | **83.29%** | 81.72% | replay costs more (1) |
| **Railgun** | 18 | 15 | **78.72%** | 72.02% | replay costs more (1) |
| **Renzo** | 2 | 1 | *62.97%* | *62.97%* | replay costs more (1); **label inferred — entry point unidentified, do not quote** |
| **Aave** | 20 | 10 | **59.61%** | 37.77% | under the floor (9), replay costs more (1) |
| **Symbiotic** | 4 | 4 | **57.04%** | 54.65% | — |
| **Pyth** | 13 | 13 | **52.06%** | 16.22% | — |
| **Mellow** | 5 | 5 | **41.55%** | 30.00% | — |
| **Midas** | 12 | 9 | **23.54%** | 10.21% | under the floor (2), replay costs more (1); `depositInstant` wins are **not** call-blocked |
| **Chronicle** | 24 | 17 | **32.64%** | 30.17% | under the floor (4), replay costs more (3) |
| **Privacy Pools** | 11 | 2 | **19.47%** | 18.00% | replay costs more (9) |
| **Aragon** | 19 | 6 | **24.15%** | 4.64% | replay costs more (11), under the floor (2); all wins **call-dominated**, and only `execute` ever saves — 6 of 6 |
| **Ondo** | 8 | 2 | **12.09%** | 6.51% | under the floor (3), replay costs more (3) |
| **Ether.fi** | 13 | 2 | **11.09%** | 5.61% | replay costs more (6), under the floor (5) |
| **Puffer** | 2 | 1 | *7.06%* | *7.06%* | replay costs more (1); **label inferred — entry point unidentified, do not quote** |
| **Pendle** | 8 | 1 | **2.60%** | 2.60% | under the floor (5), replay costs more (2) |
| **Morpho** | 25 | 1 | **0.51%** | 0.51% | replay costs more (14), under the floor (3) |
| **EigenLayer** | 13 | 0 | **0.00%** | — | under the floor (9), replay costs more (4) |
| **Safe** | 12 | 0 | **0.00%** | — | under the floor (11), replay costs more (1) |
| **World ID** | 7 | 0 | **0.00%** | — | under the floor (7) |
| **Euler** | 8 | 0 | **0.00%** | — | under the floor (3), replay costs more (2) |
| **Chainlink** | 8 | 0 | **0.00%** | — | replay costs more (8) |
| **Panther** | 1 | 0 | **0.00%** | — | replay costs more (1) |
| **Ethena** | 22 | 0 | **0.00%** | — | under the floor (15), replay costs more (4) |
| **Lido** | 13 | 0 | **0.00%** | — | replay costs more (10), under the floor (3) |
| **ENS** | 18 | 0 | **0.00%** | — | under the floor (11), replay costs more (7) |
| **Umbra** | 8 | 0 | **0.00%** | — | replay costs more (8) |
| **Swell** | 3 | 0 | **0.00%** | — | replay costs more (2), under the floor (1) |
| **Sky** | 9 | 0 | **0.00%** | — | replay costs more (9) |
| **ZeroDev** | 9 | 0 | **0.00%** | — | replay costs more (9) |
| **EAS** | 11 | 0 | **0.00%** | — | replay costs more (11) |
| **Gitcoin** | 5 | 0 | **0.00%** | — | replay costs more (5); GTC token only — Passport is not on mainnet |
| **Snapshot** | 2 | 0 | **0.00%** | — | replay costs more (2); delegation record only, voting is off-chain |
| **delegate.xyz** | 3 | 0 | **0.00%** | — | replay costs more (3); found while separating it from Snapshot |
| **Frax** | 10 | 0 | **0.00%** | — | replay costs more (10); router rows are **call-blocked**, not empty — see `CALL_BLOCKED_CANDIDATES.md` |
| **Grove** | 10 | 0 | **0.00%** | — | under the floor (9), replay costs more (1); **no directly-callable surface** — 96 of 97 transactions enter through the operator Safe |
| **Centrifuge** | 5 | 0 | **0.00%** | — | under the floor (5); the Hub's own work is a fixed ~9,000 gas — **5 more `multicall` rows could not be measured**, 3 a replay defect and 2 rate-limited |

## ENS: 18 transactions, 18 measured, nothing saved

ENS was the highest-volume protocol left unchecked on the longlist, and the longlist called
it a good candidate for "rebate-style savings passed to users." It is the clearest negative
result in this file, and the reason is structural rather than incidental.

**All 18 transactions measured 0.00%, and 7 of them have negative surplus** — replaying the
recorded state changes costs *more* than the original transaction did.

| | |
|---|---:|
| transactions measured | 18 / 18 — no `heur` rows left |
| coverage | 9 functions across 5 ENS contracts |
| best surplus of any transaction | **16,058 gas** (`renew`) |
| Schnorr floor it must clear | 50,000 gas |
| shortfall of the best case | **33,942 gas** |
| mean surplus across all 18 | 1,975 gas |
| transactions with negative surplus | 7 of 18 |

**Why.** An ENS transaction's gas is almost entirely storage writes and logs. GasKiller has
to write those same slots and emit those same logs, so that cost does not go away — it is
the payload, not the computation. What GasKiller removes is only the surrounding compute:
string parsing, namehash, the price lookup, the commitment check. That is worth 11,000–16,000
gas and never more.

**Surplus does not grow with transaction size.** A 524,112-gas registration yields 12,329 gas
of surplus; an 88,200-gas renewal yields 16,058 — more, from a transaction six times smaller.
The large registrations spend their gas in sub-calls to the registry, the NFT and the resolver
(6 of their 8 recorded updates are `Call`s), and those must be re-executed on replay. Making
ENS transactions bigger does not move them toward the floor.

This is the same objection the longlist itself raises against EAS — "the write is the payload,
so there's little surrounding compute to strip out." It applies to ENS with full force, and
**the longlist's assessment of ENS should be revised down.**

### It is not the external calls

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

**What it would be worth if the signature were free.** ENS-wide: 26,319 transactions/month ×
1,975 gas mean surplus, at the 0.107 gwei median effective gas price actually paid and ETH at
$2,396.31 (Chainlink, read on-chain) = **$13/month**. At 20 gwei, $2,491/month. With the real
50,000-gas floor it is **$0 at any gas price**, because none of the nine functions measured
clears the floor — the best is 68% short.

Volume for reference: 12,227 distinct ENS-touching transactions in a 13.94-day window across
7 contracts, i.e. 877/day. The dominant one is the current `ETHRegistrarController`
(`0x59e16fcc…`, 445/day), which handles only `register` and `renew`. Caveat: 18 transactions
over nine functions is a sample, not the population — but the shortfall is 11,000 gas wide,
not a rounding error, and it is negative for 7 of the 18.

## Chronicle — the best new candidate found, and every direct transaction wins

Chronicle runs Sky/Maker's oracle network. It was picked because it is the last unchecked
protocol on the longlist whose on-chain work is *verification* rather than accounting, and
that prediction held.

**24 transactions, all trace-measured, no `heur` rows. 21 of 24 save. The only three that
do not are Multicall3 batches.**

| | |
|---|---:|
| direct pokes measured | 21, **all winning** |
| Scribe `poke` range | **28.55% – 32.64%** (median 30.17%) |
| legacy Median / OSM range | 0% – 16.56% (4 of 8 now under the floor) |
| gas saved per Scribe poke | 34,321 – 42,135 |
| state updates per transaction | **2** — one storage write, one log |
| external calls | **0** on every direct poke |
| replay cost (base) | **~37,000, essentially constant** |

### Why the shape is close to ideal

A Chronicle feed update burns 121,000–129,000 gas and writes one storage slot plus one log.
Replaying that costs about 37,000 gas no matter which feed or which transaction — the base
estimate varies by only 96 gas across all 13 Scribe measurements. Everything above that,
mean **89,031 gas** — is removable work.

*What* that work is, the analyzer does not say: it reports the amount of removable work, not
its composition. Reading it as signature verification is an inference from Scribe's `poke`
path (decode, staleness check, Schnorr verify, signer-registry lookup, write), where the
verification is much the largest item and the 260-byte calldata is mostly signature. **Not
decomposed, not verified.**

This is the exact inverse of ENS, measured in the same session: ENS is a large payload with
no computation around it, Chronicle is a tiny payload with a lot. Same floor, opposite result.

Note Chronicle already optimises hard — the dominant entry point is
`poke_optimized_7136211`, a function name mined so its selector is `0x00000082`, three zero
bytes to shave calldata cost. A team doing that is likely receptive to a gas argument, and
also unlikely to have left easy wins lying around.

### What it is worth

189 qualifying transactions/day (92.7 Scribe direct + 96.4 legacy Median/OSM), 240.9M gas
saved per month. **At the 1.007 gwei these transactions actually paid and ETH at $2,441:
$304/month.** At 20 gwei, $6,041.

That places it third by money behind Aave and Railgun, and **~25x Pyth** — despite Pyth
having a higher headline percentage. Two reasons: Chronicle has 6x the qualifying volume,
and its transactions pay **~10x the gas price** ENS and Pyth pay, because an oracle update
has to land promptly and bids accordingly. Gas price paid, not just gas used, belongs in the
ranking.

### Two honest objections

**1. Scribe is already a Schnorr multi-signature oracle.** Its own repository describes it as
"an efficient Schnorr multi-signature based Oracle." So GasKiller would be replacing one
aggregate-signature check with another, and the 50,000-gas floor is charged against a contract
whose entire design goal is minimising exactly that cost. The pitch is narrow and quantitative —
*the measured removable surplus averages 89,031 gas; GasKiller's own signature check costs
50,000* — rather than "we remove your computation." Quote both for what they are: 50,000 is a
constant in this repo (`crates/core/src/encoding.rs:21`), 89,031 is gas used minus the
measured replay cost.

**2. Optimistic settlement changes what an oracle is.** GasKiller writes the result first and
allows a challenge later. For a lending protocol reading that price to decide liquidations,
"verified now" and "verifiable later" are not the same guarantee. This is a security-model
conversation, not a gas conversation, and Chronicle will raise it first. It is the strongest
counter-argument to the largest measured win in this section, and I have not evaluated it.

**Batching is the one technical blocker.** Roughly 10% of Scribe traffic arrives through
Multicall3 (`aggregate3`), where a keeper pokes several feeds in one transaction. All three
measured that way score 0% with negative surplus, because each inner poke becomes an external
call that has to be re-executed. Any integration should keep pokes as separate direct
transactions.

## Re-evaluating at a different floor without re-running anything

The signature floor is a hardcoded constant (`TURETZKY_UPPER_GAS_LIMIT_SCHNORR`,
`crates/core/src/encoding.rs`), applied flat: `estimate = base + 50,000`, then
`savings = gas_used − estimate`. Nothing about it is derived from the transaction. There is no
derivation, citation or benchmark for the number anywhere in this repository.

**Every conclusion in this file is therefore conditional on that one constant** — and can be
revised with no new measurement. `surplus = gas_used − base_estimate` is floor-independent,
and both columns are recorded here for all 235 properly measured transactions. Changing the
floor is arithmetic on this table, not a re-run of the analyzer.

| floor | winning txs | protocols with ≥1 win | most wins |
|---:|---:|---:|---|
| 0 | 169 | 23 | Chronicle 21, Aave 19, Railgun 15, Ethena 15 |
| 10,000 | 144 | 22 | Chronicle 21, Railgun 15, Ethena 14, Pyth 13 |
| 27,000 *(old)* | 104 | 21 | Chronicle 21, Railgun 15, Pyth 13, Aave 10 |
| 40,000 | 86 | 17 | Chronicle 19, Railgun 15, Pyth 13, Aave 10 |
| 50,000 **(current)** | 80 | 15 | Chronicle 17, Railgun 15, Pyth 13, Aave 10 |
| 60,000 | 76 | 14 | Railgun 15, Chronicle 15, Pyth 13, Aave 10 |
| 80,000 | 73 | 13 | Railgun 15, Pyth 13, Chronicle 13, Aave 10 |
| 100,000 | 48 | 10 | Railgun 15, Aave 9, Pyth 5, Mellow 5 |
| 150,000 | 39 | 10 | Railgun 15, Aave 7, Kelp 4, Symbiotic 4 |
| 250,000 *(BLS)* | 27 | 7 | Railgun 15, Kelp 4, Aave 2, ERC-4337 EntryPoint 2 |

**89 transactions have positive surplus but under 50,000, so are killed by the floor alone** — they have positive surplus but under
50,000. If the floor were lowered again they would come back; if raised, more would die.

### The floor each protocol can tolerate

A protocol keeps at least one win at any floor below its best surplus:

| protocol | best surplus | protocol | best surplus |
|---|---:|---|---:|
| ERC-4337 *(suspect row — see warning above)* | 1,493,522 | Ethena | 48,699 |
| Railgun | 1,297,915 | Lido | 46,558 |
| Aave | 390,592 | EigenLayer | 38,841 |
| Ondo | 267,495 | Safe | 37,454 |
| Pyth | 166,006 | World ID | 35,578 |
| Privacy Pools | 164,301 | Euler | 34,191 |
| Pendle | 94,736 | ENS | 16,058 |
| **Chronicle** | **92,135** | Chainlink | 0 |
| Ether.fi | 82,310 | Panther | 0 |
| Morpho | 59,150 | | |

**Railgun, Aave and Pyth are robust** — they survive a floor 4–48x higher than the current
one. **Chronicle is the most floor-sensitive of the strong candidates:** all 21 of its wins
held at the old 27,000 floor but only 17 do at 50,000, 15 at 60,000, and none above 92,135. Since Chronicle's
own product is a Schnorr multi-signature oracle, they are also the counterparty most likely to
have a precise view of what on-chain Schnorr verification really costs. **Establish the
provenance of the floor before pitching them.**

Chainlink, Panther, Umbra and Sky score zero at *any* floor, including zero — their surplus is
negative, so replaying costs more than the original transaction regardless of signature
scheme. Umbra is the starkest: all 8 of its transactions are negative, best case −7,488 gas.

Caveats: the 15 `heur` rows are excluded, since their base estimates are unreliable for
reasons unrelated to the floor. The 5 unmeasurable transactions have no base estimate at all
and cannot be re-evaluated at any floor. The BLS row uses the same mechanism with its 250,000
constant, which has the same lack of provenance.

## Umbra — zero at any floor, and the volume premise is wrong too

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
scores zero **at any floor, including a floor of zero** — the floor-sensitivity table above
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

## What actually predicts a win

Three rules. Every result in this file follows them.

**1. The transaction has to be sent straight to the contract doing the expensive work.**

The clearest proof is Aave against Euler. Both run the same per-asset risk maths on a borrow. Aave lets users call its Pool contract directly and a borrow saves up to 59.61%. Euler forces every user through its EVC router — 0 of 191 transactions reached a vault directly — and now scores **0%** at the 50,000 floor (best surplus 34,191 gas). Same computation, opposite outcome, decided entirely by routing.

**2. The expensive work has to be computation, not bookkeeping.**

Railgun verifies zero-knowledge proofs: 65–81% saved. Morpho updates share balances: 2.60% at best. Cryptography and per-asset oracle loops win. Merkle hashing, allowlist checks and share accounting do not, because the writes they produce cost as much as the work they did.

**3. Screen per entry point, not per protocol.**

Aave's `borrow` won 9 out of 9. Aave's `supply` and `repay` won 0 out of 6 — they skip the health-factor check, so there is no computation to remove. One protocol can be both a great candidate and a dead end depending on which function is called.

### What that means for targeting

Look for protocols that:

- do elliptic-curve cryptography on chain (ZK proof verification, BLS/Groth16 checks, signature aggregation);
- loop over per-asset oracle reads on every transaction;
- let users call the contract directly instead of forcing a router or relayer.

Avoid protocols whose transactions are mostly transfers, share-balance updates, merkle-tree appends or allowlist lookups — and avoid anything where a relayer, batcher or safe sits in front, until the external-call problem is solved.

## Near misses — blocked by calls but already close

These transactions have real compressible work left over and still lost. If the contract behind the call also ran GasKiller, these are the ones that flip first. **Shortfalls are against the 50,000-gas floor** — at the old 27,000 floor they were 23,000 gas smaller, and several of these rows were wins.

| protocol | tx | function | gas used | surplus | short of the floor by | calls in the result |
|---|---|---|---:|---:|---:|---:|
| Morpho | [`0x1c71eb76…`](https://etherscan.io/tx/0x1c71eb76549cc6a80467e06e8bc938b7fc1e67e9575c2aece8d98345243bb218) | *9-market reallocation* `0xeb7499cf` | 725,295 | +25,527 | 24,473 | 1 |
| Safe | [`0x5688590b…`](https://etherscan.io/tx/0x5688590bc26e704d720d7bb2185b195aabb310ba67dddd944f64509b1cf70513) | `execTransaction` ✓ `0x6a761202` | 322,338 | +25,210 | 24,790 | 2 |
| Pendle | [`0xa2c6de73…`](https://etherscan.io/tx/0xa2c6de73e89c7bd707a9fe308d09c54eb16d2ddf9e3ff09f866d8a68e3948afd) | *third-party aggregator* `0xc685f647` | 1,183,159 | +25,192 | 24,808 | 5 |
| Safe | [`0x2666f99a…`](https://etherscan.io/tx/0x2666f99a3b1ad225cf8dcc40fbafb1959a6efb5bb3c561b3d2d5a3b242ca4a29) | `execTransaction` ✓ `0x6a761202` | 96,660 | +23,309 | 26,691 | 1 |
| World ID | [`0x36c09544…`](https://etherscan.io/tx/0x36c095445eb96f2ccaa2a2ec9544ac2cf72aa524c36c0ce23c0aecc2cf36b8b7) | `registerIdentities` ✓ `0x2217b211` | 285,261 | +22,186 | 27,814 | 1 |
| EigenLayer | [`0xaa858fcd…`](https://etherscan.io/tx/0xaa858fcd781a6a5afa142ccd9a802d0df1e2f68292f0abf8546426cda3fe6644) | *EigenLayer rewards claim* `0x3ccc861d` | 156,150 | +20,985 | 29,015 | 2 |
| Safe | [`0xb286eeb1…`](https://etherscan.io/tx/0xb286eeb15c4cb3445a73e275e89336f7563eb46c2e9ec97a82aeefb5a4485430) | `execTransaction` ✓ `0x6a761202` | 463,470 | +20,526 | 29,474 | 6 |
| World ID | [`0x6b2fb8d3…`](https://etherscan.io/tx/0x6b2fb8d32c1fc927e5c37ae0ca52d17cb122b949ec0140f75a8212164911f494) | `registerIdentities` ✓ `0x2217b211` | 282,573 | +19,534 | 30,466 | 1 |
| World ID | [`0xb2f5ba58…`](https://etherscan.io/tx/0xb2f5ba588077025662acd44f62ead62c4dc6da4faa30890d658542aedcaef3c5) | `registerIdentities` ✓ `0x2217b211` | 281,457 | +18,406 | 31,594 | 1 |
| World ID | [`0xcd404a27…`](https://etherscan.io/tx/0xcd404a27462a9e60fdd5a17c024d758d809f860ad2da9f1709882d497276375a) | `registerIdentities` ✓ `0x2217b211` | 281,445 | +18,394 | 31,606 | 1 |
| Safe | [`0x909681b5…`](https://etherscan.io/tx/0x909681b5131c5ccc56e6f6791f152efe41cf270172c5a4645fc0067567bd8651) | `execTransaction` ✓ `0x6a761202` | 103,575 | +18,056 | 31,944 | 1 |
| Euler | [`0x7d1e2345…`](https://etherscan.io/tx/0x7d1e2345c39b884a16eb6b2e06c1c4a4177c5639fe1c91474a356c3eef04fd87) | *third-party contract* `0x3271ba8d` | 2,701,108 | +17,630 | 32,370 | 3 |
| Euler | [`0xa32effd3…`](https://etherscan.io/tx/0xa32effd3b31a02343d8cf4362c4fee2e806ea9dcf00fdea5eb1a2b054ae0ea4a) | `batch` ✓ `0xc16ae7a4` | 499,524 | +16,691 | 33,309 | 5 |
| Aave | [`0x9905c35e…`](https://etherscan.io/tx/0x9905c35e963d0c36e66b33d6f2319085daebf2920a8572ce26c01e201d0bbc16) | `withdraw` ✓ `0x69328dec` | 183,126 | +16,416 | 33,584 | 1 |

**One caveat on the Safe rows.** A Safe's own work is verifying owner signatures — about 3,000 gas each — and it writes one slot, its nonce. So its surplus is capped by owner count no matter what the transaction does. The gas inside the call belongs to whatever the Safe called, and those protocols would get that saving with or without a Safe in front. Safe is a thin wrapper over other candidates, not a candidate itself.

`CALL_BLOCKED_CANDIDATES.md` has the deeper write-up of this group.

## Warning: `heur` rows are usually rate limiting, not real results

When the analyzer cannot replay a block it falls back to a heuristic estimator and prints
a normal-looking result with a small `(heuristic - measured estimation failed)` note. The
estimator prices `Call` at **zero gas**, so it fails in one direction only: it *overstates*
savings.

During the Ethena runs, 9 of 21 transactions hit this path. The cause was not the
transactions — it was the RPC provider returning `HTTP 429: 50/second request limit
reached` mid-replay. Re-running them serially recovered real measurements for 6, and
**every single one collapsed to 0%**:

| tx | heuristic claimed | true measured |
|---|---:|---:|
| `0xae6a3e25…` | 36.96% | 0% |
| `0xaf1a2df7…` | 34.99% | 0% |
| `0xd2475759…` | 33.91% | 0% |
| `0x91e950a3…` | 33.90% | 0% |
| `0xb3a29f2b…` | 30.95% | 0% |
| `0x6f12cb87…` | 3.94% | 0% |

On `0xaf1a2df7…` the heuristic was wrong by 86,378 gas.

**Practical rules.** Never quote a `heur` row. Re-run it serially — one analyzer process at
a time — before drawing any conclusion. The remaining `heur` rows in the table below,
including those inherited from earlier protocols, were produced under the same throttling
and should be re-run before use rather than treated as data.


### The heuristic also underprices fresh storage writes, not just calls

ENS exposed a second, independent way the fallback lies. `crates/core/src/heuristic.rs:40`
charges `WARM_SSTORE_COST` 5,000 per storage write. A write to a slot that was previously
empty actually costs about 20,000. ENS resolver records are mostly new slots, so the
heuristic underestimated the replay cost by roughly 15,000 gas per write — and it did this
on transactions with **zero external calls**, where the `Call`-priced-at-zero explanation
does not apply at all.

8 of the 18 ENS runs fell back to the heuristic, all of them on `HTTP 429`. Retrying
(up to 10 attempts each) recovered real measurements for all 8, and **all 8 collapsed to 0%**:

| tx | function | calls | heuristic claimed | true measured | heuristic underpriced base by |
|---|---|---:|---:|---:|---:|
| `0x707689e3…` | `multicall` | 0 | 51.78% | 0% | 125,611 gas |
| `0xd49a8171…` | `multicall` | 0 | 34.21% | 0% | 56,733 gas |
| `0x063bce87…` | `multicall` | 0 | 27.61% | 0% | 56,733 gas |
| `0x3b10d318…` | `renew` | 2 | 21.42% | 0% | 31,180 gas |
| `0xacbe2f4e…` | `register` | 5 | 15.57% | 0% | 48,014 gas |
| `0x4fce8ead…` | `setAddr` | 0 | 14.63% | 0% | 32,321 gas |
| `0x15e84300…` | `setText` | 0 | 12.40% | 0% | 28,677 gas |
| `0xfe33d0ff…` | `setContenthash` | 0 | 0% | 0% | 13,476 gas |

The worst case, `0x707689e3…`, was wrong by 125,611 gas: the heuristic reported a 51.78%
saving on a transaction whose replay actually costs *more* than the original.

**So "zero external calls" is not a safety check on a `heur` row.** Three of the four largest
overstatements above have no calls at all. The only safe treatment is re-measurement.
Retrying does work, but it can take persistence: `0x707689e3…` needed four separate retry
rounds before the replay went through.

## The replay defect — why 14 transactions can't be measured, and one silent failure mode

Separate from rate limiting, 14 runs failed with `RevertingContext CALL #n ... reverted`.
These cluster in **Morpho (7), Centrifuge (3), Euler (2) and Railgun (2)** — and not at all in
Lido, Chainlink or Pyth.

**What happens.** GasKiller records a transaction as a list of state updates and replays
them to price it. But the recorded steps depend on each other's side effects, and the
recording does not preserve them. A Euler liquidation
(`0x575f2fb2224cf67a0a3a8cca18def46bbf327eb72e1ac1414771dffd6f4a67f3`, 3,036,470 gas)
reduces to four calls:

1. Morpho Blue `0xe0232b42`
2. WETH `withdraw(uint256)` (`0x2e1a7d4d`, keccak-verified)
3. an ETH transfer
4. an ETH transfer to a builder

On replay, step 2 reverts: `WETH.withdraw` requires the caller to already hold that WETH,
and step 1 is what delivered it in the original transaction. The recording says only *call
Morpho Blue with these bytes* — the balance change that call produced is not carried
forward.

This hits transactions that **chain** operations — borrow, then swap, then repay — which is
exactly what liquidations and bundled DeFi calls do. Simple transactions never trip it,
which is why Lido and Pyth measured first time.

**The detected case is safe.** When the revert escapes, the tool notices, refuses to
report a measurement and says why. That is correct behaviour.

**The undetected case is not.** If the contract catches its own errors, the revert never
escapes. The tool sees a call that "succeeded" very cheaply and reports a large saving.
This is the suspected explanation for the two ERC-4337 EntryPoint rows showing 80.66% and
86.54%: EntryPoint is designed to catch a failing userOp rather than revert. Two
structurally identical EntryPoint transactions — same eight updates, same ordering, same
`validateUserOp` and `innerHandleOp` calls — replay for 201,100 and 2,205,725 gas
respectively, a 10x divergence with no structural difference.

| replay fails and… | tool reports | risk |
|---|---|---|
| the revert escapes | "estimation failed" | none — honest |
| the contract catches it | a large saving | **you quote it to a customer** |

Nothing in the output distinguishes the second case from a real win. Both are labelled
`measured via StateChangeHandler` with no warning.

**A second mechanism, found in Centrifuge.** The three Hub `multicall` failures are not
missing intermediate *state* — they are missing the caller's *identity*. Each records as a
single `Call` instruction carrying the whole batch, and on replay the callee's
`onlyManager` check rejects it with `NotManager()` (`0xc0fc8a8a`). The original call
reached that callee from inside the Hub; the replay arrives from somewhere else. The
analyzer's own output names the cause — *"a callee re-entered the target contract during
execution"* — and the trace confirms it: Hub calls `0x19a524d0…`, which calls straight back
into the Hub. So the defect has two distinct forms: **lost intermediate state** (Morpho,
Euler, Railgun) and **lost caller context** (Centrifuge). Both are detected and both refuse
to report, which is the safe branch of the table above.

**One-sentence version:** GasKiller's replay doesn't carry forward the intermediate state
between a transaction's recorded steps, so chained calls fail on replay — and when a
contract swallows that failure internally, the analyzer reports it as a large false saving.

## Every transaction

Sorted by protocol (best protocol first), then by savings.

`heur` marks a transaction where the real replay failed and the tool fell back to a rough estimate. **Those numbers are not reliable** — the estimator prices calls at zero gas, and the one time it could be checked against a real measurement it was off by 95,744 gas.

A **✓** on a function name means I confirmed the 4-byte selector by hashing the signature myself. An *italic* name was guessed from the events the transaction emitted — treat it as a description, not an identification.

| protocol | tx | function | gas used | GasKiller cost | surplus | Schnorr saved | BLS saved | why 0 | updates | notes |
|---|---|---|---:|---:|---:|---:|---:|---|---:|---|
| Railgun | [`0xaa357a48…`](https://etherscan.io/tx/0xaa357a4824001aed7173b3bc7d976f997fc7839def4c56ec070db97ec2121bc4) | *Railgun private transfer / unshield* `0xd8ae136a` | 1,085,832 | 181,095 | +904,737 | **854,737** (78.72%) | 654,737 | — | 14 (11S/3L1) |  |
| Railgun | [`0x32daef80…`](https://etherscan.io/tx/0x32daef80a0c5180dcf45b15130e10ecced485242f0d3305b30942ebeb5aec364) | *Railgun private transfer / unshield* `0xd8ae136a` | 1,056,246 | 197,859 | +858,387 | **808,387** (76.53%) | 608,387 | — | 15 (12S/3L1) |  |
| Railgun | [`0xe7e605b6…`](https://etherscan.io/tx/0xe7e605b6520aaf757f4531a88af4966866d86fee61ec06e93b3423b30a934adc) | *Railgun private transfer / unshield* `0xd8ae136a` | 1,615,755 | 317,840 | +1,297,915 | **1,247,915** (77.23%) | 1,047,915 | — | 22 (15S/5L1/2C) |  |
| Railgun | [`0xa2177825…`](https://etherscan.io/tx/0xa21778257ba78ce1354a4ff25a48ee07854e5e858f4facfe3e3c3893d9a1945f) | *Railgun private transfer / unshield* `0xd8ae136a` | 1,561,573 | 312,286 | +1,249,287 | **1,199,287** (76.80%) | 999,287 | — | 23 (16S/5L1/2C) |  |
| Railgun | [`0x73a1d71e…`](https://etherscan.io/tx/0x73a1d71e2cfa678b63c934c8c04eb6b6069de89c85faf16d0376241ecabfb0ec) | *Railgun private transfer / unshield* `0xd8ae136a` | 1,097,058 | 213,396 | +883,662 | **833,662** (75.99%) | 633,662 | — | 17 (14S/3L1) |  |
| Railgun | [`0xa3a010fa…`](https://etherscan.io/tx/0xa3a010fa890d910e669fba1ea7b681a4c1f464b754c5b7bff7d62ae15ae25e71) | *Railgun private transfer / unshield* `0xd8ae136a` | 1,113,545 | 241,625 | +871,920 | **821,920** (73.81%) | 621,920 | — | 18 (12S/4L1/2C) |  |
| Railgun | [`0x04736806…`](https://etherscan.io/tx/0x04736806756593b664eb29591a2ea046b2261c5a4fa1bdd1707a6dc5abf54f07) | *Railgun private transfer / unshield* `0xd8ae136a` | 1,136,044 | 266,554 | +869,490 | **819,490** (72.14%) | 619,490 | — | 19 (13S/4L1/2C) |  |
| Railgun | [`0x39a67a29…`](https://etherscan.io/tx/0x39a67a2964b675ccd1be1939c513b46f62cae71c3f320bece6acdaf71934b3ae) | *Railgun private transfer / unshield* `0xd8ae136a` | 1,131,080 | 266,430 | +864,650 | **814,650** (72.02%) | 614,650 | — | 20 (14S/4L1/2C) |  |
| Railgun | [`0xaf36e218…`](https://etherscan.io/tx/0xaf36e2187e095fa88299a8859632963594414b716f36aae541318d4ce71740e6) | *Railgun private transfer / unshield* `0xd8ae136a` | 1,177,014 | 282,477 | +894,537 | **844,537** (71.75%) | 644,537 | — | 21 (15S/4L1/2C) |  |
| Railgun | [`0x0376edd3…`](https://etherscan.io/tx/0x0376edd36b0c9211b1a38f41e5f1c04233478ca4dcf7d4852ef313deb1c57ade) | `shield` ✓ `0x044a40c3` | 724,515 | 168,652 | +555,863 | **505,863** (69.82%) | 305,863 | — | 14 (10S/2C/2L1) |  |
| Railgun | [`0xab44777b…`](https://etherscan.io/tx/0xab44777b4e3a37169ea03163ec5d14dbf668bcb18219c3a95cc2313c2be55a3d) | `shield` ✓ `0x044a40c3` | 736,786 | 177,753 | +559,033 | **509,033** (69.09%) | 309,033 | — | 13 (9S/2C/2L1) |  |
| Railgun | [`0x27ce0220…`](https://etherscan.io/tx/0x27ce022039ef027d473c61f3140da32c8e58f0a8daaee826e6f04a58744db447) | `shield` ✓ `0x044a40c3` | 742,727 | 185,294 | +557,433 | **507,433** (68.32%) | 307,433 | — | 14 (10S/2C/2L1) |  |
| Railgun | [`0x3d54cfc3…`](https://etherscan.io/tx/0x3d54cfc375e626acd71432b2ab59a94bde2f6ee2490528ca8259417091e3ab97) | `shield` ✓ `0x044a40c3` | 752,878 | 197,812 | +555,066 | **505,066** (67.08%) | 305,066 | — | 15 (11S/2C/2L1) |  |
| Railgun | [`0x6837bb8d…`](https://etherscan.io/tx/0x6837bb8d629ee0dce5f045acfc6c1e296df4abe1907897820bf621462dc23425) | `shield` ✓ `0x044a40c3` | 758,741 | 211,644 | +547,097 | **497,097** (65.52%) | 297,097 | — | 18 (14S/2C/2L1) |  |
| Railgun | [`0x792a8e57…`](https://etherscan.io/tx/0x792a8e5783cec82cc456d83f0f1703a2bf71eafa05984a17896809bd952567cc) | *Railgun private transfer / unshield* `0xd8ae136a` | 484,303 | 139,722 | +344,581 | **294,581** (60.83%) | 94,581 | — | 7 (3L1/2C/2S) |  |
| Railgun | [`0x6f534f5a…`](https://etherscan.io/tx/0x6f534f5af7fa26b66e0c6a5f49505f7125665e88b0d1af23efca86da88109f27) `heur` | *Railgun RelayAdapt bundle* `0x28223a77` | 1,297,603 | 1,287,231 | +10,372 | **0** (0.00%) | 0 | under the floor | 5 (3C/2S) |  |
| Railgun | [`0x7c731150…`](https://etherscan.io/tx/0x7c731150234add278ecae3ee9b6bcd35ee50435cc69bc47cce1a008e54c1f2ce) `heur` | *Railgun RelayAdapt bundle* `0x28223a77` | 1,120,780 | 1,116,659 | +4,121 | **0** (0.00%) | 0 | under the floor | 5 (3C/2S) |  |
| Railgun | [`0x2d754e6f…`](https://etherscan.io/tx/0x2d754e6f8a34058e5d07596e627cbc70e0c704279e9f745a4c0baef80389cca7) | *Railgun RelayAdapt bundle* `0x28223a77` | 523,496 | 533,777 | -10,281 | **0** (0.00%) | 0 | replay costs more | 5 (3C/2S) |  |
| Aave | [`0xa7a8c34f…`](https://etherscan.io/tx/0xa7a8c34fee3795db241bcdf3e5c0b8b279dcb78f62ceee2f3530c9f38dd1ebec) | `borrow` ✓ `0xa415bcad` | 571,333 | 180,741 | +390,592 | **340,592** (59.61%) | 140,592 | — | 11 (7S/2C/1L2/1L4) |  |
| Aave | [`0xa36db142…`](https://etherscan.io/tx/0xa36db1427faa3a36a7461bf00e80bc12bd07d9d7c87fbab54ee49bec92b9fec7) | `borrow` ✓ `0xa415bcad` | 450,205 | 163,828 | +286,377 | **236,377** (52.50%) | 36,377 | — | 10 (6S/2C/1L2/1L4) |  |
| Aave | [`0x1b708eba…`](https://etherscan.io/tx/0x1b708eba95e753a84558374c488f1557907935272fabc2ffe91f6d8844c06370) | `withdraw` ✓ `0x69328dec` | 408,792 | 180,921 | +227,871 | **177,871** (43.51%) | 0 | — | 12 (8S/1C/1L2/1L3/1L4) |  |
| Aave | [`0xa70a6bbd…`](https://etherscan.io/tx/0xa70a6bbd833f973defbcc4a0b1ad281f4708fa1960a39635d784a855a8fac9e1) | `borrow` ✓ `0xa415bcad` | 371,912 | 173,408 | +198,504 | **148,504** (39.93%) | 0 | — | 12 (8S/2C/1L2/1L4) |  |
| Aave | [`0xc62d052c…`](https://etherscan.io/tx/0xc62d052c8385a546ab9f2f4d6a9fc194e45c3c9c7bf69e22454e38d9c55cb0cb) | `borrow` ✓ `0xa415bcad` | 360,781 | 170,263 | +190,518 | **140,518** (38.95%) | 0 | — | 11 (7S/2C/1L2/1L4) |  |
| Aave | [`0xe73dcebf…`](https://etherscan.io/tx/0xe73dcebf75429339193a24c45a37e377948bf6f69fa77b8f50931d1e26ebeeea) | `borrow` ✓ `0xa415bcad` | 345,794 | 170,335 | +175,459 | **125,459** (36.28%) | 0 | — | 11 (7S/2C/1L2/1L4) |  |
| Aave | [`0x000d4a32…`](https://etherscan.io/tx/0x000d4a32a076758c9ca1271e2909e2c4e1acaf988ff36ac8e8dc513f5fa64332) | `borrow` ✓ `0xa415bcad` | 365,438 | 181,716 | +183,722 | **133,722** (36.59%) | 0 | — | 11 (7S/2C/1L2/1L4) |  |
| Aave | [`0x2cab2e0f…`](https://etherscan.io/tx/0x2cab2e0f215f22a30249a1198f6604bdcfcc131183aeaaa7c1257fb939ec239f) | `borrow` ✓ `0xa415bcad` | 346,272 | 206,699 | +139,573 | **89,573** (25.87%) | 0 | — | 12 (8S/2C/1L2/1L4) |  |
| Aave | [`0xe65a59b9…`](https://etherscan.io/tx/0xe65a59b9f5d42dfd18018dd8c42850e6ea38c49d4a61718888c072e4f13dcc77) | `borrow` ✓ `0xa415bcad` | 316,682 | 205,592 | +111,090 | **61,090** (19.29%) | 0 | — | 12 (8S/2C/1L2/1L4) |  |
| Aave | [`0xb33162e1…`](https://etherscan.io/tx/0xb33162e1275b4e14a4a0de3d327949fb520949cadd898d17718bb813547ca0fb) | `borrow` ✓ `0xa415bcad` | 252,529 | 164,712 | +87,817 | **37,817** (14.98%) | 0 | — | 11 (7S/2C/1L2/1L4) |  |
| Aave | [`0xeff004bd…`](https://etherscan.io/tx/0xeff004bd1fb2851258ac5aa69997def87176f40716ecd4fe3d68904e1d6c3669) | `withdraw` ✓ `0x69328dec` | 211,120 | 194,806 | +16,314 | **0** (0.00%) | 0 | under the floor | 10 (1C) | **re-measured** — heuristic claimed 11.09% |
| Aave | [`0x9287f808…`](https://etherscan.io/tx/0x9287f80894eeeacc8af236609401da9f14ce0e655cbb9748e0db2e405aeb2ef5) | *third-party liquidator bot* `0x7e809076` | 1,165,207 | 1,156,574 | +8,633 | **0** (0.00%) | 0 | under the floor | 6 (4C/2S) |  |
| Aave | [`0x324633c1…`](https://etherscan.io/tx/0x324633c1f5cf10b86a58aad0d48ac39673afd6ee24e2b391488ac84e4c6baaa0) | `supplyWithPermit` ✓ `0x02c205f0` | 206,695 | 207,356 | -661 | **0** (0.00%) | 0 | replay costs more | 11 (5S/3C/1L2/1L3/1L4) |  |
| Aave | [`0x4eba5f8d…`](https://etherscan.io/tx/0x4eba5f8de29afdcac5703668d41a1f4bee734545dcdb37a129c6341b41c6ea44) | `supply` ✓ `0x617ba037` | 183,352 | 178,041 | +5,311 | **0** (0.00%) | 0 | under the floor | 11 (7S/2C/1L2/1L4) |  |
| Aave | [`0x9905c35e…`](https://etherscan.io/tx/0x9905c35e963d0c36e66b33d6f2319085daebf2920a8572ce26c01e201d0bbc16) | `withdraw` ✓ `0x69328dec` | 183,126 | 166,710 | +16,416 | **0** (0.00%) | 0 | under the floor | 10 (7S/1C/1L2/1L4) |  |
| Aave | [`0x52b373f5…`](https://etherscan.io/tx/0x52b373f5701425f48c42e3779527b6b7da51e7c764317c07cb40446377113649) | `supplyWithPermit` ✓ `0x02c205f0` | 179,856 | 179,187 | +669 | **0** (0.00%) | 0 | under the floor | 12 (7S/3C/1L2/1L4) |  |
| Aave | [`0xe41dd331…`](https://etherscan.io/tx/0xe41dd331b63a80add54ec1ef340f252c623538cfe35b69a65b190651aa636691) | `withdraw` ✓ `0x69328dec` | 167,589 | 160,020 | +7,569 | **0** (0.00%) | 0 | under the floor | 12 (8S/1C/1L2/1L3/1L4) |  |
| Aave | [`0x7f281bd6…`](https://etherscan.io/tx/0x7f281bd663289348bccaeb5c1616459ab424f557a65eaebfb603a1d445267ad4) | `supply` ✓ `0x617ba037` | 155,576 | 150,490 | +5,086 | **0** (0.00%) | 0 | under the floor | 11 (7S/2C/1L2/1L4) |  |
| Aave | [`0x055c232c…`](https://etherscan.io/tx/0x055c232ce489f003f64d5f05a5f77706c8a282f921d60a4264b5eeb21a6c6736) | `supply` ✓ `0x617ba037` | 147,675 | 142,925 | +4,750 | **0** (0.00%) | 0 | under the floor | 11 (7S/2C/1L2/1L4) |  |
| Aave | [`0x6b7563d1…`](https://etherscan.io/tx/0x6b7563d1e117aa90cc1e65b19b10ee525da3bdc89a26d0498a2a7084ab7867b1) | `repay` ✓ `0x573ade81` | 144,130 | 142,631 | +1,499 | **0** (0.00%) | 0 | under the floor | 11 (7S/2C/1L2/1L4) |  |
| Privacy Pools | [`0xe894abc7…`](https://etherscan.io/tx/0xe894abc79ca19fae8e3ef2a98b9570da0037d6f47ce531351002770d16ffe11f) | `withdraw` ✓ `0x30c0766d` | 587,069 | 422,768 | +164,301 | **114,301** (19.47%) | 0 | — | 16 (12S/2C/1L1/1L2) |  |
| Privacy Pools | [`0x67deaa0e…`](https://etherscan.io/tx/0x67deaa0e50f0db65925f464c05168927db7ce336079334100aba5cdbeb701e64) | `withdraw` ✓ `0x30c0766d` | 576,177 | 430,907 | +145,270 | **95,270** (16.53%) | 0 | — | 17 (13S/2C/1L1/1L2) |  |
| Privacy Pools | [`0x15082298…`](https://etherscan.io/tx/0x150822981204592e4cfa340ba2e63e607a1c6ded490b988f9a8bd37c1f2b46d0) | `relay` ✓ `0x8a44121e` | 620,208 | 632,053 | -11,845 | **0** (0.00%) | 0 | replay costs more | 6 (3C/2S/1L4) |  |
| Privacy Pools | [`0x03ebad9a…`](https://etherscan.io/tx/0x03ebad9a10bc3dc5ad36613de80975b7ee8061d7fa74367f1a9aa04e77cc1524) | `relay` ✓ `0x8a44121e` | 604,245 | 616,114 | -11,869 | **0** (0.00%) | 0 | replay costs more | 6 (3C/2S/1L4) |  |
| Privacy Pools | [`0xad4ac41d…`](https://etherscan.io/tx/0xad4ac41d7ad3ba9792d7c426631dba0d46a31e271f5105dbb6aa6df349c891a5) | `relay` ✓ `0x8a44121e` | 604,233 | 616,066 | -11,833 | **0** (0.00%) | 0 | replay costs more | 6 (3C/2S/1L4) |  |
| Privacy Pools | [`0x4d8f00ee…`](https://etherscan.io/tx/0x4d8f00ee277c67f95049a43dfe604418d0a408fed40a6473bd5b154045c2e2e2) | `relay` ✓ `0x8a44121e` | 577,042 | 588,768 | -11,726 | **0** (0.00%) | 0 | replay costs more | 6 (3C/2S/1L4) |  |
| Privacy Pools | [`0x2766c992…`](https://etherscan.io/tx/0x2766c992f22f5aec9bdfc1f16e394d4c4ed6b996bd002f64235b5234e9269cd2) | `relay` ✓ `0x8a44121e` | 558,846 | 571,008 | -12,162 | **0** (0.00%) | 0 | replay costs more | 6 (3C/2S/1L4) |  |
| Privacy Pools | [`0x53e6375e…`](https://etherscan.io/tx/0x53e6375e0156f40d6917e8d48d26f0af6e1fd197d54d0042b96138dfc449660f) | `deposit` ✓ `0x0efe6a8b` | 393,615 | 402,757 | -9,142 | **0** (0.00%) | 0 | replay costs more | 6 (3S/2C/1L3) |  |
| Privacy Pools | [`0x46a8ff4b…`](https://etherscan.io/tx/0x46a8ff4b10a52df709860a908f1749cd66523b5e6a3b18e7eeb901f8b7cd97eb) | `deposit` ✓ `0xb6b55f25` | 381,540 | 387,061 | -5,521 | **0** (0.00%) | 0 | replay costs more | 5 (3S/1C/1L3) |  |
| Privacy Pools | [`0xb120146b…`](https://etherscan.io/tx/0xb120146b4dd84f30f7c44cfb6f9fb5fca7c0b10f051a6259edd5c5c7b40d9da6) | `ragequit` ✓ `0x71235b34` | 279,732 | 287,612 | -7,880 | **0** (0.00%) | 0 | replay costs more | 4 (2C/1L2/1S) |  |
| Privacy Pools | [`0x0b27aa2c…`](https://etherscan.io/tx/0x0b27aa2ce30ee4e0f9e34a3f28537115d38c5a5fd499937b04fe437cfa3537f8) | `updateRoot` ✓ `0x87bf00f0` | 149,961 | 163,803 | -13,842 | **0** (0.00%) | 0 | replay costs more | 7 (6S/1L1) |  |
| Ether.fi | [`0x5ab8d02a…`](https://etherscan.io/tx/0x5ab8d02ae1b7a79bcfb65057b14e874fcd9165b5bcae85253f58958e25e1477b) | *(selector not captured)* | 291,228 | 208,918 | +82,310 | **32,310** (11.09%) | 0 | — | 6 (3C/2S/1L3) |  |
| Ether.fi | [`0xab780dc7…`](https://etherscan.io/tx/0xab780dc7c7c59d079462a88428b4e172c84a05eeec892195a02787a856214583) | *Ether.fi oracle-report execution* `0x2e03931e` | 259,254 | 208,906 | +50,348 | **348** (0.13%) | 0 | — | 6 (3C/2S/1L3) |  |
| Ether.fi | [`0xadb81164…`](https://etherscan.io/tx/0xadb81164fb568da41e4876b7695f287df7caaec92e4fb4f11579ac6a8aa61af8) | *Ether.fi oracle-report execution* `0x2e03931e` | 250,124 | 208,906 | +41,218 | **0** (0.00%) | 0 | under the floor | 6 (3C/2S/1L3) |  |
| Ether.fi | [`0x9fe2db76…`](https://etherscan.io/tx/0x9fe2db76e575eba316f1c1133b9522b1084631a7140b9895272fb782ea65cb8d) | *Ether.fi oracle-report execution* `0x2e03931e` | 245,559 | 208,894 | +36,665 | **0** (0.00%) | 0 | under the floor | 6 (3C/2S/1L3) |  |
| Ether.fi | [`0xdce4440b…`](https://etherscan.io/tx/0xdce4440b1e1cd6ae69eaa3331085bcbe38c6ab23c8d53401f7c49c63d7ec06ce) | `batchClaimWithdraw` ✓ `0x24fccdcf` | 205,965 | 209,933 | -3,968 | **0** (0.00%) | 0 | replay costs more | 18 (4C) | **re-measured** — heuristic claimed 2.27% |
| Ether.fi | [`0xc3081e6f…`](https://etherscan.io/tx/0xc3081e6f850f214a3df7ccf069f0233a4d07fd08fede69f3e904c45e644789cf) | *third-party aggregator* `0x146ee74d` | 4,904,702 | 4,956,803 | -52,101 | **0** (0.00%) | 0 | replay costs more | 1 (1C) |  |
| Ether.fi | [`0x87b26753…`](https://etherscan.io/tx/0x87b26753364ee01e9c442fbf5c2a37443f28e00d3e34591cd4a9147611fe4eb7) | `batchClaimWithdraw` ✓ `0x24fccdcf` | 679,714 | 878,853 | -199,139 | **0** (0.00%) | 0 | replay costs more | 117 (65S/26C/13L2/13L4) | 13 withdrawals batched — 117 state updates |
| Ether.fi | [`0x7ee0a346…`](https://etherscan.io/tx/0x7ee0a34642b5380eea636f02ce6ee35f109390a95bd2d19b8ff1794512829bb1) | `requestWithdraw` ✓ `0x397a1b28` | 193,099 | 198,205 | -5,106 | **0** (0.00%) | 0 | replay costs more | 3 (2C/1L2) |  |
| Ether.fi | [`0x4964cf5a…`](https://etherscan.io/tx/0x4964cf5adfaaf0e7d0d48d4cd2cc02bf792493653550293dbb22aa7909a18eda) | `requestWithdraw` ✓ `0x397a1b28` | 193,075 | 198,133 | -5,058 | **0** (0.00%) | 0 | replay costs more | 3 (2C/1L2) |  |
| Ether.fi | [`0xd6ec9fc5…`](https://etherscan.io/tx/0xd6ec9fc5c359167794fd0c692b578a346ae978b73ed8dc503aa5e6350ed84b63) | `claimWithdraw` ✓ `0xb13acedd` | 153,292 | 144,419 | +8,873 | **0** (0.00%) | 0 | under the floor | 9 (5S/2C/1L2/1L4) |  |
| Ether.fi | [`0xd14eb830…`](https://etherscan.io/tx/0xd14eb830b3308feb3dee287e11752e9400d4aaf8b1c85cacb04d1ef9321a2a84) | `wrap` ✓ `0xea598cb0` | 134,730 | 130,194 | +4,536 | **0** (0.00%) | 0 | under the floor | 4 (2S/1C/1L3) |  |
| Ether.fi | [`0x2cc9a112…`](https://etherscan.io/tx/0x2cc9a112936e0cfda1b4e9afd88ac5a861f2392cb9e20d2598f255a509b6d929) | `unwrap` ✓ `0xde0e9a3e` | 122,474 | 117,487 | +4,987 | **0** (0.00%) | 0 | under the floor | 4 (2S/1C/1L3) |  |
| Ether.fi | [`0xbe33787e…`](https://etherscan.io/tx/0xbe33787eb89c203cacaee0fb05da574bfef9c0aef4b80bcd8eed779a57f86222) | `deposit` ✓ `0xd0e30db0` | 120,178 | 128,056 | -7,878 | **0** (0.00%) | 0 | replay costs more | 4 (2S/1C/1L2) |  |
| EigenLayer | [`0x4ce09132…`](https://etherscan.io/tx/0x4ce0913231fcb4ac1351f81c6632f53165a5a80dc1f44fc7ea9c31021e5c7b04) | *EigenPod checkpoint-proof verification* `0xf074ba62` | 229,856 | 191,015 | +38,841 | **0** (0.00%) | 0 | under the floor | 11 (7S/1C/1L1/1L2/1L3) |  |
| EigenLayer | [`0x03d50d7f…`](https://etherscan.io/tx/0x03d50d7f761256ff7ddcab530c0535f352ad8101d5d2912d67339e65e3c61b5d) | `forwardEigenPodCall` ✓ `0x297fdfe4` | 134,366 | 103,398 | +30,968 | **0** (0.00%) | 0 | under the floor | 1 (1C) |  |
| EigenLayer | [`0xc770332c…`](https://etherscan.io/tx/0xc770332c7e516902481cc309756988fbe452f58f89a1144713150fe083c1105e) | `forwardEigenPodCall` ✓ `0x297fdfe4` | 417,090 | 386,305 | +30,785 | **0** (0.00%) | 0 | under the floor | 1 (1C) |  |
| EigenLayer | [`0xbbc8abcb…`](https://etherscan.io/tx/0xbbc8abcb0eeb0f311b36ab4274e8629bd2b8c1395ffe79ffdebbcbf4536fbe29) | `forwardEigenPodCall` ✓ `0x297fdfe4` | 417,028 | 386,243 | +30,785 | **0** (0.00%) | 0 | under the floor | 1 (1C) |  |
| EigenLayer | [`0x95fa2d07…`](https://etherscan.io/tx/0x95fa2d07b579aaac9fa7e0fbd3545bcdb408c197956e0b4e34b9b29fa0f1cd9c) | *EigenLayer rewards claim* `0x3ccc861d` | 108,528 | 81,086 | +27,442 | **0** (0.00%) | 0 | under the floor | 5 (3S/1C/1L4) |  |
| EigenLayer | [`0x6fa0fbbf…`](https://etherscan.io/tx/0x6fa0fbbf87072c3315c4801db2ac55a1e6c58b009d9ff07234e9c84b7a84801e) | *EigenLayer rewards claim* `0x3ccc861d` | 125,638 | 98,174 | +27,464 | **0** (0.00%) | 0 | under the floor | 5 (3S/1C/1L4) |  |
| EigenLayer | [`0xf09b9b69…`](https://etherscan.io/tx/0xf09b9b69b3640f7b018509045180218c1c7acff17eb665fbc40bb9ad2003ed0b) | `queueWithdrawals` ✓ `0x0dd8dd02` | 440,373 | 471,942 | -31,569 | **0** (0.00%) | 0 | replay costs more | 24 (20S/2L1/1C/1L2) |  |
| EigenLayer | [`0x065a18a2…`](https://etherscan.io/tx/0x065a18a2af1e2d80514ad79067794b7c34e92ba2c2754c5cb7ddb5157eb111b8) | `queueWithdrawals` ✓ `0x0dd8dd02` | 439,868 | 469,142 | -29,274 | **0** (0.00%) | 0 | replay costs more | 24 (20S/2L1/1C/1L2) |  |
| EigenLayer | [`0x5ce19358…`](https://etherscan.io/tx/0x5ce19358229301efda44bc79908632dfc69c1609477d52438c3cd9add6950792) | `completeQueuedWithdrawal` ✓ `0xe4cc3f90` | 190,728 | 190,504 | +224 | **0** (0.00%) | 0 | under the floor | 17 (15S/1C/1L1) |  |
| EigenLayer | [`0xfb18ffe1…`](https://etherscan.io/tx/0xfb18ffe1164630f6d3a2c818f28404fcdc1782103870eadeaea75aaa0de4f0b9) | `completeQueuedWithdrawals` ✓ `0x9435bb43` | 186,142 | 188,312 | -2,170 | **0** (0.00%) | 0 | replay costs more | 17 (15S/1C/1L1) |  |
| EigenLayer | [`0xe5de910b…`](https://etherscan.io/tx/0xe5de910bc96de735b7bc040855d99c5b565baa1de8e14c373af2febb5076d19b) | `completeQueuedWithdrawals` ✓ `0x9435bb43` | 183,232 | 185,594 | -2,362 | **0** (0.00%) | 0 | replay costs more | 17 (15S/1C/1L1) |  |
| EigenLayer | [`0xaa858fcd…`](https://etherscan.io/tx/0xaa858fcd781a6a5afa142ccd9a802d0df1e2f68292f0abf8546426cda3fe6644) | *EigenLayer rewards claim* `0x3ccc861d` | 156,150 | 135,165 | +20,985 | **0** (0.00%) | 0 | under the floor | 8 (4S/2C/2L4) |  |
| EigenLayer | [`0x22b2c58c…`](https://etherscan.io/tx/0x22b2c58ced9f209d9ec2d21415436e9395067b377764d600927c8b54625f6d4f) | `startCheckpoint` ✓ `0x88676cad` | 76,444 | 52,517 | +23,927 | **0** (0.00%) | 0 | under the floor | 4 (3S/1L3) |  |
| Safe | [`0xa9eca9f1…`](https://etherscan.io/tx/0xa9eca9f1a7075c8eb971e7ee2a1a3ee514cf3cf6b1077d6ddcc4f60f8ebf4eaa) | `execTransaction` ✓ `0x6a761202` | 104,612 | 67,158 | +37,454 | **0** (0.00%) | 0 | under the floor | 3 (1C/1L2/1S) |  |
| Safe | [`0x5c559278…`](https://etherscan.io/tx/0x5c5592787da61ec8c46326d93089c14e667276fab45703077168e72dcbbee99e) | `execTransaction` ✓ `0x6a761202` | 115,958 | 78,540 | +37,418 | **0** (0.00%) | 0 | under the floor | 3 (1C/1L2/1S) |  |
| Safe | [`0x8951b058…`](https://etherscan.io/tx/0x8951b058f41486ff7d9c5806d187af52f7d969ae69ddbb85c1e1be04171dae04) | `execTransaction` ✓ `0x6a761202` | 3,251,629 | 3,220,361 | +31,268 | **0** (0.00%) | 0 | under the floor | 3 (1C/1L2/1S) |  |
| Safe | [`0xf20b6df4…`](https://etherscan.io/tx/0xf20b6df4702b6537ba520316a35552b6d1da7b696e3c69e34986ed901402bd56) | `execTransaction` ✓ `0x6a761202` | 11,414,223 | 11,400,916 | +13,307 | **0** (0.00%) | 0 | under the floor | 3 (1C/1L2/1S) | 11.4M gas, 3 state updates — all of it inside one call |
| Safe | [`0xdcc894ec…`](https://etherscan.io/tx/0xdcc894ec22dc799bd1cd8c24caa4bcd2a2d7f35ae2ba8ab7c431a07f76e5ba21) | `execTransaction` ✓ `0x6a761202` | 1,004,511 | 1,005,210 | -699 | **0** (0.00%) | 0 | replay costs more | 8 (6C/1L2/1S) |  |
| Safe | [`0xb286eeb1…`](https://etherscan.io/tx/0xb286eeb15c4cb3445a73e275e89336f7563eb46c2e9ec97a82aeefb5a4485430) | `execTransaction` ✓ `0x6a761202` | 463,470 | 442,944 | +20,526 | **0** (0.00%) | 0 | under the floor | 8 (6C/1L1/1S) |  |
| Safe | [`0x4e13a401…`](https://etherscan.io/tx/0x4e13a40100c52346b4e971697a347030ffd0cc5bd47d521e8b4a9baf1a984872) | `execTransaction` ✓ `0x6a761202` | 458,625 | 452,215 | +6,410 | **0** (0.00%) | 0 | under the floor | 9 (7C/1L2/1S) |  |
| Safe | [`0x5688590b…`](https://etherscan.io/tx/0x5688590bc26e704d720d7bb2185b195aabb310ba67dddd944f64509b1cf70513) | `execTransaction` ✓ `0x6a761202` | 322,338 | 297,128 | +25,210 | **0** (0.00%) | 0 | under the floor | 4 (2C/1L1/1S) |  |
| Safe | [`0xf6ebba6b…`](https://etherscan.io/tx/0xf6ebba6ba0e5e5f003598b5e05efbb737fb5e00e6a1818e58d1e565316f96b74) | `execTransaction` ✓ `0x6a761202` | 214,221 | 202,578 | +11,643 | **0** (0.00%) | 0 | under the floor | 6 (4C/1L2/1S) |  |
| Safe | [`0x909681b5…`](https://etherscan.io/tx/0x909681b5131c5ccc56e6f6791f152efe41cf270172c5a4645fc0067567bd8651) | `execTransaction` ✓ `0x6a761202` | 103,575 | 85,519 | +18,056 | **0** (0.00%) | 0 | under the floor | 4 (2L1/1C/1S) |  |
| Safe | [`0x2666f99a…`](https://etherscan.io/tx/0x2666f99a3b1ad225cf8dcc40fbafb1959a6efb5bb3c561b3d2d5a3b242ca4a29) | `execTransaction` ✓ `0x6a761202` | 96,660 | 73,351 | +23,309 | **0** (0.00%) | 0 | under the floor | 3 (1C/1L2/1S) |  |
| Safe | [`0xb2b17e51…`](https://etherscan.io/tx/0xb2b17e51681c60f3d66aa112fa13f070c5ea76c466e794e3ba360c8b833b5a55) | `execTransaction` ✓ `0x6a761202` | 75,536 | 70,129 | +5,407 | **0** (0.00%) | 0 | under the floor | 3 (1C/1L2/1S) |  |
| Pendle | [`0x75aceefb…`](https://etherscan.io/tx/0x75aceefb54f607c4de446308146e0b84ff405ec56a6e5bc24ccb88b3b5397991) | *third-party aggregator* `0xc685f647` | 1,719,271 | 1,624,535 | +94,736 | **44,736** (2.60%) | 0 | — | 9 (5C/1L2/1L3/1L4/1S) |  |
| Pendle | [`0xa2c6de73…`](https://etherscan.io/tx/0xa2c6de73e89c7bd707a9fe308d09c54eb16d2ddf9e3ff09f866d8a68e3948afd) | *third-party aggregator* `0xc685f647` | 1,183,159 | 1,157,967 | +25,192 | **0** (0.00%) | 0 | under the floor | 9 (5C/1L2/1L3/1L4/1S) |  |
| Pendle | [`0x8bd2985a…`](https://etherscan.io/tx/0x8bd2985af25143dbf0d3aa60f0e36bc50195d2702e4beeaf1576f8f4464200d7) | *Pendle router action* `0x60fc8466` | 1,018,948 | 1,020,097 | -1,149 | **0** (0.00%) | 0 | replay costs more | 8 (7C/1L4) |  |
| Pendle | [`0xa01ba5b6…`](https://etherscan.io/tx/0xa01ba5b6e8c9f78e7d4d324bd2b03da78a7d02cdf9fa852aa82b60dc400a586c) | *Pendle router action* `0xed48907e` | 768,674 | 762,631 | +6,043 | **0** (0.00%) | 0 | under the floor | 7 (6C/1L4) |  |
| Pendle | [`0x90476689…`](https://etherscan.io/tx/0x9047668966adcd340cf4b69b727a17c5df6c6f34d4bad1994f9cf5331e2329f7) | *Pendle router action* `0xed48907e` | 531,449 | 524,603 | +6,846 | **0** (0.00%) | 0 | under the floor | 7 (6C/1L4) |  |
| Pendle | [`0xa3ec8aea…`](https://etherscan.io/tx/0xa3ec8aea5dd4b01271f7dd979830a444ec2b3fa618f5e0afc550a2bd03af65a3) | *Pendle router action* `0xed48907e` | 370,167 | 359,084 | +11,083 | **0** (0.00%) | 0 | under the floor | 5 (4C/1L4) |  |
| Pendle | [`0xec4d1fdf…`](https://etherscan.io/tx/0xec4d1fdf22d55bdde9d358e329af22a6c3345032ce969c79afb9d5dea8487556) | *Pendle router action* `0x594a88cc` | 205,329 | 213,408 | -8,079 | **0** (0.00%) | 0 | replay costs more | 4 (3C/1L4) |  |
| Pendle | [`0xc503cb6f…`](https://etherscan.io/tx/0xc503cb6f653908693bc666cf764b7fbd18d25d1f2982bde550107e98c81559a0) | `swapSyForExactPt` ✓ `0x5b709f17` | 153,140 | 148,995 | +4,145 | **0** (0.00%) | 0 | under the floor | 10 (5S/3C/1L2/1L3) |  |
| Morpho | [`0x641b76f4…`](https://etherscan.io/tx/0x641b76f483f45a02815116bb7b0213530d0f2aee019b7cc4840a2d71a2940f0e) | *liquidator bot* `0xc2df23ef` | 721,933 | 707,735 | +14,198 | **0** (0.00%) | 0 | under the floor | 4 (3C) | **re-measured** — heuristic claimed 16.32% |
| Morpho | [`0xcd59750e…`](https://etherscan.io/tx/0xcd59750e91859ec6af4209c588997b61962dcec2aad6c549ef35324476870bdf) | `reallocate` ✓ `0x7299aa31` | 324,608 | 349,625 | -25,017 | **0** (0.00%) | 0 | replay costs more | 15 (10C) | **re-measured** — heuristic claimed 13.47% |
| Morpho | [`0x9a5fecc6…`](https://etherscan.io/tx/0x9a5fecc64422a0e8f8edb3b914eaed17cd675a09f1e2811a79d0cf0181893851) `heur` | *liquidator bot* `0x3f462f8f` | 2,661,881 | 2,335,360 | +326,521 | **276,521** (10.39%) | 76,521 | — | 8 (8C) |  |
| Morpho | [`0x80329618…`](https://etherscan.io/tx/0x80329618f5c5261829097e2a8a079c765c6ae0ce35f6d98e09a4d246a694c8bf) | `multicall` ✓ `0xac9650d8` | 380,049 | 343,154 | +36,895 | **0** (0.00%) | 0 | under the floor | 18 (10S/4C/3L3/1L1) |  |
| Morpho | [`0x6ed1eaa3…`](https://etherscan.io/tx/0x6ed1eaa33eff8b3b992ee3fc55d5548d2072edd5f32ba437854d784dc9e62946) `heur` | *liquidator bot* `0xca8bd1f9` | 307,371 | 273,856 | +33,515 | **0** (0.00%) | 0 | under the floor | 3 (3C) |  |
| Morpho | [`0x4e547494…`](https://etherscan.io/tx/0x4e547494fcf332b50465117a6467c8cb097787e4b54fd5b97ff6ff5cfec96ceb) | *flash-loan leverage* `0x642ba7a7` | 1,779,190 | 1,720,040 | +59,150 | **9,150** (0.51%) | 0 | — | 6 (3S/2C/1L1) |  |
| Morpho | [`0x16a0a31c…`](https://etherscan.io/tx/0x16a0a31c0547f2f35018c38f0c2fa3bdcf1320e6a75f998caaa957747e9dc568) `heur` | *flash-loan deleverage* `0x2f5066dd` | 1,312,558 | 1,577,595 | -265,037 | **0** (0.00%) | 0 | replay costs more | 1 (1C) |  |
| Morpho | [`0xb1bf36be…`](https://etherscan.io/tx/0xb1bf36beaf1aeeb69e575a1230468d917ef4646c6416ab465201bca70d8c7a72) | `multicall` ✓ `0xac9650d8` | 1,278,050 | 1,457,568 | -179,518 | **0** (0.00%) | 0 | replay costs more | 84 (45S/22C/12L3/5L1) |  |
| Morpho | [`0x1c71eb76…`](https://etherscan.io/tx/0x1c71eb76549cc6a80467e06e8bc938b7fc1e67e9575c2aece8d98345243bb218) | *9-market reallocation* `0xeb7499cf` | 725,295 | 699,768 | +25,527 | **0** (0.00%) | 0 | under the floor | 1 (1C) | missed the old 27,000 floor by 1,473 gas; 24,473 short of 50,000 |
| Morpho | [`0x09fd0f6e…`](https://etherscan.io/tx/0x09fd0f6eb66388ce7cdc484b2020d300b5c6d519df89c5bddc73307d9e68bd80) `heur` | *liquidator bot* `0x1a28e979` | 619,024 | 733,358 | -114,334 | **0** (0.00%) | 0 | replay costs more | 2 (1C/1L3) |  |
| Morpho | [`0x482fb3b2…`](https://etherscan.io/tx/0x482fb3b2dfb2d336237a0112285a14d7847af91006e64e6fd442f11864360e9c) | *liquidator bot* `0xc35d5cb3` | 457,129 | 462,926 | -5,797 | **0** (0.00%) | 0 | replay costs more | 4 (4C) |  |
| Morpho | [`0x9a08a526…`](https://etherscan.io/tx/0x9a08a526e05f5fe827840f0ec4e3d1ce31906fa5a7a9bda7677098e4d78903df) `heur` | *flash-loan MEV bot* `0x03f00196` | 420,293 | 414,721 | +5,572 | **0** (0.00%) | 0 | under the floor | 5 (5C) |  |
| Morpho | [`0xbeffded8…`](https://etherscan.io/tx/0xbeffded8df725752edea428f171d8ec2a842dcdb645977ea9cf5bedba14ca414) | `reallocate` ✓ `0x7299aa31` | 416,744 | 451,366 | -34,622 | **0** (0.00%) | 0 | replay costs more | 18 (12C/6L3) |  |
| Morpho | [`0x1338ba16…`](https://etherscan.io/tx/0x1338ba16b0a7f61988caf43896fde0e32edac97cd7dab32bb6136bf9e77f0302) | *flash-loan MEV bot* `0x99999999` | 405,201 | 423,289 | -18,088 | **0** (0.00%) | 0 | replay costs more | 1 (1C) |  |
| Morpho | [`0xe520cf76…`](https://etherscan.io/tx/0xe520cf761e3fd61b115b0f31bd7f182a9cce43ec747b1aeaf77bf3457ebdc91f) | `multicall` ✓ `0xac9650d8` | 366,689 | 393,924 | -27,235 | **0** (0.00%) | 0 | replay costs more | 24 (13S/6C/3L3/2L1) |  |
| Morpho | [`0x584c52d9…`](https://etherscan.io/tx/0x584c52d957c165432f32e42e0ebacc4683d0e6f9cb251d926060701f8f71322b) | *flash-loan liquidation* `0xeddba708` | 362,143 | 382,655 | -20,512 | **0** (0.00%) | 0 | replay costs more | 8 (6S/2C) |  |
| Morpho | [`0x3dffb38b…`](https://etherscan.io/tx/0x3dffb38b03f52c07073a0ad32f336c5d3106640c2462f72204c9d6fe02534ed1) | `multicall` ✓ `0xac9650d8` | 360,323 | 371,754 | -11,431 | **0** (0.00%) | 0 | replay costs more | 8 (6C/2S) |  |
| Morpho | [`0x8e4616ac…`](https://etherscan.io/tx/0x8e4616acfaf812a41b471e139924a1bc906e03e8e1203760ae6117113682b760) | `multicall` ✓ `0xac9650d8` | 312,814 | 314,184 | -1,370 | **0** (0.00%) | 0 | replay costs more | 18 (10S/4C/3L3/1L1) |  |
| Morpho | [`0x50305a21…`](https://etherscan.io/tx/0x50305a216cbeabbc02ad2262619090e91c6928ecc30def46af4eaab7bde99e9b) | `multicall` ✓ `0xac9650d8` | 179,644 | 183,470 | -3,826 | **0** (0.00%) | 0 | replay costs more | 5 (3C/2S) |  |
| Morpho | [`0x8d0c4018…`](https://etherscan.io/tx/0x8d0c40187a36dd2de2b64800b87d8db9b235624479d35202a11c2b2fb98fd76a) | `multicall` ✓ `0xac9650d8` | 157,756 | 161,582 | -3,826 | **0** (0.00%) | 0 | replay costs more | 5 (3C/2S) |  |
| Morpho | [`0xdc74e020…`](https://etherscan.io/tx/0xdc74e020e296fbb968edfc2ffd630bad47d557c71dabe901938315be6329c5c9) `heur` | *router* `0x374f435d` | 134,366 | 148,620 | -14,254 | **0** (0.00%) | 0 | replay costs more | 2 (2C) |  |
| Morpho | [`0x441cd851…`](https://etherscan.io/tx/0x441cd85183e88986305c0721c98bdd3c25edbe5ecc4578baeb964f09b8b42686) | `withdrawCollateral` ✓ `0x8720316d` | 132,478 | 158,129 | -25,651 | **0** (0.00%) | 0 | replay costs more | 8 (4S/2C/1L2/1L4) |  |
| Morpho | [`0x2d7cebfe…`](https://etherscan.io/tx/0x2d7cebfe726192fe692ccfa905b401fdedb108f5a3ecdf34aff20d2e77b3c320) `heur` | *router* `0x374f435d` | 122,812 | 126,798 | -3,986 | **0** (0.00%) | 0 | replay costs more | 3 (3C) |  |
| Morpho | [`0x4419f117…`](https://etherscan.io/tx/0x4419f1176b254fa8b1f0cb0daa7093b223379894701addb921fa02f00f373f8d) | `withdraw` ✓ `0x5c2bea49` | 111,792 | 142,279 | -30,487 | **0** (0.00%) | 0 | replay costs more | 10 (6S/2C/1L2/1L4) |  |
| Morpho | [`0x8a27bff6…`](https://etherscan.io/tx/0x8a27bff6e7606ee0f89b63f01241c1a6a8d5cff37d726ee413df165b243c2f64) | `supply` ✓ `0xa99aad89` | 99,912 | 130,941 | -31,029 | **0** (0.00%) | 0 | replay costs more | 10 (6S/2C/1L2/1L4) |  |
| World ID | [`0xa447c2d3…`](https://etherscan.io/tx/0xa447c2d3d0786a32f8b23c0f571e714e91d4d812b575d7bee27864c7c3e8c556) | `registerIdentities` ✓ `0x2217b211` | 298,629 | 263,051 | +35,578 | **0** (0.00%) | 0 | under the floor | 4 (2S/1C/1L4) |  |
| World ID | [`0x36c09544…`](https://etherscan.io/tx/0x36c095445eb96f2ccaa2a2ec9544ac2cf72aa524c36c0ce23c0aecc2cf36b8b7) | `registerIdentities` ✓ `0x2217b211` | 285,261 | 263,075 | +22,186 | **0** (0.00%) | 0 | under the floor | 4 (2S/1C/1L4) |  |
| World ID | [`0x6b2fb8d3…`](https://etherscan.io/tx/0x6b2fb8d32c1fc927e5c37ae0ca52d17cb122b949ec0140f75a8212164911f494) | `registerIdentities` ✓ `0x2217b211` | 282,573 | 263,039 | +19,534 | **0** (0.00%) | 0 | under the floor | 4 (2S/1C/1L4) |  |
| World ID | [`0xb2f5ba58…`](https://etherscan.io/tx/0xb2f5ba588077025662acd44f62ead62c4dc6da4faa30890d658542aedcaef3c5) | `registerIdentities` ✓ `0x2217b211` | 281,457 | 263,051 | +18,406 | **0** (0.00%) | 0 | under the floor | 4 (2S/1C/1L4) |  |
| World ID | [`0xcd404a27…`](https://etherscan.io/tx/0xcd404a27462a9e60fdd5a17c024d758d809f860ad2da9f1709882d497276375a) | `registerIdentities` ✓ `0x2217b211` | 281,445 | 263,051 | +18,394 | **0** (0.00%) | 0 | under the floor | 4 (2S/1C/1L4) |  |
| World ID | [`0x04ca8194…`](https://etherscan.io/tx/0x04ca81943592e11ddbce6e4fac96c0f84debb12c8d972bd3f910dc8bf77274de) | `deleteIdentities` ✓ `0xea10fbbe` | 271,876 | 263,087 | +8,789 | **0** (0.00%) | 0 | under the floor | 4 (2S/1C/1L4) |  |
| World ID | [`0x2fee0848…`](https://etherscan.io/tx/0x2fee084888a10a8cf80c30b36bf511e8ba499e517d49dbc0ca2a97d4c4e160e6) | `deleteIdentities` ✓ `0xea10fbbe` | 271,816 | 263,075 | +8,741 | **0** (0.00%) | 0 | under the floor | 4 (2S/1C/1L4) |  |
| Ondo | [`0x4551339c…`](https://etherscan.io/tx/0x4551339cc87aabe9c57e492856f0af4c5cc00666be7bbfbd00ee8117d6b2327c) | *flash-loan MEV bot* `0x24c12020` | 1,799,146 | 1,531,651 | +267,495 | **217,495** (12.09%) | 17,495 | — | 11 (8S/2C/1L2) | not really Ondo — MEV bot, only 4 of 31 logs are Ondo |
| Ondo | [`0x10fdab16…`](https://etherscan.io/tx/0x10fdab165e2a37d70223b9546f80e9f7a248e1a0ccacd6638bbc66d565de8c35) | *Ondo instant mint* `0xd8780161` | 350,502 | 316,467 | +34,035 | **0** (0.00%) | 0 | under the floor | 10 (7C/2S/1L3) |  |
| Ondo | [`0x197c9a14…`](https://etherscan.io/tx/0x197c9a14ed634444154e66fb75bfa167b874dfbba78b463c62f5b390063c8965) | *third-party aggregator* `0x146ee74d` | 3,290,733 | 3,209,798 | +80,935 | **30,935** (0.94%) | 0 | — | 1 (1C) | not really Ondo — aggregator, only 5 of 190 logs are Ondo |
| Ondo | [`0x089be390…`](https://etherscan.io/tx/0x089be390aab1f47562520e714e3d96b270c279b0c2a7b2876c933ee390a264b0) | *Ondo instant mint* `0xd8780161` | 447,366 | 413,235 | +34,131 | **0** (0.00%) | 0 | under the floor | 10 (7C/2S/1L3) |  |
| Ondo | [`0x23ac6eda…`](https://etherscan.io/tx/0x23ac6eda7ddb46309b5d61628b5f24ced1b1c1cb608470d451f6dfb869fc6242) | *Ondo instant redeem* `0x22d4a175` | 432,419 | 400,729 | +31,690 | **0** (0.00%) | 0 | under the floor | 10 (7C/2S/1L3) |  |
| Ondo | [`0xe16fb5bc…`](https://etherscan.io/tx/0xe16fb5bcb8d2d4d2a2a9d3c7b92d7388e8e8af784f771d3bd0f3250daeb54e42) | `settle` ✓ `0x13d79a0b` | 3,611,533 | 3,660,592 | -49,059 | **0** (0.00%) | 0 | replay costs more | 1 (1C) |  |
| Ondo | [`0xfccb2eda…`](https://etherscan.io/tx/0xfccb2eda50342893f6f1e93b0fb08df57dff595d17ac74414a688d1bfe3aaa78) | *third-party router* `0x81a794cb` | 819,503 | 843,764 | -24,261 | **0** (0.00%) | 0 | replay costs more | 15 (9S/5C/1L4) |  |
| Ondo | [`0xd8ea9b21…`](https://etherscan.io/tx/0xd8ea9b2158d7bf3407ea618ad07e3f7debc096076e108f6c166ca9fa53e9ec37) | `settle` ✓ `0x13d79a0b` | 519,037 | 542,092 | -23,055 | **0** (0.00%) | 0 | replay costs more | 13 (5C/5L2/3S) |  |
| Euler | [`0x0a06e978…`](https://etherscan.io/tx/0x0a06e9783d4bc563d8b4674112b2dd427597c80a1095c377e6b88e307b31927c) | `batch` ✓ `0xc16ae7a4` | 548,011 | 513,820 | +34,191 | **0** (0.00%) | 0 | under the floor | 29 (16S/5C/3L3/3L4/2L2) |  |
| Euler | [`0x575f2fb2…`](https://etherscan.io/tx/0x575f2fb2224cf67a0a3a8cca18def46bbf327eb72e1ac1414771dffd6f4a67f3) `heur` | *third-party contract* `0x1d23a9c4` | 3,036,470 | 3,319,285 | -282,815 | **0** (0.00%) | 0 | replay costs more | 4 (4C) |  |
| Euler | [`0x1fd83b06…`](https://etherscan.io/tx/0x1fd83b06274079376b85f63220bbfb16cdfe1279ad5b8d07bd613a68b7639ca3) `heur` | *third-party contract* `0x1d23a9c4` | 2,715,594 | 3,069,384 | -353,790 | **0** (0.00%) | 0 | replay costs more | 4 (4C) |  |
| Euler | [`0x7d1e2345…`](https://etherscan.io/tx/0x7d1e2345c39b884a16eb6b2e06c1c4a4177c5639fe1c91474a356c3eef04fd87) | *third-party contract* `0x3271ba8d` | 2,701,108 | 2,683,478 | +17,630 | **0** (0.00%) | 0 | under the floor | 7 (3C/3S/1L2) |  |
| Euler | [`0xf6e16544…`](https://etherscan.io/tx/0xf6e16544c8c04199f8318649d05ab68f3ddd4ea2c1f7dee9cab98a0301afd0ad) `heur` | `batch` ✓ `0xc16ae7a4` | 1,531,193 | 1,608,623 | -77,430 | **0** (0.00%) | 0 | replay costs more | 152 (80S/33C/31L4/6L3/2L2) |  |
| Euler | [`0xc3543837…`](https://etherscan.io/tx/0xc3543837e22a84fb06798cb626d7a1cc716329fdf15fb675eafc587911090206) | `batch` ✓ `0xc16ae7a4` | 1,415,274 | 1,871,874 | -456,600 | **0** (0.00%) | 0 | replay costs more | 158 (82S/37C/35L4/2L2/2L3) | worst result measured anywhere |
| Euler | [`0xa32effd3…`](https://etherscan.io/tx/0xa32effd3b31a02343d8cf4362c4fee2e806ea9dcf00fdea5eb1a2b054ae0ea4a) | `batch` ✓ `0xc16ae7a4` | 499,524 | 482,833 | +16,691 | **0** (0.00%) | 0 | under the floor | 29 (16S/5C/3L3/3L4/2L2) |  |
| Euler | [`0x10c755ee…`](https://etherscan.io/tx/0x10c755eea1865f9761e49f2e52dd700d8ecc4e0037057bb2ea05df24bb946095) | `batch` ✓ `0xc16ae7a4` | 203,620 | 244,538 | -40,918 | **0** (0.00%) | 0 | replay costs more | 14 (8S/3C/2L4/1L2) |  |
| Chainlink | [`0xff646682…`](https://etherscan.io/tx/0xff6466828843a8e795e4b6ae1b29644a148141dd48784b4be99c58b0ad3be268) | `forward` ✓ `0x6fadcf72` | 716,016 | 718,282 | -2,266 | **0** (0.00%) | 0 | replay costs more | 1 (1C) |  |
| Chainlink | [`0x6fc803ec…`](https://etherscan.io/tx/0x6fc803ecc426f8d20c9bcbdcc6c8118a1d8f22395a9702a7145fd7586adf4d80) | `forward` ✓ `0x6fadcf72` | 183,165 | 185,665 | -2,500 | **0** (0.00%) | 0 | replay costs more | 1 (1C) |  |
| Chainlink | [`0x0937e5c9…`](https://etherscan.io/tx/0x0937e5c9c7070b119608b28b836efc1c435ce7327f78ff00fff7fcc9ac1eef5f) | `forward` ✓ `0x6fadcf72` | 182,433 | 184,933 | -2,500 | **0** (0.00%) | 0 | replay costs more | 1 (1C) |  |
| Chainlink | [`0x973a53f5…`](https://etherscan.io/tx/0x973a53f585cbf82e951c96c24b58f1639a88f2935e6964ef4ac084ea10fcd278) | `forward` ✓ `0x6fadcf72` | 145,183 | 147,547 | -2,364 | **0** (0.00%) | 0 | replay costs more | 1 (1C) |  |
| Chainlink | [`0x9da346d0…`](https://etherscan.io/tx/0x9da346d0b79f055e1ac769f289ec0d449c4a20711c86300fa9230e817e069c95) | `forward` ✓ `0x6fadcf72` | 145,015 | 147,379 | -2,364 | **0** (0.00%) | 0 | replay costs more | 1 (1C) |  |
| Chainlink | [`0x4b8d2ac4…`](https://etherscan.io/tx/0x4b8d2ac44a640f4ce2b9fb274f5d1e3760ca324395aeaa3774190e99e41a10c9) | `forward` ✓ `0x6fadcf72` | 136,406 | 138,725 | -2,319 | **0** (0.00%) | 0 | replay costs more | 1 (1C) |  |
| Chainlink | [`0xf200bdfd…`](https://etherscan.io/tx/0xf200bdfd609fdb4228a02f6279e2968da2fc4c27590a3eadf5371843c5b5c6d0) | `forward` ✓ `0x6fadcf72` | 136,394 | 138,713 | -2,319 | **0** (0.00%) | 0 | replay costs more | 1 (1C) |  |
| Chainlink | [`0xa676c243…`](https://etherscan.io/tx/0xa676c24374af6324558937b595e3a94fca0fb817823fd22a24ea0f783ebffc6c) | `forward` ✓ `0x6fadcf72` | 136,046 | 138,365 | -2,319 | **0** (0.00%) | 0 | replay costs more | 1 (1C) |  |

Update shorthand: `S` storage write, `C` call, `L0`–`L4` log with that many topics, `Cr` contract creation.

| Panther | [`0x63338b98…`](https://etherscan.io/tx/0x63338b98cb3c6bf3390a7f7dcb84e25766424b7a1c6444b4b1b3c89f9059d134) | *staking* `0x7f678334` | 207,193 | 226,374 | -19,181 | **0** (0.00%) | 0 | replay costs more | 11 (8S/1L3/2C) | only Panther mainnet tx in 200k blocks |

| Ethena | [`0x5055ea7f…`](https://etherscan.io/tx/0x5055ea7ff088407138215ddbe45b9cedfc334cda7e791d0eba4061aea819015c) | *mint* `0x96eea750` | 241,268 | 192,569 | +48,699 | **0** (0.00%) | 0 | under the floor | — | **900B order — 1 of 309 mints** |
| Ethena | [`0xb3a29f2b…`](https://etherscan.io/tx/0xb3a29f2bdcb1573d2f3b7d613a08415854df6ea60d356c9611248856474a8a21) | *mint* `0x96eea750` | 219,295 | 204,750 | +14,545 | **0** (0.00%) | 0 | under the floor | — |  |
| Ethena | [`0xae6a3e25…`](https://etherscan.io/tx/0xae6a3e25f711d88ab06a1729ec60acf771c33e83877b2ac7885661cfe0d4d253) | *mint* `0x96eea750` | 210,560 | 192,497 | +18,063 | **0** (0.00%) | 0 | under the floor | — | heuristic first claimed 36.96% |
| Ethena | [`0xd2475759…`](https://etherscan.io/tx/0xd2475759c71f278896ea7ff15ca213bb17dc9c3e0b29ddfdc8e1e01424995ae0) | *mint* `0x96eea750` | 208,058 | 190,820 | +17,238 | **0** (0.00%) | 0 | under the floor | — | heuristic first claimed 33.91% |
| Ethena | [`0x91e950a3…`](https://etherscan.io/tx/0x91e950a3e5497de1908db495bd8432a9068865314a8bba6e2ee3f800eb9c0e41) | *mint* `0x96eea750` | 208,046 | 190,808 | +17,238 | **0** (0.00%) | 0 | under the floor | — | heuristic first claimed 33.90% |
| Ethena | [`0x2bdf6644…`](https://etherscan.io/tx/0x2bdf664447b22de7c275becd81ff56775417e0544812417ee0dadc95232a6fd4) | *mint* `0x96eea750` | 207,927 | 192,581 | +15,346 | **0** (0.00%) | 0 | under the floor | — |  |
| Ethena | [`0xe6f15a94…`](https://etherscan.io/tx/0xe6f15a94892f1ec9a52263ba0a8869c081db57bc9c48558b31e9cc1e3609e126) | *mint* `0x96eea750` | 205,401 | 190,844 | +14,557 | **0** (0.00%) | 0 | under the floor | — |  |
| Ethena | [`0xba225f3e…`](https://etherscan.io/tx/0xba225f3ef9ad52f911771e967f5e81e83fc0cdebe5eb1cd996012e4aa543ef21) | *mint* `0x96eea750` | 202,207 | 187,626 | +14,581 | **0** (0.00%) | 0 | under the floor | — |  |
| Ethena | [`0xe67e1c84…`](https://etherscan.io/tx/0xe67e1c8420c330116b81cb6e9bd73d5016058267d390701dd8fab89e592877d0) | *mint* `0x96eea750` | 202,195 | 187,602 | +14,593 | **0** (0.00%) | 0 | under the floor | — |  |
| Ethena | [`0x1c4c1779…`](https://etherscan.io/tx/0x1c4c1779b4b03b196c1e2891be88fb9771f33931fc356597ae5be7f54433b264) | *mint* `0x96eea750` | 200,589 | 186,044 | +14,545 | **0** (0.00%) | 0 | under the floor | — |  |
| Ethena | [`0xaf1a2df7…`](https://etherscan.io/tx/0xaf1a2df790dc89d457abe7cfb14a5be4e6d32d92a547e2f991479dcbdd7321f3) | *mint* `0x96eea750` | 200,023 | 189,422 | +10,601 | **0** (0.00%) | 0 | under the floor | — | heuristic first claimed 34.99% |
| Ethena | [`0x0e4976bf…`](https://etherscan.io/tx/0x0e4976bf08241feb978fc57172e36ea04a066b0bd242c3952ce06fabfd03ade8) | *mint* `0x96eea750` | 200,023 | 189,422 | +10,601 | **0** (0.00%) | 0 | under the floor | — |  |
| Ethena | [`0x2b762d27…`](https://etherscan.io/tx/0x2b762d27b09d8f0b8a221a71bc3e3544e55b7c34d9a44edfd566fa5ebc739ed7) | *mint* `0x96eea750` | 200,011 | 189,446 | +10,565 | **0** (0.00%) | 0 | under the floor | — |  |
| Ethena | [`0xcfea9cfa…`](https://etherscan.io/tx/0xcfea9cfa79f814a7ff93a431c56dde3b9feeb10a86e8dde41c00ce3adf6d7ec2) | *mint* `0x96eea750` | 185,047 | 170,454 | +14,593 | **0** (0.00%) | 0 | under the floor | — |  |
| Ethena | [`0x9786d142…`](https://etherscan.io/tx/0x9786d142e2a872dda2f8af0c108635e8f638b9779b62170fd8692eb3ed633632) | *sUSDe* | 407,179 | 409,604 | -2,425 | **0** (0.00%) | 0 | replay costs more | — |  |
| Ethena | [`0xc371b418…`](https://etherscan.io/tx/0xc371b418f7a88c1bcbce3ebee77145ac28e6f9764569d11de55a2a86fc7fd0fb) | `cooldownShares` ✓ `0x9343d9e1` | 89,471 | 103,472 | -14,001 | **0** (0.00%) | 0 | replay costs more | — |  |
| Ethena | [`0xd6e74eef…`](https://etherscan.io/tx/0xd6e74eef135030ef66c96c65247c0595d81d8de790923139eabe419800752aba) | `cooldownShares` ✓ `0x9343d9e1` | 89,459 | 103,460 | -14,001 | **0** (0.00%) | 0 | replay costs more | — |  |
| Ethena | [`0x6f12cb87…`](https://etherscan.io/tx/0x6f12cb8706d5c2f6fa999ff37dd5728cd9530d0d9c256efc715800df45d72403) | `deposit` ✓ `0x6e553f65` | 88,423 | 99,316 | -10,893 | **0** (0.00%) | 0 | replay costs more | — | heuristic first claimed 3.94% |
| Ethena | [`0x20437c45…`](https://etherscan.io/tx/0x20437c4593fc6e80acdd78578e134c336cc0a1f827e56cb36a18e8becb5d62e0) | *sUSDe* | 84,342 | 83,451 | +891 | **0** (0.00%) | 0 | under the floor | — |  |
| Ethena | [`0xe9eebd35…`](https://etherscan.io/tx/0xe9eebd353a8623401f2106e17a73cf433f31c3f6ac45722ffe61c2f70965e5cd) `heur` | `deposit` ✓ `0x6e553f65` | 83,659 | 57,942 | +25,717 | **0** (0.00%) | 0 | under the floor | — |  |
| Ethena | [`0x7a4241aa…`](https://etherscan.io/tx/0x7a4241aa594bf958bdb4c5fa93ef04a12f6cc1f6b854584000349f75c809b11d) `heur` | `cooldownShares` ✓ `0x9343d9e1` | 72,371 | 65,909 | +6,462 | **0** (0.00%) | 0 | under the floor | — |  |
| Ethena | [`0x03c37967…`](https://etherscan.io/tx/0x03c37967a8003d273e3a8b8518689d304fd03c93d429754f0df4a66e663355af) `heur` | `deposit` ✓ `0x6e553f65` | 66,559 | 57,942 | +8,617 | **0** (0.00%) | 0 | under the floor | — |  |

| ERC-4337 EntryPoint | [`0x030b4fd3…`](https://etherscan.io/tx/0x030b4fd3776594fc57df6451e83b61e916554227a0c7208f2f6a039f9a2bc312) | `handleOps` | 1,694,622 | 201,100 | +1,493,522 | **1,443,522** (85.18%) | — | — | — | **SUSPECT** — see EntryPoint section |
| ERC-4337 EntryPoint | [`0xb752f16b…`](https://etherscan.io/tx/0xb752f16bd51240342af289dfffebd5276e28ec313eb12ba8bf4ad654794bd807) | `handleOps` | 1,103,781 | 186,440 | +917,341 | **867,341** (78.58%) | — | — | — | **SUSPECT** — reproduced twice, but see EntryPoint section |
| ERC-4337 EntryPoint | [`0x112f2b10…`](https://etherscan.io/tx/0x112f2b10d8e6fc37032a3103957c8324db6cee480bf030da56bbbcc5bec5816e) | `handleOps` | 2,137,036 | 2,205,725 | -68,689 | **0** (0.00%) | — | replay costs more | — | structurally identical to the 86.54% row |
| ERC-4337 EntryPoint | [`0x98949778…`](https://etherscan.io/tx/0x989497784755fae4ffaefe945aa8309269455dc966784e3d0a8a8224cf5c27a4) | `handleOps` | 1,141,959 | 1,208,050 | -66,091 | **0** (0.00%) | — | replay costs more | — |  |
| ERC-4337 EntryPoint | [`0xe64e4eb1…`](https://etherscan.io/tx/0xe64e4eb1fc3306f4eb081b65fc8b3bdf3e2e21c7478980fa9c13aa70540e8e2b) | `handleOps` | 177,986 | 228,198 | -50,212 | **0** (0.00%) | — | replay costs more | — |  |
| ERC-4337 EntryPoint | [`0xf177394e…`](https://etherscan.io/tx/0xf177394e40b6e52101c309fa9be07aa66711250e6e981c996c2080324a1a9c89) | `handleOps` | 177,986 | 228,174 | -50,188 | **0** (0.00%) | — | replay costs more | — |  |
| ERC-4337 EntryPoint | [`0x92f6ec5b…`](https://etherscan.io/tx/0x92f6ec5bede29c44849b7bd1f12f86ff4965022525ada840029eaa676c4ceedb) | `handleOps` | 165,688 | 207,785 | -42,097 | **0** (0.00%) | — | replay costs more | — | EntryPoint v0.6 |
| ERC-4337 EntryPoint | [`0x773e691e…`](https://etherscan.io/tx/0x773e691ea71b9e0b99e8599fa29e9ea9097c73de92e66d25bad564f17a264dad) | `handleOps` | 145,170 | 183,888 | -38,718 | **0** (0.00%) | — | replay costs more | — | EntryPoint v0.6 |

| Lido | [`0x69d40f3d…`](https://etherscan.io/tx/0x69d40f3d0e599963cd619a61cbf60a1c3e847e9f2f87796a139561b53cec4424) | `addSigningKeysOperatorBH` ✓ `0x805911ae` | 5,887,344 | 6,739,086 | -851,742 | **0** (0.00%) | 0 | replay costs more | 306 (·/1C) | largest tx in survey; 306 writes |
| Lido | [`0x21fa690f…`](https://etherscan.io/tx/0x21fa690fbbbbefec96c3fb533b2e0b6a275e9f0bad3fa7f6c71ccec9de398461) | `addSigningKeysOperatorBH` ✓ `0x805911ae` | 5,887,248 | 6,739,014 | -851,766 | **0** (0.00%) | 0 | replay costs more | 306 (·/1C) |  |
| Lido | [`0xf9a0c484…`](https://etherscan.io/tx/0xf9a0c48463e92a01347aadfefbf9349ec72858550a8fa162e894f61e9e99a499) | *oracle report* `0x11a78d23` | 1,729,395 | 1,682,837 | +46,558 | **0** (0.00%) | 0 | under the floor | 9 (·/4C) | only Lido function that pays |
| Lido | [`0x1bad3438…`](https://etherscan.io/tx/0x1bad343834044681f393485bcf131863801ff082da4fe24a2095629a7332d517) | *oracle report* `0x11a78d23` | 1,721,688 | 1,675,339 | +46,349 | **0** (0.00%) | 0 | under the floor | 9 (·/4C) |  |
| Lido | [`0x341d60b7…`](https://etherscan.io/tx/0x341d60b7870a57c2fa6d31a6935bfa143f0cff41685fa038661fd8721e7b4a92) | *registry* `0x8f73c5ae` | 978,934 | 1,038,649 | -59,715 | **0** (0.00%) | 0 | replay costs more | 73 (·/37C) |  |
| Lido | [`0x0df2c733…`](https://etherscan.io/tx/0x0df2c7332dd34a84ee404631b5431648ecce7e791ddb93f37c3fd9a3ce7206c9) | *registry* `0x8f73c5ae` | 978,934 | 1,038,632 | -59,698 | **0** (0.00%) | 0 | replay costs more | 73 (·/37C) | heuristic first claimed 25.84% |
| Lido | [`0x6e2453d1…`](https://etherscan.io/tx/0x6e2453d1b4b55a31ffb9fd94b38a6475c6fc68727e83edbc30078829274b4446) | `claimWithdrawals` ✓ `0xacf41e4d` | 261,492 | 275,614 | -14,122 | **0** (0.00%) | 0 | replay costs more | 10 (·/2C) |  |
| Lido | [`0xdfbaead0…`](https://etherscan.io/tx/0xdfbaead0d3c07378a6265a5093d029987518e7c75ede86ceb7b41d7f6fead305) | `claimWithdrawals` ✓ `0xacf41e4d` | 261,468 | 275,626 | -14,158 | **0** (0.00%) | 0 | replay costs more | 10 (·/2C) |  |
| Lido | [`0x07dfd955…`](https://etherscan.io/tx/0x07dfd9551205d17c73cd997e2ccf76708f60eae947999636a7e96b5f45f908f2) | *wstETH withdrawal* `0x7951b76f` | 258,886 | 276,945 | -18,059 | **0** (0.00%) | 0 | replay costs more | 11 (·/3C) |  |
| Lido | [`0x8af05a00…`](https://etherscan.io/tx/0x8af05a00ef89fdbc3c3cd246e5274c935f7a45869cba96ebbfd1aaea451db50f) | `requestWithdrawals` ✓ `0xd6681042` | 215,719 | 225,836 | -10,117 | **0** (0.00%) | 0 | replay costs more | 9 (·/1C) |  |
| Lido | [`0x954e6c05…`](https://etherscan.io/tx/0x954e6c05327ab8ac475eb27d646450b600826ed279ca5c99ca3ab90e1f953177) | `requestWithdrawals` ✓ `0xd6681042` | 215,683 | 225,752 | -10,069 | **0** (0.00%) | 0 | replay costs more | 9 (·/1C) |  |
| Lido | [`0x9f518648…`](https://etherscan.io/tx/0x9f51864813f2f5744a5114d7345653ef2c1b8d87b9e479317020a14153e9b490) | `claimWithdrawals` ✓ `0xe3afe0a3` | 131,269 | 171,727 | -40,458 | **0** (0.00%) | 0 | replay costs more | 26 (·/3C) |  |
| Lido | [`0x076a9688…`](https://etherscan.io/tx/0x076a9688c14bf3e1af823eb525fe3243176492d5c246567cbe6b5680bdef7844) | `claimWithdrawals` ✓ `0xe3afe0a3` | 81,977 | 80,590 | +1,387 | **0** (0.00%) | 0 | under the floor | 8 (·/1C) |  |


| **Pyth** | [`0x8874d5a5…`](https://etherscan.io/tx/0x8874d5a5dd22f4be257985b269f6c6ded6f28e08f0a572280d49d2db9a3a347a) | `updatePriceFeedsIfNecessary` ✓ `0xb9256d28` | 279,375 | 113,369 | +166,006 | **116,006** (41.52%) | 0 | — | 12 | 2884B calldata. recovered from heuristic (claimed 65.79%) |
| **Pyth** | [`0xbf483557…`](https://etherscan.io/tx/0xbf4835576f7677f4d93a6f96fe75671c0dd19362652bb1cf5c8622cec1d54fb9) | `updatePriceFeedsIfNecessary` ✓ `0xb9256d28` | 278,401 | 113,441 | +164,960 | **114,960** (41.29%) | 0 | — | 12 | 2884B calldata.  |
| **Pyth** | [`0x616ba1cd…`](https://etherscan.io/tx/0x616ba1cd828ee4f0e63a5be3e09df5d8ef28e0661e8c396f45658cdca477fea9) | `updatePriceFeedsIfNecessary` ✓ `0xb9256d28` | 193,725 | 42,864 | +150,861 | **100,861** (52.06%) | 0 | — | 3 | 1636B calldata. **best** — 1 feed written; recovered from heuristic |
| **Pyth** | [`0xf8800e04…`](https://etherscan.io/tx/0xf8800e04ea63017f9a4ffe500a4399c72a5606f243230a351c5758828568757b) | `updatePriceFeedsIfNecessary` ✓ `0xb9256d28` | 192,005 | 42,864 | +149,141 | **99,141** (51.63%) | 0 | — | 3 | 1636B calldata. 1 feed written |
| **Pyth** | [`0xa8ae7011…`](https://etherscan.io/tx/0xa8ae70119c42ea2fb646f18a81b58f4263ae9cce624e0d44301abee3960ba7d4) | `executeGovernanceInstruction` ✓ `0xb6ed701e` | 194,705 | 55,548 | +139,157 | **89,157** (45.79%) | 0 | — | 3 | 1028B calldata. governance instruction |
| **Pyth** | [`0xab298442…`](https://etherscan.io/tx/0xab2984424844b5a4120660896eddea19589458b583b7a7279b8d951ddb2e90db) | `updatePriceFeedsIfNecessary` ✓ `0xb9256d28` | 195,034 | 113,393 | +81,641 | **31,641** (16.22%) | 0 | — | 12 | 2148B calldata. typical shape |
| **Pyth** | [`0x32913147…`](https://etherscan.io/tx/0x329131473471b39de257f0392204b6ddc7ac7560c94e8d2407d4d33590f420f9) | `updatePriceFeedsIfNecessary` ✓ `0xb9256d28` | 194,986 | 113,357 | +81,629 | **31,629** (16.22%) | 0 | — | 12 | 2148B calldata.  |
| **Pyth** | [`0xfd6656e5…`](https://etherscan.io/tx/0xfd6656e58db697736c638a01a1abe0d3065a1b72627a1c9368b108e052cb03e3) | `updatePriceFeedsIfNecessary` ✓ `0xb9256d28` | 195,031 | 113,405 | +81,626 | **31,626** (16.22%) | 0 | — | 12 | 2148B calldata.  |
| **Pyth** | [`0xacc36012…`](https://etherscan.io/tx/0xacc36012498cc4c26e3e79d5f6ee1d0bc579e2ccf03828f34c1b60f77c5e239c) | `updatePriceFeedsIfNecessary` ✓ `0xb9256d28` | 194,992 | 113,369 | +81,623 | **31,623** (16.22%) | 0 | — | 12 | 2148B calldata.  |
| **Pyth** | [`0xe2795d24…`](https://etherscan.io/tx/0xe2795d246d11e909653880ca648a00e2b658b4c252dcf9bfd237cd41bab1112f) | `updatePriceFeedsIfNecessary` ✓ `0xb9256d28` | 195,007 | 113,393 | +81,614 | **31,614** (16.21%) | 0 | — | 12 | 2148B calldata.  |
| **Pyth** | [`0x3862ae1b…`](https://etherscan.io/tx/0x3862ae1b964adcdc8932bfd4583854ad2fb749ed85cce0ae8d0e85440f41a571) | `updatePriceFeedsIfNecessary` ✓ `0xb9256d28` | 195,004 | 113,393 | +81,611 | **31,611** (16.21%) | 0 | — | 12 | 2148B calldata.  |
| **Pyth** | [`0x90b34b5d…`](https://etherscan.io/tx/0x90b34b5df172d1d050f207ab34da927e4f81f7e710ae1edc1aa945e0fbc887d9) | `updatePriceFeedsIfNecessary` ✓ `0xb9256d28` | 194,995 | 113,405 | +81,590 | **31,590** (16.20%) | 0 | — | 12 | 2148B calldata.  |
| **Pyth** | [`0x9f3e0810…`](https://etherscan.io/tx/0x9f3e08104c3a853674bb012ae9331fccb6f00dacd90c0661bf5d3de97079c7ee) | `updatePriceFeedsIfNecessary` ✓ `0xb9256d28` | 194,989 | 113,405 | +81,584 | **31,584** (16.20%) | 0 | — | 12 | 2148B calldata.  |

| ENS | [`0x00061980…`](https://etherscan.io/tx/0x000619805359c5bbf89fd109825f18f9e6ef602ee010df1482c4444107131b98) | Controller `renew` ✓ `0x18026ad1` | 88,200 | 72,142 | +16,058 | **0** (0.00%) | 0 | under the floor | 3 (2C/1L2) |  |
| ENS | [`0x27b47957…`](https://etherscan.io/tx/0x27b479573f4bfa7ab2ae841aeb979d7e415d8cdf00d5533d9f1d3e9bfd8289f7) | Controller `register` ✓ `0xef9c8805` | 140,288 | 124,344 | +15,944 | **0** (0.00%) | 0 | under the floor | 5 (3C/1L3/1S) |  |
| ENS | [`0x518c3dc9…`](https://etherscan.io/tx/0x518c3dc964d3794cbc21a1f5f5f39c218ef77b741418b24b7cfbe7aecb053a4a) | Controller `register` ✓ `0xef9c8805` | 455,003 | 440,380 | +14,623 | **0** (0.00%) | 0 | under the floor | 8 (6C/1L3/1S) |  |
| ENS | [`0x3b10d318…`](https://etherscan.io/tx/0x3b10d318e95285570651ca3662a40c592873e9ef55309eb64e5eeb2a182e9747) | Controller `renew` ✓ `0x18026ad1` | 83,013 | 69,415 | +13,598 | **0** (0.00%) | 0 | under the floor | 3 (2C/1L2) |  |
| ENS | [`0xe6c6ae69…`](https://etherscan.io/tx/0xe6c6ae69a80283612cc07a48e3f4f65bf19d2ccafb247136ec98d4b1ee937346) | Controller `register` ✓ `0xef9c8805` | 524,112 | 511,783 | +12,329 | **0** (0.00%) | 0 | under the floor | 8 (6C/1L3/1S) |  |
| ENS | [`0x3d046fd6…`](https://etherscan.io/tx/0x3d046fd6792e7306571e45a22eea26744796b46dba0522209504e12f657efdea) | Controller `renew` ✓ `0x18026ad1` | 80,866 | 69,331 | +11,535 | **0** (0.00%) | 0 | under the floor | 3 (2C/1L2) |  |
| ENS | [`0xacbe2f4e…`](https://etherscan.io/tx/0xacbe2f4e73a952fb2ed80b6d2d44628e57c20446707aba2916dce1cb35580bec) | Controller `register` ✓ `0xef9c8805` | 207,083 | 195,854 | +11,229 | **0** (0.00%) | 0 | under the floor | 7 (5C/1L3/1S) |  |
| ENS | [`0x15e84300…`](https://etherscan.io/tx/0x15e8430076c4d227e82b143d875c27fb6989ef5e761a1a6948a16d746998ceb6) | PublicResolver `setText` ✓ `0x10f13a8c` | 63,971 | 57,713 | +6,258 | **0** (0.00%) | 0 | under the floor | 2 (1L3/1S) |  |
| ENS | [`0x4fce8ead…`](https://etherscan.io/tx/0x4fce8ead701079e2eedf6e422305741ca541cbb3daf5d4ddf589e1a98a2630fa) | PublicResolver `setAddr` ✓ `0xd5fa2b00` | 66,214 | 61,851 | +4,363 | **0** (0.00%) | 0 | under the floor | 3 (2L2/1S) |  |
| ENS | [`0xd49a8171…`](https://etherscan.io/tx/0xd49a8171d37b5fd4a3b2a20104378746771ce302c4f75ab08416b6255f133068) | PublicResolver `multicall` ✓ `0xac9650d8` | 95,617 | 92,644 | +2,973 | **0** (0.00%) | 0 | under the floor | 5 (3L2/2S) |  |
| ENS | [`0x56b75bb9…`](https://etherscan.io/tx/0x56b75bb9a6edfd8f1e154aa50d77826298dda3ce9b8ff7a38bd2550c04964cb9) | PublicResolver `setText` ✓ `0x10f13a8c` | 110,303 | 108,030 | +2,273 | **0** (0.00%) | 0 | under the floor | 4 (1L3/3S) |  |
| ENS | [`0xfe33d0ff…`](https://etherscan.io/tx/0xfe33d0ffec57cf666aab00eab3e93c7db5bb19e2c1d6a1c1b364539e1a318a0c) | PublicResolver `setContenthash` ✓ `0x304e6ade` | 48,536 | 51,625 | -3,089 | **0** (0.00%) | 0 | replay costs more | 4 (1L2/3S) |  |
| ENS | [`0x063bce87…`](https://etherscan.io/tx/0x063bce8758b202c3130502edbb56e57b49200da873751ba911ae2dc1f3d35347) | PublicResolver `multicall` ✓ `0xac9650d8` | 86,903 | 92,644 | -5,741 | **0** (0.00%) | 0 | replay costs more | 5 (3L2/2S) |  |
| ENS | [`0x24718216…`](https://etherscan.io/tx/0x24718216634b3849236fed508cce84aa1cd40b65a0030e2dd0e384c8466fb297) | NameWrapper `setSubnodeRecord` ✓ `0x24c1af44` | 142,491 | 150,080 | -7,589 | **0** (0.00%) | 0 | replay costs more | 5 (1C/1L2/1L4/2S) |  |
| ENS | [`0x707689e3…`](https://etherscan.io/tx/0x707689e32396134bcfe3fcee826a3bbbdd9b668dae5f438404449696027896b1) | PublicResolver `multicall` ✓ `0xac9650d8` | 171,817 | 181,469 | -9,652 | **0** (0.00%) | 0 | replay costs more | 9 (2L2/2L3/5S) |  |
| ENS | [`0x8beab91b…`](https://etherscan.io/tx/0x8beab91bab4d5bbf770c63071eeff6faca54dbf3c2a399f38507fb9a989ccc9f) | Registry `setSubnodeRecord` ✓ `0x5ef2c7f0` | 76,480 | 86,787 | -10,307 | **0** (0.00%) | 0 | replay costs more | 4 (1L2/1L3/2S) |  |
| ENS | [`0x7e8f6cf9…`](https://etherscan.io/tx/0x7e8f6cf9bd7ff68bcbbe6181362379868086438492a79d55f57a72c851b182a6) | BaseRegistrar `safeTransferFrom` ✓ `0xb88d4fde` | 128,799 | 146,761 | -17,962 | **0** (0.00%) | 0 | replay costs more | 5 (1C/1L4/3S) |  |
| ENS | [`0x2a918a42…`](https://etherscan.io/tx/0x2a918a425728e529f0c9889da1fff462ba34aa62e7386c3868565f060d99696f) | NameWrapper `setRecord` ✓ `0xcf408823` | 53,596 | 74,883 | -21,287 | **0** (0.00%) | 0 | replay costs more | 6 (2C/1L2/1L4/2S) |  |

| Chronicle | [`0x33fc0276…`](https://etherscan.io/tx/0x33fc0276a8d7ed1948aac0130dad3adb5c285cfbdb65880d647fcda76d9a90c8) | Scribe `poke_optimized_7136211` ✓ `0x00000082` | 129,099 | 36,964 | +92,135 | **42,135** (32.64%) | 0 | — | 2 (1L2/1S) |  |
| Chronicle | [`0x0bb84b09…`](https://etherscan.io/tx/0x0bb84b092ba588fb16ff105e7c13957841facfaea7e1dce09918b8e6ddec9906) | Scribe `poke` ✓ `0x2f529d73` | 128,819 | 36,964 | +91,855 | **41,855** (32.49%) | 0 | — | 2 (1L2/1S) |  |
| Chronicle | [`0xd4ccdc11…`](https://etherscan.io/tx/0xd4ccdc1185f1269709d962e9ec8becf18ffeb40a048016cd877bd57f8c56a395) | Scribe `poke` ✓ `0x2f529d73` | 127,899 | 36,940 | +90,959 | **40,959** (32.02%) | 0 | — | 2 (1L2/1S) |  |
| Chronicle | [`0xc2ff01f2…`](https://etherscan.io/tx/0xc2ff01f2e2b32d3a92441742ad8ef44ac7645a2a12b3a0a0595d5803e95b3314) | Scribe `poke_optimized_7136211` ✓ `0x00000082` | 127,643 | 36,964 | +90,679 | **40,679** (31.87%) | 0 | — | 2 (1L2/1S) |  |
| Chronicle | [`0x18beefef…`](https://etherscan.io/tx/0x18beefef56141767a0e4c4d6aebaab6f4e042ba2fd73063b325590fedd954559) | Scribe `poke_optimized_7136211` ✓ `0x00000082` | 127,655 | 37,036 | +90,619 | **40,619** (31.82%) | 0 | — | 2 (1L2/1S) |  |
| Chronicle | [`0xa5043652…`](https://etherscan.io/tx/0xa50436526fc8a0e8c94781fd8cec6c2e782e81588ec069525419903a685b5586) | Scribe `poke_optimized_7136211` ✓ `0x00000082` | 126,087 | 36,988 | +89,099 | **39,099** (31.01%) | 0 | — | 2 (1L2/1S) |  |
| Chronicle | [`0xa43037be…`](https://etherscan.io/tx/0xa43037be59fafae9223f0ba1342c3eeaae408da11080b1b9e0d80c7545a8e9f9) | Scribe `poke_optimized_7136211` ✓ `0x00000082` | 125,951 | 36,940 | +89,011 | **39,011** (30.97%) | 0 | — | 2 (1L2/1S) |  |
| Chronicle | [`0xbf98a993…`](https://etherscan.io/tx/0xbf98a993b605a94c01605b92d14f08d5cf6a019c1f89dbe3654a8b70abda7780) | Scribe `poke_optimized_7136211` ✓ `0x00000082` | 125,663 | 37,036 | +88,627 | **38,627** (30.74%) | 0 | — | 2 (1L2/1S) |  |
| Chronicle | [`0xfd9968d1…`](https://etherscan.io/tx/0xfd9968d1b696a78ade14ce04b7c2368cab2350b5e521e0b41d1a8ac5c07bfedb) | Scribe `poke_optimized_7136211` ✓ `0x00000082` | 124,495 | 36,940 | +87,555 | **37,555** (30.17%) | 0 | — | 2 (1L2/1S) |  |
| Chronicle | [`0xd3fa91b6…`](https://etherscan.io/tx/0xd3fa91b65de811df53dcb9827df0ac660675ba0f6cebd2a1c53b2c2d59ab2dc0) | Scribe `poke_optimized_7136211` ✓ `0x00000082` | 124,507 | 36,988 | +87,519 | **37,519** (30.13%) | 0 | — | 2 (1L2/1S) |  |
| Chronicle | [`0x85ff84f4…`](https://etherscan.io/tx/0x85ff84f45a7383338660b54e3cb4763d462c5781a78a631141fd783f05ae8aed) | Scribe `poke_optimized_7136211` ✓ `0x00000082` | 124,507 | 36,988 | +87,519 | **37,519** (30.13%) | 0 | — | 2 (1L2/1S) |  |
| Chronicle | [`0x1a8e1999…`](https://etherscan.io/tx/0x1a8e1999e69bb4f2996e716a0e740b9b492f0f1458106d5412a92573d69a319d) | Scribe `poke_optimized_7136211` ✓ `0x00000082` | 124,519 | 37,012 | +87,507 | **37,507** (30.12%) | 0 | — | 2 (1L2/1S) |  |
| Chronicle | [`0xc504a4dc…`](https://etherscan.io/tx/0xc504a4dcbdb2f1a547c8e85a3aa10e301fb47b7618636f74d582110275a3dfda) | Scribe `poke_optimized_7136211` ✓ `0x00000082` | 121,309 | 36,988 | +84,321 | **34,321** (28.29%) | 0 | — | 2 (1L2/1S) |  |
| Chronicle | [`0xfaffd0ec…`](https://etherscan.io/tx/0xfaffd0ecd5ad094bc14a1f7d1474a38c6c200235298119e39e77f13b5fb955fa) | OSM `poke()` ✓ `0x18178358` | 103,090 | 36,022 | +67,068 | **17,068** (16.56%) | 0 | — | 2 (1L1/1S) |  |
| Chronicle | [`0x11df7756…`](https://etherscan.io/tx/0x11df7756226128459aff94e29187d1ec9501dccc2d905bba2136ea531a7e76e2) | OSM `poke()` ✓ `0x18178358` | 103,080 | 36,022 | +67,058 | **17,058** (16.55%) | 0 | — | 2 (1L1/1S) |  |
| Chronicle | [`0xf4e4f0f1…`](https://etherscan.io/tx/0xf4e4f0f17ed73f459a59ff95f17a8496e03d65a70cfd7208de79ccb87bc56f56) | Median `poke(uint256[],uint256[],uint8[],bytes32[],bytes32[])` ✓ `0x89bbb8b2` | 89,949 | 35,974 | +53,975 | **3,975** (4.42%) | 0 | — | 2 (1L1/1S) |  |
| Chronicle | [`0x1a400408…`](https://etherscan.io/tx/0x1a40040807a503ec6538bfeffaa4fa3458ed9566af8aa83a94a5ace150e65dca) | Median `poke(uint256[],uint256[],uint8[],bytes32[],bytes32[])` ✓ `0x89bbb8b2` | 89,937 | 35,974 | +53,963 | **3,963** (4.41%) | 0 | — | 2 (1L1/1S) |  |
| Chronicle | [`0x2ed22cf0…`](https://etherscan.io/tx/0x2ed22cf0d3276cefb494e31647f280b844ce618e67a8326ba2fe9fc43d720ee9) | OSM `poke()` ✓ `0x18178358` | 80,034 | 35,974 | +44,060 | **0** (0.00%) | 0 | under the floor | 2 (1L1/1S) |  |
| Chronicle | [`0x2b1cdec4…`](https://etherscan.io/tx/0x2b1cdec4cc43ebcde9112c9d92256ca344eda19dfee70457882a23e9e6cfc386) | OSM `poke()` ✓ `0x18178358` | 80,034 | 35,974 | +44,060 | **0** (0.00%) | 0 | under the floor | 2 (1L1/1S) |  |
| Chronicle | [`0x07668874…`](https://etherscan.io/tx/0x0766887492c81242e9346d58c8630dac26a1c6f4307dc62a987e2d79c4668f82) | Median `poke(uint256[],uint256[],uint8[],bytes32[],bytes32[])` ✓ `0x89bbb8b2` | 73,567 | 36,022 | +37,545 | **0** (0.00%) | 0 | under the floor | 2 (1L1/1S) |  |
| Chronicle | [`0x96b59d20…`](https://etherscan.io/tx/0x96b59d20ce9611707d365c3df5b33b2d1468c68dba4dc6a2f0ecbf055fd448a8) | Median `poke(uint256[],uint256[],uint8[],bytes32[],bytes32[])` ✓ `0x89bbb8b2` | 73,493 | 36,022 | +37,471 | **0** (0.00%) | 0 | under the floor | 2 (1L1/1S) |  |
| Chronicle | [`0xcd7e52d7…`](https://etherscan.io/tx/0xcd7e52d764d8cc8d810a33e5d156b74837cad5b74688126b8a21ed5494413d15) | Multicall3 `aggregate3` ✓ `0x82ad56cb` | 897,296 | 911,985 | -14,689 | **0** (0.00%) | 0 | replay costs more | 8 (8C) |  |
| Chronicle | [`0x640f1093…`](https://etherscan.io/tx/0x640f1093965977576f6f631e09c267391b3a213d2fef75c74cd83a25d5825f22) | Multicall3 `aggregate3` ✓ `0x82ad56cb` | 569,896 | 579,405 | -9,509 | **0** (0.00%) | 0 | replay costs more | 5 (5C) |  |
| Chronicle | [`0x3aa6909a…`](https://etherscan.io/tx/0x3aa6909a86a92ae55183b4fe13961dc1972a1d670a450418179ac5b4395fabe7) | Multicall3 `aggregate3` ✓ `0x82ad56cb` | 243,479 | 247,819 | -4,340 | **0** (0.00%) | 0 | replay costs more | 2 (2C) |  |

| Umbra | [`0x281842ba…`](https://etherscan.io/tx/0x281842ba2fd455a6e0e832ed95a04aa3c872451d3189ed956b4af673242be149) | `sendEth` ✓ `0xbeb9addf` | 62,261 | 69,749 | -7,488 | **0** (0.00%) | 0 | replay costs more | 2 (1C/1L3) |  |
| Umbra | [`0x292bfbc8…`](https://etherscan.io/tx/0x292bfbc8b76c06254cfb83e2980b8100410e8ac1e367609e5936020c59a292e5) | `sendEth` ✓ `0xbeb9addf` | 62,261 | 69,773 | -7,512 | **0** (0.00%) | 0 | replay costs more | 2 (1C/1L3) |  |
| Umbra | [`0x13ad4804…`](https://etherscan.io/tx/0x13ad4804e62a9d15b2bd7bb521bc86214dd787d89dc90d380404850ffb299f6c) | `withdrawTokenOnBehalf` ✓ `0x81ab0fcd` | 70,497 | 79,463 | -8,966 | **0** (0.00%) | 0 | replay costs more | 4 (2C/1L4/1S) |  |
| Umbra | [`0x15272613…`](https://etherscan.io/tx/0x15272613ac2388a2b9a2e71f3f47c807387c8524e067b9b8adf3306ec674766f) | `withdrawTokenOnBehalf` ✓ `0x81ab0fcd` | 70,613 | 79,861 | -9,248 | **0** (0.00%) | 0 | replay costs more | 4 (2C/1L4/1S) |  |
| Umbra | [`0x1ab89fac…`](https://etherscan.io/tx/0x1ab89fac7fc4f93a41671563e0a739ef53b85eebf49b6e08ddee46356899908a) | `sendToken` ✓ `0xb9bfabe1` | 83,712 | 93,356 | -9,644 | **0** (0.00%) | 0 | replay costs more | 3 (1C/1L3/1S) |  |
| Umbra | [`0x19d8496e…`](https://etherscan.io/tx/0x19d8496ec02910a6092679e948e5814e288bb799b2fccc7c7e45e52bba3efca5) | `sendToken` ✓ `0xb9bfabe1` | 83,724 | 93,380 | -9,656 | **0** (0.00%) | 0 | replay costs more | 3 (1C/1L3/1S) |  |
| Umbra | [`0x03d44b4b…`](https://etherscan.io/tx/0x03d44b4b02585abf604b803e381863fd2d71659fe9e1db94fe25be978cb2fe38) | `sendToken` ✓ `0xb9bfabe1` | 75,873 | 85,673 | -9,800 | **0** (0.00%) | 0 | replay costs more | 3 (1C/1L3/1S) |  |
| Umbra | [`0x2bfe5664…`](https://etherscan.io/tx/0x2bfe566409f498dbfaac1f42fb6a93e28773ab90165036f8cccd41276aa4ba2f) | *batch send (11 Announcements)* `0x7d703ead` | 505,078 | 531,727 | -26,649 | **0** (0.00%) | 0 | replay costs more | 11 (10C/1L2) |  |

| Kelp | [`0x5927773e…`](https://etherscan.io/tx/0x5927773e7bf28ca0228333c07d5913192569982502caa320d594616403ac8581) | `depositETH` ✓ `0x72c51c0b` | 881,047 | 97,229 | +783,818 | **733,818** (83.29%) | 533,818 | — | 4 (1C/1L2/2S) |  |
| Kelp | [`0x3d793f5e…`](https://etherscan.io/tx/0x3d793f5e6caf4cca5325c0a08586f09ea802e7155537c6268cae62a0d9b2fb90) | `depositETH` ✓ `0x72c51c0b` | 843,973 | 97,253 | +746,720 | **696,720** (82.55%) | 496,720 | — | 4 (1C/1L2/2S) |  |
| Kelp | [`0xed07bc6d…`](https://etherscan.io/tx/0xed07bc6df666ead240eee3539cf2fbe198222bd5e77373dee853ed66799b8356) | `depositETH` ✓ `0x72c51c0b` | 860,124 | 114,353 | +745,771 | **695,771** (80.89%) | 495,771 | — | 4 (1C/1L2/2S) |  |
| Kelp | [`0x1de5a43e…`](https://etherscan.io/tx/0x1de5a43e5be3c8909ee49f2b31d7da4fb6e5ae2820db7dcab45c7b54cd975db1) | `depositETH` ✓ `0x72c51c0b` | 860,124 | 114,353 | +745,771 | **695,771** (80.89%) | 495,771 | — | 4 (1C/1L2/2S) |  |
| Renzo | [`0x0164c9ec…`](https://etherscan.io/tx/0x0164c9ec2a2aca0002fb6c83b026baf02ae79657118116d659cc1607306e732d) | `claim` ✓ `0xddd5e1b2` | 556,985 | 156,250 | +400,735 | **350,735** (62.97%) | 150,735 | — | 17 (2C/1L1/14S) | **label inferred** — `to` `0x5efc9d10…` unidentified; moves ezETH but not confirmed as Renzo's own contract |
| Symbiotic | [`0xf9907340…`](https://etherscan.io/tx/0xf99073406b04143cb575fd593f4acce362cc6dedd1dbc7dc121f7b741d266974) | `withdraw` ✓ `0xb460af94` | 388,545 | 116,909 | +271,636 | **221,636** (57.04%) | 21,636 | — | 7 (1C/1L3/1L4/4S) |  |
| Symbiotic | [`0x222b1607…`](https://etherscan.io/tx/0x222b16076f8654a56941e68b760ce77a76837708f34a778ac9c0c448aa1e74a8) | `withdraw` ✓ `0xb460af94` | 393,345 | 121,781 | +271,564 | **221,564** (56.33%) | 21,564 | — | 7 (1C/1L3/1L4/4S) |  |
| Symbiotic | [`0x52cc4627…`](https://etherscan.io/tx/0x52cc462709e07ca5cd17b03456a405d420552051f717a39e058ce3531eee0ad6) | `redeem` ✓ `0xba087652` | 354,891 | 116,909 | +237,982 | **187,982** (52.97%) | 0 | — | 7 (1C/1L3/1L4/4S) |  |
| Symbiotic | [`0x42aa444d…`](https://etherscan.io/tx/0x42aa444d7ee88138c5b8d1466996ee1e1fbc54a45837dad954528751b2d046e9) | `redeem` ✓ `0xba087652` | 354,891 | 116,909 | +237,982 | **187,982** (52.97%) | 0 | — | 7 (1C/1L3/1L4/4S) |  |
| Mellow | [`0xf6e00504…`](https://etherscan.io/tx/0xf6e005046649586bebc607e52b1a599be30fa5298a675c7bd47cb65910d4b0e9) | `withdraw` ✓ `0xb460af94` | 285,541 | 116,909 | +168,632 | **118,632** (41.55%) | 0 | — | 7 (1C/1L3/1L4/4S) |  |
| Mellow | [`0xfe087bdd…`](https://etherscan.io/tx/0xfe087bdd2929c1ffa4b9cfd6ced03e510015b91bfd4d2e46630d45782bea7733) | `redeem` ✓ `0xba087652` | 257,579 | 116,909 | +140,670 | **90,670** (35.20%) | 0 | — | 7 (1C/1L3/1L4/4S) |  |
| Mellow | [`0x7492f30f…`](https://etherscan.io/tx/0x7492f30ffc86ee6112332404b2d566b7ac69892b929a8b1269e83b02ec002739) | `withdraw` ✓ `0xb460af94` | 267,866 | 137,503 | +130,363 | **80,363** (30.00%) | 0 | — | 7 (1C/1L3/1L4/4S) |  |
| Mellow | [`0x8cab3ca8…`](https://etherscan.io/tx/0x8cab3ca8f227eea89b600c21d9946246c1d3b934ec4fa0866b75bf06c2c4fd64) | `redeem` ✓ `0xba087652` | 244,274 | 132,703 | +111,571 | **61,571** (25.21%) | 0 | — | 7 (1C/1L3/1L4/4S) |  |
| Mellow | [`0x7bcd05f1…`](https://etherscan.io/tx/0x7bcd05f137e612ed18a05b8ae6a3d69098e49478bd08f3f1fdc503125e7660a6) | `redeem` ✓ `0xba087652` | 362,727 | 255,112 | +107,615 | **57,615** (15.88%) | 0 | — | 8 (2C/1L3/1L4/4S) | **unverified** — 8 of 10 receipt logs unaccounted for by the 2 recorded calls |
| Puffer | [`0x4138ef12…`](https://etherscan.io/tx/0x4138ef12a8ff9af26a8a3e2215ece5d3d89a7def48d0d15014b0ac1c5b766233) | `requestWithdrawal` ✓ `0xef027fbf` | 189,094 | 125,747 | +63,347 | **13,347** (7.06%) | 0 | — | 7 (1C/1L4/5S) | **label inferred** — `to` `0xdda04831…` unidentified; moves pufETH but not confirmed as Puffer's own contract |
| Swell | [`0xde520139…`](https://etherscan.io/tx/0xde520139bb8c7e72bc8f00f44e5f5acc1836e277dd2ca6c383ec2cb85fdf07a4) | *withdrawal route* `0x64370336` | 506,140 | 500,723 | +5,417 | **0** (0.00%) | 0 | under the floor | 18 (2C/3L2/13S) |  |
| Swell | [`0x5fa9fc3e…`](https://etherscan.io/tx/0x5fa9fc3e86cd5eca4d1cea80f43cdc4deda42654347dc2d9f96f1d3861c747c9) | `swap` ✓ `0xe21fd0e9` | 1,429,886 | 1,434,239 | -4,353 | **0** (0.00%) | 0 | replay costs more | 7 (3C/4L1) | **not Swell's own** — aggregator touching rswETH |
| Swell | [`0x007900f8…`](https://etherscan.io/tx/0x007900f86481e523c1e73a76908b3ae1af44fd4978f798298305f98c300461dd) | `createWithdrawRequest` ✓ `0x74dc9d1a` | 310,597 | 317,086 | -6,489 | **0** (0.00%) | 0 | replay costs more | 16 (2C/1L3/1L4/12S) |  |
| Renzo | [`0xbec0bce9…`](https://etherscan.io/tx/0xbec0bce9263ce0eafb97a9516080b2ffb8fbbac17bec59bd6de8314cf755107d) | `transferAndMulticall` ✓ `0xf9e4bab4` | 836,980 | 843,164 | -6,184 | **0** (0.00%) | 0 | replay costs more | 3 (2C/1L1) | **not Renzo's own** — aggregator that touches ezETH |
| Puffer | [`0x98eacd62…`](https://etherscan.io/tx/0x98eacd62af71a709fa00814c8e065c2865e5e90432d97147dacea56fbcffba60) | `swapExactAmountInOnCurveV1` ✓ `0x1a01c532` | 239,072 | 252,170 | -13,098 | **0** (0.00%) | 0 | replay costs more | 5 (5C) | **not Puffer's own** — Paraswap route touching pufETH |
| Kelp | [`0xe0901586…`](https://etherscan.io/tx/0xe090158643e1c7bf676c2e373ca98e3d37d95affb69ca257b2ee598bbc03310a) | *withdrawal route* `0x6d7b7040` | 508,968 | 515,629 | -6,661 | **0** (0.00%) | 0 | replay costs more | 1 (1C) | via third-party contract |

| Sky | [`0xea36a77d…`](https://etherscan.io/tx/0xea36a77deb266334389af73a95ad7dd7769253612695af1aa83e12cf4b0b6362) | Safe `execTransaction` ✓ `0x6a761202` | 902,223 | 902,671 | -448 | **0** (0.00%) | 0 | replay costs more | 8 (6C/1L2/1S) | **not Sky's own** — a market maker's multisig touching Jug/Vat/PSM |
| Sky | [`0x8468cfac…`](https://etherscan.io/tx/0x8468cfacae12d76e813dd9fba6f224d5671a39b2e96b7f50dfd0da3ccb57d898) | Safe `execTransaction` ✓ `0x6a761202` | 982,548 | 985,574 | -3,026 | **0** (0.00%) | 0 | replay costs more | 9 (7C/1L2/1S) | **not Sky's own** — same multisig |
| Sky | [`0x1c77d8ed…`](https://etherscan.io/tx/0x1c77d8edef60f73522dfe4b551680d7f3ed0d12e53b146fae31a3af0f5539fe6) | sUSDS `transfer` ✓ `0xa9059cbb` | 56,380 | 62,836 | -6,456 | **0** (0.00%) | 0 | replay costs more | 3 (1L3/2S) |  |
| Sky | [`0x765e023f…`](https://etherscan.io/tx/0x765e023f53a0822981195b2c5711f9a1c973c951a3488856ecdfb01ac6b48f7c) | USDS `transfer` ✓ `0xa9059cbb` | 56,336 | 62,836 | -6,500 | **0** (0.00%) | 0 | replay costs more | 3 (1L3/2S) |  |
| Sky | [`0xd1ddae6d…`](https://etherscan.io/tx/0xd1ddae6dade88620d7be1aea762b7881998f1040dea2900a71e7126b6ea23a6e) | DaiUsds `daiToUsds` ✓ `0xf2c07aae` | 132,007 | 151,437 | -19,430 | **0** (0.00%) | 0 | replay costs more | 4 (3C/1L3) |  |
| delegate.xyz | [`0x65286291…`](https://etherscan.io/tx/0x65286291c107b37220aa654fb9083509bb2220a83978bf8dd25795eed4e4f12a) | `delegateERC721` ✓ `0xb18e2bbb` | 203,515 | 232,663 | -29,148 | **0** (0.00%) | 0 | replay costs more | 9 (8S/1L4) |  |
| delegate.xyz | [`0xec6a26db…`](https://etherscan.io/tx/0xec6a26db73946d9cb69adc06deac17fc4fd98ba7a2e33c6ac052b6d547b8a0b2) | `delegateERC721` ✓ `0xb18e2bbb` | 186,415 | 215,587 | -29,172 | **0** (0.00%) | 0 | replay costs more | 9 (8S/1L4) |  |
| delegate.xyz | [`0xb83be259…`](https://etherscan.io/tx/0xb83be25931d74b873a78105d727b60e1c9f804378661f53a47e89396492064eb) | `delegateERC721` ✓ `0xb18e2bbb` | 186,127 | 215,023 | -28,896 | **0** (0.00%) | 0 | replay costs more | 9 (8S/1L4) |  |
| Midas | [`0xaada5d1a…`](https://etherscan.io/tx/0xaada5d1ae5bb22de8e355b516af999e9d3561b7456d521ee34ce63d953c78c76) | `redeemInstant` ✓ `0x8b53f75e` | 687,607 | 577,695 | +109,912 | **59,912** (8.71%) | 0 | — | 9 (6C/2S/1L3) | **call-dominated** — 18 of 19 receipt logs produced inside the replayed `CALL`s |
| Midas | [`0x4749ed20…`](https://etherscan.io/tx/0x4749ed20ece3a8f05389932fe7469103c21c7dda5501fc537ab1654e0d6fc81f) | `redeemInstant` ✓ `0x8b53f75e` | 687,605 | 577,690 | +109,915 | **59,915** (8.71%) | 0 | — | 9 (6C/2S/1L3) | **call-dominated** — 18 of 19 receipt logs produced inside the replayed `CALL`s |
| Midas | [`0xa8a9dc84…`](https://etherscan.io/tx/0xa8a9dc84c9c612e20355603b505a8de8e133ff15bc3bc8572f113a98e852b5a1) | `redeemInstant` ✓ `0x8b53f75e` | 680,083 | 570,027 | +110,056 | **60,056** (8.83%) | 0 | — | 9 (6C/2S/1L3) | **call-dominated** — 18 of 19 receipt logs produced inside the replayed `CALL`s |
| Midas | [`0xd1fc0758…`](https://etherscan.io/tx/0xd1fc0758c59333d16f0b86a2e18452da0cae8d9bdac94028dd9fbb891b493b14) | `redeemInstant` ✓ `0x8b53f75e` | 675,459 | 565,323 | +110,136 | **60,136** (8.90%) | 0 | — | 9 (6C/2S/1L3) | **call-dominated** — 18 of 19 receipt logs produced inside the replayed `CALL`s |
| Midas | [`0x314d14d3…`](https://etherscan.io/tx/0x314d14d32e8b7749b4ae410c00b3a48bd585b37c272e9baa4db34d2c430452ce) | `redeemInstant` ✓ `0x8b53f75e` | 675,283 | 565,275 | +110,008 | **60,008** (8.89%) | 0 | — | 9 (6C/2S/1L3) | **call-dominated** — 18 of 19 receipt logs produced inside the replayed `CALL`s |
| Midas | [`0xb4b5ebf8…`](https://etherscan.io/tx/0xb4b5ebf82257ed485cb1d5ef1c9a2d414d48b43121ee976ce97fd39206bc4f5e) | `redeemRequest` ✓ `0xbfc2d46a` | 343,673 | 239,894 | +103,779 | **53,779** (15.65%) | 0 | — | 9 (7S/1C/1L4) |  |
| Midas | [`0x874fa4e0…`](https://etherscan.io/tx/0x874fa4e00aa6788e99b19e5d8ed53615a570ef4f1e8061ebfa311fde6dfb8315) | `depositInstant` ✓ `0xc02dd27a` | 340,326 | 210,210 | +130,116 | **80,116** (23.54%) | 0 | — | 6 (3S/2C/1L3) |  |
| Midas | [`0xc21732ae…`](https://etherscan.io/tx/0xc21732ae2c101c8fb1529d88f8e0ebca2d20fd84bdc66f6cf6e8c61d7cfad37d) | `depositInstant` ✓ `0xc02dd27a` | 340,201 | 210,126 | +130,075 | **80,075** (23.54%) | 0 | — | 6 (3S/2C/1L3) |  |
| Midas | [`0xc4ec177d…`](https://etherscan.io/tx/0xc4ec177d4ef03734406c6c3b14bd1ec00f79d961b2be44d90b9eccdaa997a702) | `redeemRequest` ✓ `0xbfc2d46a` | 338,910 | 235,377 | +103,533 | **53,533** (15.80%) | 0 | — | 9 (7S/1C/1L4) |  |
| Midas | [`0x4596692b…`](https://etherscan.io/tx/0x4596692b4874036338f537fef4a86ad8eaf98011c0792d24c3ddfa224a2e93dc) | *unidentified* `0xa0c74afc` | 295,179 | 292,927 | +2,252 | **0** (0.00%) | 0 | under the floor | 30 (21S/6C/3L2) | **call-dominated** — 6 of 9 receipt logs produced inside the replayed `CALL`s |
| Midas | [`0x1e12eeca…`](https://etherscan.io/tx/0x1e12eecadefc574812056cbc9051d057b0f99c78c41e84691bae36fdbfaf67e4) | *unidentified* `0xa0c74afc` | 265,313 | 223,351 | +41,962 | **0** (0.00%) | 0 | under the floor | 20 (14S/4C/2L2) | **call-dominated** — 4 of 6 receipt logs produced inside the replayed `CALL`s |
| Midas | [`0xdc8fcd5a…`](https://etherscan.io/tx/0xdc8fcd5a80986694166ff02d3f6380ce01246dd043f6abeecda19cdba7e17eec) | *unidentified* `0x2c0a90a9` | 146,391 | 153,917 | -7,526 | **0** (0.00%) | 0 | replay costs more | 10 (7S/2C/1L2) |  |
| Snapshot | [`0x7cbed6fc…`](https://etherscan.io/tx/0x7cbed6fc639c0190a49c40a08a783f72ea139c31e5c05310f03477be632487aa) | DelegateRegistry `setDelegate` ✓ `0xbd86e508` | 46,927 | 55,776 | -8,849 | **0** (0.00%) | 0 | replay costs more | 2 (1S/1L4) |  |
| Snapshot | [`0xedb0f7be…`](https://etherscan.io/tx/0xedb0f7be3d0539a6442f0c86cf08aba995fa8b6f4bda8a181dd8aab1b22d018f) | DelegateRegistry `setDelegate` ✓ `0xbd86e508` | 46,747 | 55,596 | -8,849 | **0** (0.00%) | 0 | replay costs more | 2 (1S/1L4) |  |
| Gitcoin | [`0xa5c2fea2…`](https://etherscan.io/tx/0xa5c2fea27689a1aa1fe0cda700eab32ee0f53175ad99c2afe2cc0f4caa13b423) | GTC `transfer` ✓ `0xa9059cbb` | 100,501 | 118,905 | -18,404 | **0** (0.00%) | 0 | replay costs more | 9 (6S/2L2/1L3) |  |
| Gitcoin | [`0xac81a1b9…`](https://etherscan.io/tx/0xac81a1b9c1cfc97be6cdeb5a09419262f21fb81e2b5ac595b21859dd91c48746) | GTC `transfer` ✓ `0xa9059cbb` | 100,465 | 118,749 | -18,284 | **0** (0.00%) | 0 | replay costs more | 9 (6S/2L2/1L3) |  |
| Gitcoin | [`0xeb3b43d1…`](https://etherscan.io/tx/0xeb3b43d10aa80364be3551a1e14a04e9d7a52e0b055c480efcc54ded56347d28) | GTC `delegate` ✓ `0x5c19a95c` | 95,579 | 111,457 | -15,878 | **0** (0.00%) | 0 | replay costs more | 5 (3S/1L4/1L2) |  |
| Gitcoin | [`0xae77a0e9…`](https://etherscan.io/tx/0xae77a0e98284ea462ef01ac687e57c6e8c0f8ffbaaff4cbd986eefae24da9328) | GTC `delegate` ✓ `0x5c19a95c` | 95,579 | 111,481 | -15,902 | **0** (0.00%) | 0 | replay costs more | 5 (3S/1L4/1L2) |  |
| Gitcoin | [`0xefb98a52…`](https://etherscan.io/tx/0xefb98a522180bba1db20d628ab971337ba5b4a55fe950421162ef0aa18044418) | GTC `transfer` ✓ `0xa9059cbb` | 89,735 | 101,981 | -12,246 | **0** (0.00%) | 0 | replay costs more | 6 (4S/1L3/1L2) |  |
| EAS | [`0xcb068c52…`](https://etherscan.io/tx/0xcb068c521d567965d0773333a6890e366d3428e86b015b2d111b353129dba8be) | EAS `multiAttest` ✓ `0x44adc90e` | 2,546,830 | 2,806,215 | -259,385 | **0** (0.00%) | 0 | replay costs more | 105 (100S/4L4/1C) |  |
| EAS | [`0xa6d232b3…`](https://etherscan.io/tx/0xa6d232b3196a03647493807a7f8b24785397c037eea05d3367bd2d023f0c092a) | EAS `attest` ✓ `0xf17325e7` | 545,839 | 583,699 | -37,860 | **0** (0.00%) | 0 | replay costs more | 24 (23S/1L4) |  |
| EAS | [`0x001628e1…`](https://etherscan.io/tx/0x001628e13d64e27053791f44172e220b0eaee981238113171a2794efb41b1f62) | EAS `attest` ✓ `0xf17325e7` | 524,905 | 565,059 | -40,154 | **0** (0.00%) | 0 | replay costs more | 24 (23S/1L4) |  |
| EAS | [`0x8e5ff8aa…`](https://etherscan.io/tx/0x8e5ff8aa7ac32a56efb5733331e4c0d1a78a34374762332c956e7f059267f060) | EAS `attest` ✓ `0xf17325e7` | 522,644 | 557,956 | -35,312 | **0** (0.00%) | 0 | replay costs more | 23 (22S/1L4) |  |
| EAS | [`0x27de14a6…`](https://etherscan.io/tx/0x27de14a62cfd1e040aa0dca72dfdf039e098dbec6e885df57919c324fdd65a1a) | EAS `attest` ✓ `0xf17325e7` | 432,047 | 464,993 | -32,946 | **0** (0.00%) | 0 | replay costs more | 20 (19S/1L4) |  |
| EAS | [`0x435f638f…`](https://etherscan.io/tx/0x435f638f942ddd9925e57ad2c65d04c4f3ed375c3579572743e7c964f90b32b6) | EAS `attest` ✓ `0xf17325e7` | 409,295 | 439,863 | -30,568 | **0** (0.00%) | 0 | replay costs more | 19 (18S/1L4) |  |
| EAS | [`0xdc789cb3…`](https://etherscan.io/tx/0xdc789cb32bd4a89cf9aab8889fb96d1f140d1b6e2cffcb474c124ff143821528) | EAS `attest` ✓ `0xf17325e7` | 389,922 | 422,287 | -32,365 | **0** (0.00%) | 0 | replay costs more | 14 (12S/1L4/1C) |  |
| EAS | [`0x09b8d89e…`](https://etherscan.io/tx/0x09b8d89ed6712a559d1900f71fb450e83571ce55bf483c77685594fd4be59cb3) | SchemaRegistry `register` ✓ `0x60d7a278` | 364,292 | 406,567 | -42,275 | **0** (0.00%) | 0 | replay costs more | 16 (15S/1L2) |  |
| EAS | [`0xac28c020…`](https://etherscan.io/tx/0xac28c020e311cfaae896fd2c7efe329a4c7994a7d568f4eebdf76f46df2c4122) | EAS `attest` ✓ `0xf17325e7` | 327,202 | 356,912 | -29,710 | **0** (0.00%) | 0 | replay costs more | 13 (11S/1L4/1C) |  |
| EAS | [`0x7393d4b5…`](https://etherscan.io/tx/0x7393d4b51bfebddafe47583f6156fae9294483e79b46c4141130f99c82917455) | EAS `attest` ✓ `0xf17325e7` | 271,239 | 294,193 | -22,954 | **0** (0.00%) | 0 | replay costs more | 14 (13S/1L4) |  |
| EAS | [`0x574099f6…`](https://etherscan.io/tx/0x574099f673c7450d52c576682d7e65312c8b0b3cc01f573e7bd7476cdc620d9c) | EAS `multiTimestamp` ✓ `0xe71ff365` | 267,640 | 335,511 | -67,871 | **0** (0.00%) | 0 | replay costs more | 20 (10S/10L3) |  |
| ZeroDev | [`0xbf9ddaa7…`](https://etherscan.io/tx/0xbf9ddaa7ebd2a1cde46693b1467b4007c76f190b58ff2c8307a57e5515751718) | EntryPoint `handleOps`, 1 userOp from a **Kernel v3.1** account | 622,870 | 679,189 | -56,319 | **0** (0.00%) | 0 | replay costs more | 9 (4S/4C/1L1) |  |
| ZeroDev | [`0x048854ab…`](https://etherscan.io/tx/0x048854ab2d10688db8e8fdcddc93d3966587ad51c0408a8e46cef391c1f8ab16) | EntryPoint `handleOps`, 1 userOp from a **Kernel v3.1** account | 594,900 | 668,985 | -74,085 | **0** (0.00%) | 0 | replay costs more | 9 (4S/4C/1L1) |  |
| ZeroDev | [`0x83a6114c…`](https://etherscan.io/tx/0x83a6114cb84fccf4f54bebb27bf848d392371ccb24c7ad15e0115303438d2da8) | EntryPoint `handleOps`, 1 userOp from a **Kernel** account | 474,560 | 565,299 | -90,739 | **0** (0.00%) | 0 | replay costs more | 9 (4S/4C/1L1) |  |
| ZeroDev | [`0x1a82bbc2…`](https://etherscan.io/tx/0x1a82bbc236311d674b4609c84e36f4988fbe636b823507344dc84c26c66ced68) | EntryPoint `handleOps`, 1 userOp from a **Kernel v3.0** account | 429,858 | 487,060 | -57,202 | **0** (0.00%) | 0 | replay costs more | 11 (5C/4S/1L3/1L1) |  |
| ZeroDev | [`0xd0598f41…`](https://etherscan.io/tx/0xd0598f411c9d1aec316ff875ec2877e4de10474bfabbe6ee155cb1ab547dc0a5) | EntryPoint `handleOps`, 1 userOp from a **Kernel** account | 332,571 | 402,041 | -69,470 | **0** (0.00%) | 0 | replay costs more | 9 (4S/4C/1L1) |  |
| ZeroDev | [`0xb41e3e28…`](https://etherscan.io/tx/0xb41e3e2848acb069f5fd02bf2b62ca1c0e134368e5a59327e5861104fd954e3b) | EntryPoint `handleOps`, 1 userOp from a **Kernel v3.0** account | 211,416 | 252,106 | -40,690 | **0** (0.00%) | 0 | replay costs more | 9 (4S/4C/1L1) |  |
| ZeroDev | [`0x038ded9a…`](https://etherscan.io/tx/0x038ded9abc1b7936548fdfcdebd920c59a2d3fd004e467a6512bb91dd5a495f0) | EntryPoint `handleOps`, 1 userOp from a **Kernel** account | 182,649 | 224,499 | -41,850 | **0** (0.00%) | 0 | replay costs more | 9 (4S/4C/1L1) |  |
| ZeroDev | [`0x6a01cb04…`](https://etherscan.io/tx/0x6a01cb04154fa3077dc686bcdf0d3c034d703cd4e3665cb3e776d916af3aa0fd) | EntryPoint `handleOps`, 1 userOp from a **Kernel v2.4** account | 162,270 | 200,964 | -38,694 | **0** (0.00%) | 0 | replay costs more | 9 (4S/4C/1L1) |  |
| ZeroDev | [`0xcabc8ae7…`](https://etherscan.io/tx/0xcabc8ae7254a9bef80ddf6d8f6276d6b8bb2a3d000f6a5b2265007814250c2eb) | EntryPoint `handleOps`, 1 userOp from a **Kernel v2.4** account | 145,146 | 183,816 | -38,670 | **0** (0.00%) | 0 | replay costs more | 9 (4S/4C/1L1) |  |
| Aragon | [`0x9a11baf5…`](https://etherscan.io/tx/0x9a11baf52820a8b6fa0b7c3402a190163ec8ab5152d43d6667df83a43c81c331) | plugin `execute` ✓ `0xfe0d94c1` | 1,221,959 | 876,897 | +345,062 | **295,062** (24.15%) | 0 | — | 3 (1S/1C/1L2) | **call-dominated** — 32 of 33 receipt logs produced inside the replayed `CALL`; recovered from heuristic (claimed 25.78%) |
| Aragon | [`0x3a73cbfe…`](https://etherscan.io/tx/0x3a73cbfe82d45d522aafa83acbc4a44dd89a2b409530e3a52d0076009a036c78) | plugin `execute` ✓ `0xfe0d94c1` | 8,364,080 | 7,845,342 | +518,738 | **468,738** (5.60%) | 0 | — | 3 (1S/1C/1L2) | **call-dominated** — 13 of 14 receipt logs produced inside the replayed `CALL` |
| Aragon | [`0x5f809f01…`](https://etherscan.io/tx/0x5f809f01d5e1a520a5320b2d090ef762a214fd5bbd29f376bf03f2c9dd8ecec5) | plugin `execute` ✓ `0xfe0d94c1` | 2,928,005 | 2,629,545 | +298,460 | **248,460** (8.49%) | 0 | — | 3 (1S/1C/1L2) | **call-dominated** — 123 of 124 receipt logs produced inside the replayed `CALL` |
| Aragon | [`0x8418c9cf…`](https://etherscan.io/tx/0x8418c9cf72855a8e980dd72f7d3a657e5995b3eefe7fd0f61fafffd3810ee551) | plugin `execute` ✓ `0xfe0d94c1` | 2,563,458 | 2,037,722 | +525,736 | **475,736** (18.56%) | 0 | — | 3 (1S/1C/1L2) | **call-dominated** — 56 of 57 receipt logs produced inside the replayed `CALL` |
| Aragon | [`0xb5e91323…`](https://etherscan.io/tx/0xb5e9132393ba30f0c824cd5ef58d55e9bdebdc2dd75fa8d43fedce627ea5724f) | plugin `execute` ✓ `0xfe0d94c1` | 1,419,945 | 1,231,107 | +188,838 | **138,838** (9.78%) | 0 | — | 3 (1S/1C/1L2) | **call-dominated** — 39 of 40 receipt logs produced inside the replayed `CALL` |
| Aragon | [`0x215d1f74…`](https://etherscan.io/tx/0x215d1f7417095252844b825f778f7bec47d15474e223e85b799bb0ce4573efcd) | plugin `execute` ✓ `0xfe0d94c1` | 846,746 | 613,899 | +232,847 | **182,847** (21.59%) | 0 | — | 3 (1S/1C/1L2) | **call-dominated** — 20 of 21 receipt logs produced inside the replayed `CALL` |
| Aragon | [`0x59aaf7ea…`](https://etherscan.io/tx/0x59aaf7eaaea44ff4a6af66c3617d8040c9e78c09ddab45c2952d55ad869cee60) | Multisig `createProposal` ✓ `0xfbd56e41` | 779,933 | 839,488 | -59,555 | **0** (0.00%) | 0 | replay costs more | 42 (38S/2L3/1C/1L2) | **call-dominated** — 4 of 7 receipt logs produced inside the replayed `CALL` |
| Aragon | [`0x415e03e4…`](https://etherscan.io/tx/0x415e03e4c2ac8554ec2a5d6baa93c6c4f8c4d1a10d729029b448ad81df5e7d72) | Multisig `createProposal` ✓ `0xfbd56e41` | 779,885 | 839,440 | -59,555 | **0** (0.00%) | 0 | replay costs more | 42 (38S/2L3/1C/1L2) | **call-dominated** — 4 of 7 receipt logs produced inside the replayed `CALL` |
| Aragon | [`0x2a5b4f66…`](https://etherscan.io/tx/0x2a5b4f66df51696c39c40c0ee26a01934e67011872b44c4e9dea7d07a0fbb397) | Multisig `createProposal` ✓ `0xfbd56e41` | 779,885 | 839,344 | -59,459 | **0** (0.00%) | 0 | replay costs more | 42 (38S/2L3/1C/1L2) | **call-dominated** — 4 of 7 receipt logs produced inside the replayed `CALL` |
| Aragon | [`0xf52bf2b8…`](https://etherscan.io/tx/0xf52bf2b899889c76e0d30d1d3ccef2897cf4cf53b48ba6e4f09c2edaf5d7fc67) | Multisig `createProposal` ✓ `0xfbd56e41` | 4,933,009 | 5,583,640 | -650,631 | **0** (0.00%) | 0 | replay costs more | 266 (265S/1L3) |  |
| Aragon | [`0x5ea007bf…`](https://etherscan.io/tx/0x5ea007bfa09947742aa3708156203975cf306d3b021036a82834560af032825a) | Multisig `createProposal` ✓ `0xfbd56e41` | 3,600,315 | 4,041,397 | -441,082 | **0** (0.00%) | 0 | replay costs more | 187 (186S/1L3) |  |
| Aragon | [`0x55333434…`](https://etherscan.io/tx/0x55333434ae82aa133ebee6a31d4fac9c251c881394776f7ba28fe4a02cd24165) | Multisig `createProposal` ✓ `0xfbd56e41` | 2,120,898 | 2,382,001 | -261,103 | **0** (0.00%) | 0 | replay costs more | 117 (116S/1L3) |  |
| Aragon | [`0xd7e6f307…`](https://etherscan.io/tx/0xd7e6f3078f6a145567e5c63540c21b369a826f95059d2a9b5504dd9a7e71d9ca) | Multisig `createProposal` ✓ `0xfbd56e41` | 1,797,514 | 2,002,150 | -204,636 | **0** (0.00%) | 0 | replay costs more | 95 (94S/1L3) |  |
| Aragon | [`0xbe13a890…`](https://etherscan.io/tx/0xbe13a890f1d42d1f805b8c1ba37c425b33cf5d1f1cacd7e75dc50e36a41832c2) | Multisig `createProposal` ✓ `0xfbd56e41` | 1,704,722 | 1,938,462 | -233,740 | **0** (0.00%) | 0 | replay costs more | 113 (112S/1L3) |  |
| Aragon | [`0x5a277db6…`](https://etherscan.io/tx/0x5a277db6cc2dc98ca29b75ce3a65c9f94cb11c6a74e32ebd684c3cae811a34d5) | Multisig `createProposal` ✓ `0xfbd56e41` | 1,527,109 | 1,721,110 | -194,001 | **0** (0.00%) | 0 | replay costs more | 92 (91S/1L3) |  |
| Aragon | [`0x70a709c7…`](https://etherscan.io/tx/0x70a709c7cc559ae789324a97a4274430a9c8f36248f8389f6e5554747214e3b8) | Multisig `createProposal` ✓ `0xfbd56e41` | 674,728 | 726,034 | -51,306 | **0** (0.00%) | 0 | replay costs more | 34 (33S/1L3) |  |
| Aragon | [`0x6d7811d9…`](https://etherscan.io/tx/0x6d7811d9cd76deb1b93a64ed71489ac568a966fce11b8a75c6ff6170d2bb6877) | *unidentified* `0xe978afe5` | 413,213 | 491,468 | -78,255 | **0** (0.00%) | 0 | replay costs more | 28 (14S/14L4) |  |
| Aragon | [`0xf0f7520f…`](https://etherscan.io/tx/0xf0f7520f273464f42bbedd0f0460548290ea4c674a8978a41e7b90013911e5ee) | Multisig `approve` ✓ `0x747442d3` | 81,408 | 79,384 | +2,024 | **0** (0.00%) | 0 | under the floor | 3 (2S/1L3) |  |
| Aragon | [`0xccdc5f46…`](https://etherscan.io/tx/0xccdc5f4692cc057e07474e7c3d6eb1826bc8aaddd2cebe756349c6fc35288df2) | Multisig `approve` ✓ `0x747442d3` | 81,408 | 79,372 | +2,036 | **0** (0.00%) | 0 | under the floor | 3 (2S/1L3) |  |
| Frax | [`0x90708b44…`](https://etherscan.io/tx/0x90708b4454d6d7e5dc8dcc44b44034a7fa9967ebef463de6eb21b3f12c9d763b) | FraxswapRouter `swapExactTokensForTokens` ✓ `0x38ed1739` | 217,674 | 221,917 | -4,243 | **0** (0.00%) | 0 | replay costs more | 3 (3C) | router — all work nested in pair contracts, dropped at `trace.rs:255` |
| Frax | [`0x23b0a5dc…`](https://etherscan.io/tx/0x23b0a5dc6f12e48f79b97f0e8f4c7240e3e93c16ce4b46373f79d9735fbd0694) | FraxswapRouter `swapExactTokensForTokens` ✓ `0x38ed1739` | 213,167 | 217,410 | -4,243 | **0** (0.00%) | 0 | replay costs more | 3 (3C) | router — all work nested in pair contracts, dropped at `trace.rs:255` |
| Frax | [`0x4108ebf1…`](https://etherscan.io/tx/0x4108ebf139950b48bc09542acc14974874cfc1cc25c80d503b5becca60d43841) | FraxswapRouter `swapExactTokensForTokens` ✓ `0x38ed1739` | 208,660 | 212,903 | -4,243 | **0** (0.00%) | 0 | replay costs more | 3 (3C) | router — all work nested in pair contracts, dropped at `trace.rs:255` |
| Frax | [`0x334d2c7e…`](https://etherscan.io/tx/0x334d2c7ee4103f7f46cf6be9cc6bbe34e73ff83e6caf0440a29f9119b3c512e9) | FraxswapRouter `swapExactTokensForTokens` ✓ `0x38ed1739` | 208,660 | 212,903 | -4,243 | **0** (0.00%) | 0 | replay costs more | 3 (3C) | router — all work nested in pair contracts, dropped at `trace.rs:255` |
| Frax | [`0x2fbe40e2…`](https://etherscan.io/tx/0x2fbe40e2de7a3e1c2f8683e6e930a9a0590f978ae2307ee557a02eec2b000ef1) | FraxswapRouter `swapExactTokensForTokens` ✓ `0x38ed1739` | 208,660 | 212,903 | -4,243 | **0** (0.00%) | 0 | replay costs more | 3 (3C) | router — all work nested in pair contracts, dropped at `trace.rs:255` |
| Frax | [`0x462742b2…`](https://etherscan.io/tx/0x462742b2df4366d41e94270be3f1bf23529c4ec3a78e637692b5a11930733fb3) | FXS `transfer` ✓ `0xa9059cbb` | 128,870 | 152,949 | -24,079 | **0** (0.00%) | 0 | replay costs more | 9 (6S/2L2/1L3) |  |
| Frax | [`0xcbe7ff8b…`](https://etherscan.io/tx/0xcbe7ff8b218e51097cfedda408e3415906c6fa9ca3f4b653d0ada6fefc63023b) | FXS `transfer` ✓ `0xa9059cbb` | 97,233 | 118,929 | -21,696 | **0** (0.00%) | 0 | replay costs more | 9 (6S/2L2/1L3) |  |
| Frax | [`0xac0f72a0…`](https://etherscan.io/tx/0xac0f72a0d731fa43e4c0884d1fa60ce1e42d766050cab1fd718d3d14524ea421) | FXS `transfer` ✓ `0xa9059cbb` | 97,221 | 118,965 | -21,744 | **0** (0.00%) | 0 | replay costs more | 9 (6S/2L2/1L3) |  |
| Frax | [`0x7a627d3f…`](https://etherscan.io/tx/0x7a627d3fe217192bfd0e6fcfdf40ae4c1e56d8f50f391717ad196da52e357ee4) | sfrxETH `redeem` ✓ `0xba087652` | 78,365 | 97,929 | -19,564 | **0** (0.00%) | 0 | replay costs more | 6 (3S/1L3/1L4/1C) |  |
| Frax | [`0xe8708b5a…`](https://etherscan.io/tx/0xe8708b5a62fd630f36c44bdb32be6b9faf46f78c7d5c99181bdadf026841a32a) | frxETH `approve` ✓ `0x095ea7b3` | 46,619 | 55,564 | -8,945 | **0** (0.00%) | 0 | replay costs more | 2 (1S/1L3) | control: bookkeeping, expected 0% |
| Sky | [`0x77b86295…`](https://etherscan.io/tx/0x77b862956888e2596c3488b625eb227d0ac7da838e711e0dd702c1fea2a60ea2) | sUSDS `redeem` ✓ `0xba087652` | 148,203 | 174,502 | -26,299 | **0** (0.00%) | 0 | replay costs more | 9 (3C/1L1/1L3/1L4/3S) |  |
| Sky | [`0xd13aa7d3…`](https://etherscan.io/tx/0xd13aa7d3a3b423b3f705b6a42f0dc8960c97b3bdafcae23bb69b3a37edd7fb73) | sUSDS `withdraw` ✓ `0xb460af94` | 148,058 | 174,490 | -26,432 | **0** (0.00%) | 0 | replay costs more | 9 (3C/1L1/1L3/1L4/3S) |  |
| Sky | [`0x72447406…`](https://etherscan.io/tx/0x72447406351431526cc15cc615b0ea33e721af225347728bacb95a974705b0ea) | sUSDS `deposit` ✓ `0x9b8d6d38` | 145,878 | 177,107 | -31,229 | **0** (0.00%) | 0 | replay costs more | 10 (3C/1L1/3L3/3S) |  |
| Sky | [`0x49581560…`](https://etherscan.io/tx/0x495815608a04d20d2c25565c0d11081f78db2e6252f5edaa2781cafe94cf2071) | sUSDS `deposit` ✓ `0x9b8d6d38` | 145,585 | 177,095 | -31,510 | **0** (0.00%) | 0 | replay costs more | 10 (3C/1L1/3L3/3S) |  |
| Grove | [`0x82060585…`](https://etherscan.io/tx/0x820605858de5101d4a935a72dc7968502cd6dd43ca9a103817b44b53346ec97c) | *unidentified* `0x9aefaff8` | 2,283,620 | 2,287,372 | -3,752 | **0** (0.00%) | 0 | replay costs more | 1 (1C) | one-off governance spell — the only Grove transaction in 28 days that is **not** a Safe `execTransaction`; 24 receipt logs, 1 recorded |
| Grove | [`0x72a712a0…`](https://etherscan.io/tx/0x72a712a0dff8a9b526f8816659f17471ec8529a720cd6efa6b590e5a08893303) | Safe `execTransaction` ✓ `0x6a761202` | 998,513 | 983,468 | +15,045 | **0** (0.00%) | 0 | under the floor | 5 (3C/1S/1L2) | replays `mintUSDS`, `swapUSDSToUSDC`, `addLiquidityUniswapV3` whole — 35 receipt logs, 1 recorded |
| Grove | [`0x2534eae7…`](https://etherscan.io/tx/0x2534eae75a28b2f9c1431cd26d788b3eaa4da92afa2de5cfa5d84c42397cd55b) | Safe `execTransaction` ✓ `0x6a761202` | 833,788 | 821,836 | +11,952 | **0** (0.00%) | 0 | under the floor | 5 (3C/1S/1L2) | replays `mintUSDS`, `swapUSDSToUSDC`, `depositERC4626` whole — 38 receipt logs, 1 recorded |
| Grove | [`0x0ce6843c…`](https://etherscan.io/tx/0x0ce6843c42b48bb0589ad6a26afa8d9eee4772b76b7e6b6dbb5146867abd4be4) | Safe `execTransaction` ✓ `0x6a761202` | 690,600 | 678,650 | +11,950 | **0** (0.00%) | 0 | under the floor | 5 (3C/1S/1L2) | replays `claimRedeemERC7540`, `swapUSDCToUSDS`, `burnUSDS` whole — 31 receipt logs, 1 recorded |
| Grove | [`0x30e46f89…`](https://etherscan.io/tx/0x30e46f8952ac26e1df0656d256223f026a633dd0dfbffb9ed9d211fe32a853ca) | Safe `execTransaction` ✓ `0x6a761202` | 660,286 | 642,381 | +17,905 | **0** (0.00%) | 0 | under the floor | 4 (2C/1S/1L2) | replays `withdrawERC4626`, `swapUniswapV3` whole — 18 receipt logs, 1 recorded |
| Grove | [`0x8c88ef09…`](https://etherscan.io/tx/0x8c88ef09112f2d9f7d112723db516eda02056ace934eb751957500b914c6d600) | Safe `execTransaction` ✓ `0x6a761202` | 583,854 | 565,937 | +17,917 | **0** (0.00%) | 0 | under the floor | 4 (2C/1S/1L2) | replays `withdrawERC4626`, `swapUniswapV3` whole — 18 receipt logs, 1 recorded |
| Grove | [`0xff9475b4…`](https://etherscan.io/tx/0xff9475b4238dedeb59124201f1772a396fae59ea4ed342c907c69f0af0c4ef7e) | Safe `execTransaction` ✓ `0x6a761202` | 542,909 | 530,945 | +11,964 | **0** (0.00%) | 0 | under the floor | 5 (3C/1S/1L2) | replays `mintUSDS`, `swapUSDSToUSDC`, `transferAsset` whole — 26 receipt logs, 1 recorded |
| Grove | [`0x65276f18…`](https://etherscan.io/tx/0x65276f188f1dc7af9e60f582f87aa09ab34d40556182355c9a4134b3310ac653) | Safe `execTransaction` ✓ `0x6a761202` | 502,204 | 487,940 | +14,264 | **0** (0.00%) | 0 | under the floor | 4 (2C/1S/1L2) | replays `swapUSDCToUSDS`, `burnUSDS` whole — 25 receipt logs, 1 recorded |
| Grove | [`0x402d3aeb…`](https://etherscan.io/tx/0x402d3aeb8049f2ac33ffbda112e6a16ad9babd4cf1e44d2c10d835d71882dbc1) | Safe `execTransaction` ✓ `0x6a761202` | 146,292 | 125,513 | +20,779 | **0** (0.00%) | 0 | under the floor | 3 (1C/1S/1L2) | replays `transferAsset` whole — 3 receipt logs, 1 recorded |
| Grove | [`0x3b2f94ca…`](https://etherscan.io/tx/0x3b2f94ca433264748a3534dc3357f0f91015c451008c4521fea21192210e9d4c) | Safe `execTransaction` ✓ `0x6a761202` | 124,428 | 103,637 | +20,791 | **0** (0.00%) | 0 | under the floor | 3 (1C/1S/1L2) | replays `transferAsset` whole — 3 receipt logs, 1 recorded |
| Centrifuge | [`0xf87748e4…`](https://etherscan.io/tx/0xf87748e4f6f929b7397fd4078ca6eaef7cf7e9d9a55930ed157b338ab5c48fe3) | Hub `updateRestriction` ✓ `0x33bcc1c8` | 779,739 | 770,783 | +8,956 | **0** (0.00%) | 0 | under the floor | 4 (2C/1S/1L2) | surplus is the Hub's fixed dispatch cost; the restriction-hook `CALL` is replayed whole |
| Centrifuge | [`0x91e3f815…`](https://etherscan.io/tx/0x91e3f8156bf17a2ca6b6354da8ee39fbc39075c89ac4ae23e74b99629be0c2b4) | Hub `updateRestriction` ✓ `0x33bcc1c8` | 657,820 | 648,864 | +8,956 | **0** (0.00%) | 0 | under the floor | 4 (2C/1S/1L2) | same fixed ~9,000 surplus as the 112,968-gas row |
| Centrifuge | [`0xe3773583…`](https://etherscan.io/tx/0xe3773583af72489947f1d84def8a0d9461aa341609f33d7150d9bc48742102c7) | Hub *unidentified* `0xf3046c8e` | 664,013 | 654,404 | +9,609 | **0** (0.00%) | 0 | under the floor | 4 (2C/1S/1L2) | different function, same ~9,600 surplus |
| Centrifuge | [`0x9fb032dd…`](https://etherscan.io/tx/0x9fb032ddcdb504db55664e85ef50bcb0992a7d96c5730a67770556d409055941) | Hub `updateRestriction` ✓ `0x33bcc1c8` | 125,251 | 116,211 | +9,040 | **0** (0.00%) | 0 | under the floor | 3 (1C/1S/1L2) |  |
| Centrifuge | [`0x2a87769b…`](https://etherscan.io/tx/0x2a87769b97e35faa71c4743742f0f4cb1fedefe523939a480ff64cd8d1454c64) | Hub `updateRestriction` ✓ `0x33bcc1c8` | 112,968 | 103,928 | +9,040 | **0** (0.00%) | 0 | under the floor | 3 (1C/1S/1L2) |  |

## Transactions that could not be measured at all

The tool produced no output and exited cleanly. Every one is a very large trace, so the surveys here systematically miss the biggest and most interesting transactions.

| protocol | tx | why |
|---|---|---|
| Safe | [`0x1cce897f…`](https://etherscan.io/tx/0x1cce897f987a2ca1cf11e83b94daeb0f116ef8bc4c8b06757332c33705bc54a8) | ~6.4M gas |
| Safe | [`0x62dede44…`](https://etherscan.io/tx/0x62dede445b69352285dc30558e87fa5c5b664b8157109625772e60655759872f) | ~5.9M gas |
| Safe | [`0xfde7c414…`](https://etherscan.io/tx/0xfde7c414c1bd53ec908140e72afe5eb34f717e5d8188a8231fcd6b55f4c280e9) | ~6.5M gas |
| EigenLayer | [`0x6508d5bf…`](https://etherscan.io/tx/0x6508d5bfc34439a4005d3c0e8967fe62cf65df140eae5171cb9faa35b8ccc4ac) | checkpoint proof, ~3.4M gas, 85 KB calldata |
| EigenLayer | [`0xe92e3dad…`](https://etherscan.io/tx/0xe92e3dadee2f12722936bb8fc0bf19527e305e4c51a6e63e9f10d481d067e23d) | checkpoint proof, oversized trace |
| Sky | [`0x2f6a9995…`](https://etherscan.io/tx/0x2f6a99957e3f04443c6fb474108c0e26a026bd162317ca2964a48e2fc981c7be) | sUSDS `deposit`, 110,061 gas, 0 logs; replay failed 6 attempts |
| Centrifuge | [`0x0d6d8fe6…`](https://etherscan.io/tx/0x0d6d8fe6b1661549e843bda1fad0b431e4a208c825d24696bea7b748dbf27db5) | Hub `multicall`, 131,622 gas; replay reverts `NotManager()` (`0xc0fc8a8a`) |
| Centrifuge | [`0xe918bd9f…`](https://etherscan.io/tx/0xe918bd9fec54b88f58525b5662246e57e081c8f8aa94ec35985991ba7e4cb036) | Hub `multicall`, 883,816 gas; replay reverts `NotManager()` |
| Centrifuge | [`0x338688a1…`](https://etherscan.io/tx/0x338688a155a5c48cd2ebbffd25b0088f26bcf8f8a4cbe41ba8e258e856c646b0) | Hub `multicall`, 1,842,769 gas; replay reverts `NotManager()` |
| Centrifuge | [`0x81dcf346…`](https://etherscan.io/tx/0x81dcf3462864909275012719f63080d2a2f4f9bf6e76924a6c8e67060e362e3d) | VaultRouter `multicall`, 353,308 gas; RPC 50/second limit while replaying preceding txs, 10 attempts |
| Centrifuge | [`0xa5b90e8b…`](https://etherscan.io/tx/0xa5b90e8bb47ceec5fb55a32ef552c63c81f425f0f80d4b485697e4169575379c) | VaultRouter `multicall`, 454,309 gas; same RPC rate limit, 10 attempts |

Four Morpho liquidations failed the real replay for other reasons and appear in the table above with `heur` numbers you should not trust: one sender is an EIP-7702 smart EOA the simulator rejects outright, two revert reproducibly part-way through the replay, and one was rate-limited. `MORPHO_CANDIDATES.md` has the detail.

## What to be careful about

- **15 of the results are `heur` fallbacks** (Morpho 7, Euler 3, Ethena 3, Railgun 2). Ignore their savings figures. The three biggest apparent Morpho wins in this file (16.32%, 13.47%, 11.25% — quoted at the old floor) are all fallbacks. **The heuristic estimator itself was also fixed upstream (`271cd74`), so these rows are stale for two independent reasons and must be re-run on the rebuilt binary before use.** Of the 18 fallbacks re-measured properly so far, **16 collapsed to 0%** (6 in Ethena, 4 corrected in place across Morpho/Aave/Ether.fi, all 8 in ENS). The two exceptions are both Pyth, where a real saving survived but shrank — `0x8874d5a5…` from 65.79% to 49.76%, and `0x616ba1cd…` down to 63.94% (41.53% and 52.06% respectively at the 50,000 floor). So a fallback is not automatically fictional; it is automatically *overstated*, and on this evidence it is fictional about 90% of the time.
- **Most unmeasurable transactions are large.** EigenLayer's real ceiling is unknown for this reason. The exceptions are Sky's 110,061-gas `deposit` and Centrifuge's 131,622-gas `multicall`, which fail for reasons unrelated to size.
- **Two Ondo rows are mislabelled traffic**, flagged in the notes column — an MEV bot and an aggregator that happen to touch Ondo tokens. Ondo's own mint and redeem transactions save 1–2%.
- **A `heur` row with zero external calls is still not trustworthy.** ENS produced four such rows and the biggest was wrong by 125,611 gas. The fallback underprices fresh storage writes as well as calls.
- **ENS is fully measured (18/18) and uniformly zero.** It is the one protocol here where the negative result is structural rather than a sampling artefact.
- **Sample sizes are small per protocol** (7–26 transactions, drawn from a few thousand recent blocks). The direction of each result is solid; the exact percentages are not a population average.

Deeper write-ups: `PROTOCOL_SURVEY.md` (per protocol), `MORPHO_CANDIDATES.md` (Morpho and liquidations), `CALL_BLOCKED_CANDIDATES.md` (the external-call group).

