# Gas Analyzer

Compute state update instructions for gas killer application and estimate gas savings

## Implementation Notes
- Uses transaction tracing API (not trace call) since trace call can't produce execution traces
- Executes transactions in forked Anvil (non-forked can't generate Geth traces)
- Note: Real blockchain traces may differ due to other transactions in block

## Setup
1. Clone the repository
2. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```
3. Fill in the required environment variables in `.env`:

## Tests
```bash
cargo test
```

## CLI (unstable)
The CLI currently supports analyzing single transactions and complete blocks (using the respective hashes) or transaction requests (provided as json files).

For a transaction: 
```bash
cargo run -- t aecc4a9d20d48a84989bca3ffaf1001c8965d86d90ba688020deb958ddf9ed12
```
For a block:

```bash
cargo run -- b 0x386725b93d39849e06d42c52b6ed492d98459f12db1f6c124ab483f5e7a64375
cargo run -- b latest
```

For a transaction request:
```bash
cargo run -- r path/to/file.json
```


The analysis report is written to `reports.csv`.
