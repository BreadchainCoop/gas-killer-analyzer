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