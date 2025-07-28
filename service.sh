#!/bin/bash 
#set -x

export PATH="/usr/local/bin:/usr/bin:/bin:$PATH"

# --- Configuration ---
# The public RPC endpoint for the Ethereum mainnet.
# You can replace this with your own or another public one.
RPC_URL=
OUTPUT_FILE="reports.csv"
# --- Script Start ---
TX_HASHES=() # Initialize an empty array
while read -r hash; do
    TX_HASHES+=("$hash")
done < <(curl -s -X POST -H "Content-Type: application/json" \
          --data '{"jsonrpc":"2.0","method":"eth_getBlockReceipts","params":["latest"],"id":1}' \
          "$RPC_URL" | \
          jq -r '(.result // [])[] | "\(.gasUsed) \(.transactionHash)"' | \
          while read -r gas_used tx_hash; do
            if (( gas_used > 200000 )); then
              echo "$tx_hash"
            fi
          done)

# Step 2: Iterate over the array
echo "Found ${#TX_HASHES[@]} transactions with gas used > 200,000"
for hash in "${TX_HASHES[@]}"; do
  echo "Processing transaction: $hash"
  ./cli t "$hash"
  # You can now use the "$hash" variable for other commands
done
