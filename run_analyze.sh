#!/bin/bash
source .env
while true; do
    # Get the latest block number
    block_number=$(cast bn -r "$RPC_URL")
    echo "Processing block: $block_number"

    # Get transaction hashes from the latest block
    tx_hashes=$(cast bl -r "$RPC_URL" --json | jq -r '.transactions[]')

    # Loop through each transaction in the block
    echo "$tx_hashes" | while read -r tx_hash; do
        # Get the gas limit for the transaction
        gas=$(cast tx "$tx_hash" -r "$RPC_URL" --json | jq -r '.gas')

        # Analyze what portion of its gas can be saved
        sleep 10

        # Run the analysis script
        DATA=$(python3 analyze.py "$tx_hash" "$RPC_URL" "$block_number")
        
        if [ $? -eq 0 ]; then
            echo "tx_hash: $tx_hash"
        else
            echo "analyze script failure"
        fi
    done

    # Wait a bit before checking the next block to avoid excessive API calls
    sleep 5
done




