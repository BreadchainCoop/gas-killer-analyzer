#!/bin/bash

# Usage: ./decode-gk-error.sh 0xaa86ecee...
# Copy from the error log column in report.csv

error_args=$(cast decode-error --json --sig "RevertingContext(address,bytes)" "$1")
target_address=$(echo "$error_args" | jq -r '.[0]')
error_data=$(echo "$error_args" | jq -r '.[1]' | cast 4byte-calldata)

echo "target_address: $target_address"
echo "error_data: $error_data"
