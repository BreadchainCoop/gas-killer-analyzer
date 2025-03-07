#!/usr/bin/env python3

import sys
import json
import requests
import matplotlib.pyplot as plt
import csv
from datetime import datetime

PRINT_FLAG = False

def main():
    if len(sys.argv) < 3:
        print("Usage: analyze_trace.py <TRANSACTION_HASH> [RPC_ENDPOINT] [BLOCK_NUMBER]")
        sys.exit(1)

    tx_hash = sys.argv[1]

    # Default to a local Geth endpoint; override by second argument if provided
    rpc_endpoint = sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:8545"
    block_number = sys.argv[3] if len(sys.argv) > 3 else None

    # If block number not provided, fetch it
    if block_number is None:
        block_payload = {
            "jsonrpc": "2.0",
            "method": "eth_getTransactionByHash",
            "params": [tx_hash],
            "id": 1
        }
        try:
            response = requests.post(rpc_endpoint, json=block_payload)
            response.raise_for_status()
            tx_data = response.json()
            if "result" in tx_data and tx_data["result"]:
                block_number = int(tx_data["result"]["blockNumber"], 16)
            else:
                print(f"Could not fetch block number for transaction {tx_hash}")
                sys.exit(1)
        except requests.exceptions.RequestException as e:
            print(f"Error fetching transaction data: {e}")
            sys.exit(1)

    # Prepare the JSON-RPC payload
    payload = {
        "jsonrpc": "2.0",
        "method": "debug_traceTransaction",
        "params": [tx_hash, {}],
        "id": 1
    }

    try:
        # Send request
        response = requests.post(rpc_endpoint, json=payload)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to {rpc_endpoint}:\n{e}")
        sys.exit(1)

    result = response.json()

    # Check if we have a valid 'result' object in the response
    if "result" not in result:
        print("No valid 'result' in the JSON-RPC response:")
        print(result)
        sys.exit(1)

    trace_result = result["result"]

    # The Geth debug trace typically has a "structLogs" array of opcodes
    struct_logs = trace_result.get("structLogs", [])

    # Accumulators
    total_gas = trace_result["gas"]
    call_gas = 0
    sstore_gas = 0
    static_call_gas = 0
    sload_gas = 0
    other_gas = 0
    create_gas = 0
    log_gas = 0

    struct_logs = iter(struct_logs)
    try:
        entry = next(struct_logs)
    except StopIteration:
        print("No trace data available")
        sys.exit(1)

    first_entry = entry
    while True:
        try: 
            # print(entry)
            op = entry.get("op")
            gas_cost = entry.get("gasCost")

            if entry["depth"] == 1:
                if op in ["CALL", "DELEGATECALL", "CALLCODE"]:
                    while True:
                        entry2 = next(struct_logs)
                        if entry2["depth"] == 1:
                            break
                    gas_diff = entry["gas"] - entry2["gas"]
                    call_gas += gas_diff
                elif op == "SSTORE":
                    sstore_gas += gas_cost
                elif op == "STATICCALL":
                    while True:
                        entry2 = next(struct_logs)
                        if entry2["depth"] == 1:
                            break
                    gas_diff = entry["gas"] - entry2["gas"]
                    static_call_gas += gas_diff
                elif op == "SLOAD":
                    sload_gas += gas_cost
                elif op in ["LOG0", "LOG1", "LOG2", "LOG3", "LOG4"]:
                    log_gas += gas_cost
                elif op in ["CREATE", "CREATE2"]:
                    create_gas += gas_cost
            
                else:
                    other_gas += gas_cost
            entry = next(struct_logs)
        except StopIteration:
            break

    # if refund is missing the calculations aren't accurate
    refund = entry.get("refund", 0)
    total_gas_including_refund = total_gas + refund
    total_evm_gas = first_entry["gas"] - entry["gas"]
    total_non_evm_gas = total_gas_including_refund - total_evm_gas
    state_change_gas = call_gas + sstore_gas + log_gas + create_gas
    state_read_gas = static_call_gas + sload_gas

    # Create CSV file if it doesn't exist
    csv_filename = "transaction_analysis.csv"
    file_exists = False
    try:
        with open(csv_filename, 'r') as f:
            file_exists = True
    except FileNotFoundError:
        pass

    with open(csv_filename, 'a', newline='') as csvfile:
        fieldnames = ['timestamp', 'tx_hash', 'block_number', 'total_gas', 'refund', 'refund_percentage',
                     'non_evm_gas', 'non_evm_percentage', 'state_change_gas', 'state_change_percentage',
                     'state_read_gas', 'state_read_percentage', 'other_gas', 'other_percentage', 'margin','margin_dollar']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        if not file_exists:
            writer.writeheader()

        # Write the row with all metrics
        writer.writerow({
            'timestamp': datetime.now().isoformat(),
            'tx_hash': tx_hash,
            'block_number': block_number,
            'total_gas': total_gas_including_refund,
            'refund': refund,
            'refund_percentage': round((refund * 100 / total_gas_including_refund), 2),
            'non_evm_gas': total_non_evm_gas,
            'non_evm_percentage': round((total_non_evm_gas * 100 / total_gas_including_refund), 2),
            'state_change_gas': state_change_gas,
            'state_change_percentage': round((state_change_gas * 100 / total_gas_including_refund), 2),
            'state_read_gas': state_read_gas,
            'state_read_percentage': round((state_read_gas * 100 / total_gas_including_refund), 2),
            'other_gas': other_gas,
            'other_percentage': round((other_gas * 100 / total_gas_including_refund), 2),
            'margin': state_read_gas + other_gas,
            'margin_dollar': ((state_read_gas + other_gas) * (10**9) * 3200) / (10**18)  # Assuming $3200 ETH price
        })

    if PRINT_FLAG:
        print(f"Transaction Hash: {tx_hash}")
        print(f"Block Number: {block_number}")
        print(f"Gas total (including refund): {total_gas_including_refund}")
        print(f"Refunded: {refund} ({(refund * 100 / total_gas_including_refund):.2f}%)")
        print(f"Gas spent on non-evm: {total_non_evm_gas} ({(total_non_evm_gas * 100 / total_gas_including_refund):.2f}%)")
        print(f"Gas spent on state changes: {state_change_gas} ({(state_change_gas * 100 / total_gas_including_refund):.2f}%)")
        print(f"Gas spent on state reads: {state_read_gas} ({(state_read_gas * 100 / total_gas_including_refund):.2f}%)")
        print(f"Gas spent on other: {other_gas} ({(other_gas * 100 / total_gas_including_refund):.2f}%)")
    else:
        result = { 
            "tx_hash": tx_hash,
            "block_number": block_number,
            "margin": state_read_gas + other_gas 
        }
        print(json.dumps(result))

    # plot_gas_distribution(total_non_evm_gas, state_change_gas, state_read_gas, other_gas, tx_hash)

def plot_gas_distribution(non_evm, modification_gas, access_gas, other_gas, tx_hash):
    """Plots a pie chart of the gas distribution with absolute values on slices 
    and total gas text at the bottom."""
    labels = [
        "Non-EVM gas",
        "State modification gas",
        "State access gas",
        "Other"
    ]
    values = [non_evm, modification_gas, access_gas, other_gas]
    total_gas = sum(values)
    
    # Optional: create a custom autopct to show both percentage and absolute value.
    def autopct_generator(values):
        total = sum(values)
        def autopct(pct):
            absolute = int(round(pct * total / 100.0))
            return "{:.1f}%\n({:d})".format(pct, absolute)
        return autopct

    fig, ax = plt.subplots(figsize=(6, 6))
    
    # Create the pie chart
    # autopct will place both the percentage and the absolute value on each slice.
    wedges, texts, autotexts = ax.pie(
        values,
        labels=labels,
        autopct=autopct_generator(values),
        startangle=140
    )
    
    # Set the title
    ax.set_title(f"Transaction {tx_hash[:10]} gas distribution")

    # Ensures the pie chart is a circle, not an oval
    ax.axis("equal")  

    # Place a text box at the bottom of the chart with total gas
    # The (0.5, -0.1) coordinates place the text centered below the chart.
    ax.text(
        0.5, 
        -0.1, 
        f"Total Gas: {total_gas}", 
        transform=ax.transAxes, 
        ha='center', 
        va='center'
    )

    # Adjust layout so the text at the bottom isn't clipped
    plt.tight_layout()

    # Display the chart
    plt.show()

if __name__ == "__main__":
    main()