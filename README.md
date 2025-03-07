# Gas Killer Analyzer

A tool for analyzing Ethereum transactions to identify potential gas savings.

## Overview

Gas Killer Analyzer monitors the Ethereum blockchain in real-time, analyzing transactions to determine how much gas could potentially be saved. This tool helps developers and users optimize their transactions for cost efficiency.

## Features

- Real-time blockchain monitoring
- Transaction gas usage analysis
- Detailed reports on potential gas savings
- Support for custom RPC endpoints

## Prerequisites

- Python 3
- [Foundry](https://book.getfoundry.sh/) (for `cast` commands)
- jq (JSON processor)

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/gas-killer-analyzer.git
   cd gas-killer-analyzer
   ```

2. Set up a Python virtual environment (recommended):
   ```
   # Create a virtual environment
   python3 -m venv venv
   
   # Activate the virtual environment
   # On macOS/Linux:
   source venv/bin/activate
   # On Windows:
   # venv\Scripts\activate
   
   # Your terminal prompt should now show (venv) indicating the virtual environment is active
   ```

3. Install Python dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Configure your environment variables:
   ```
   cp example.env .env
   # Edit .env with your RPC URL and other settings
   ```

## Usage

1. Make sure your virtual environment is activated:
   ```
   # If not already activated
   source venv/bin/activate  # On macOS/Linux
   # venv\Scripts\activate   # On Windows
   ```

2. Source your environment variables:
   ```
   source .env
   ```

3. Run the analyzer:
   ```
   ./run_analyze.sh
   ```

The script will:
1. Fetch the latest block from the blockchain
2. Analyze each transaction in the block
3. Calculate potential gas savings
4. Output the results

4. When you're done, you can deactivate the virtual environment:
   ```
   deactivate
   ```

## Configuration

Configuration is handled through environment variables in the `.env` file:

- `RPC_URL`: URL for your Ethereum RPC provider (required)
- Additional configuration options can be added as needed