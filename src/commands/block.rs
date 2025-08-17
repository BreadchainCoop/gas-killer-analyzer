use std::collections::HashSet;

use alloy::{consensus::EthereumTypedTransaction, network::{TransactionBuilder, TransactionBuilder7702}, node_bindings::Anvil, primitives::{Address, Bytes, TxKind, U256}, signers::local::PrivateKeySigner, sol};
use alloy_rpc_types::{AccessList, BlockTransactions, Transaction, TransactionReceipt, TransactionRequest};
use anyhow::{anyhow, Result};
use alloy_eips::{eip1898::BlockId, eip7702::SignedAuthorization};
use alloy_provider::{ext::AnvilApi, Provider, ProviderBuilder};
use futures::{stream, StreamExt, TryStreamExt};
use url::Url;

use crate::{compute_state_updates, encode_state_updates_to_abi, get_tx_trace};

sol!(
    #[sol(rpc)]
    StateChangeHandlerGasEstimator,
    "res/abi/StateChangeHandlerGasEstimator.json"
);

pub async fn run(block_id: BlockId) -> Result<()> {
    let fork_url: Url = env::var("FORK_URL")
        .expect("FORK_URL must be set")
        .parse()
        .expect("FORK_URL must be a valid URL");
    let regular_provider = ProviderBuilder::new().connect_http(fork_url.clone());
    let block_number = regular_provider.get_block_number_by_id(block_id).await?.expect("block number must be found");
    let anvil = Anvil::new()
        .args(["--order", "fifo"])
        .fork(fork_url.as_str())
        .fork_block_number(block_number - 1)
        .try_spawn()?;
    let forked_provider = ProviderBuilder::new()
        .with_simple_nonce_management()
        .connect_http(anvil.endpoint_url());
    forked_provider.anvil_set_auto_mine(false).await?;
    forked_provider.anvil_auto_impersonate_account(true).await?;

    // clean slate anvil so I could deploy contracts without fucking up the block being built
    // needed in order to compute the runtime code of GasEstimator instances
    let dummy_signer = PrivateKeySigner::random();
    let dummy_from = dummy_signer.address();
    let bin_anvil = Anvil::new().try_spawn()?;
    let bin_provider = ProviderBuilder::new()
        .with_simple_nonce_management()
        .wallet(dummy_signer)
        .connect_http(bin_anvil.endpoint_url());
    bin_provider.anvil_set_auto_mine(true).await?;
    bin_provider.anvil_set_balance(dummy_from, U256::from_str_radix("100000000000000000000", 10).unwrap()).await?;

    let block = regular_provider.get_block_by_number(alloy_eips::BlockNumberOrTag::Number(block_number)).await?.expect("block must be found");
    let txs = match block.transactions {
        BlockTransactions::Hashes(hashes) => {
            println!("collecting txs from hashes...");
            let txs = stream::iter(hashes)
                .map(|hash| {
                    regular_provider.get_transaction_by_hash(hash)
                })
                .buffer_unordered(4)
                .try_collect::<Vec<_>>()
                .await?
                .into_iter()
                .filter_map(|tx| tx)  // TODO: should not accept None
                .collect::<Vec<_>>();
            println!("done!");
            println!("preparing txs...");
            stream::iter(txs)
                .map(|tx| prepare_tx(&regular_provider, tx))
                .buffer_unordered(4)
                .try_collect::<Vec<_>>()
                .await?
                .into_iter()
                .filter_map(|tx| tx)
                .collect::<Vec<_>>()
        }
        BlockTransactions::Full(txs) => stream::iter(txs)
            .map(|tx| prepare_tx(&regular_provider, tx))
            .buffer_unordered(4)
            .try_collect::<Vec<_>>()
            .await?
            .into_iter()
            .filter_map(|tx| tx)
            .collect::<Vec<_>>(),
        BlockTransactions::Uncle => panic!("wtf do I do with an uncle?")
    };

    let mut stepped_smart_contracts = HashSet::new();
    let mut tx_hashes = Vec::new();
    println!("sending txs...");
    for tx in txs {
        let tx_request = match tx.tx_kind_data {
            TxKindData::SmartContract { to, code, .. } => {
                if !stepped_smart_contracts.contains(&to) {
                    println!("before this...");
                    let contract = StateChangeHandlerGasEstimator::deploy(&bin_provider, code).await?;
                    println!("after this...");
                    let gas_estimator_code = bin_provider.get_code_at(*contract.address()).await?;
                    forked_provider.anvil_set_code(to, gas_estimator_code).await?;
                    stepped_smart_contracts.insert(to);
                }

                let trace = get_tx_trace(&forked_provider, tx.tx.inner.hash().to_owned()).await?;
                let (state_updates, _skipped_opcodes) = compute_state_updates(trace).await?;
                let state_updates_abi = encode_state_updates_to_abi(&state_updates);

                let tx_request = TransactionRequest::default()
                    .with_from(tx.receipt.from)
                    .with_to(to)
                    .with_gas_limit(tx.gas_limit)
                    .with_input(state_updates_abi)
                    .with_value(tx.value);
                let tx_request = add_tx_type_data(tx_request, tx.typed_transaction_data);
                tx_request
            }
            TxKindData::Transfer { to } => {
                let tx_request = TransactionRequest::default()
                    .with_from(tx.receipt.from)
                    .with_to(to)
                    .with_gas_limit(tx.gas_limit)
                    .with_value(tx.value);
                let tx_request = add_tx_type_data(tx_request, tx.typed_transaction_data);
                tx_request
            }
            TxKindData::SmartContractCreation { init_code, .. } => {
                let tx_request = TransactionRequest::default()
                    .with_from(tx.receipt.from)
                    .with_gas_limit(tx.gas_limit)
                    .with_value(tx.value)
                    .with_input(init_code);
                let tx_request = add_tx_type_data(tx_request, tx.typed_transaction_data);
                tx_request
            }
        };

        let tx = forked_provider.send_transaction(tx_request).await?.register();
        tx_hashes.push(tx);
    }

    forked_provider.anvil_mine(Some(1), None).await?;
    let block = forked_provider.get_block_by_number(alloy_eips::BlockNumberOrTag::Latest).await?.expect("block must be found");
    println!("block: {:?}", block);
        
    Ok(())
}

struct TxData {
    tx: Transaction,
    receipt: TransactionReceipt,
    gas_limit: u64,
    value: U256,
    typed_transaction_data: TypedTransactionData,
    tx_kind_data: TxKindData,
}

enum TypedTransactionData {
    Legacy {
        gas_price: u128,
    },
    Eip2930 {
        gas_price: u128,
        access_list: AccessList,
    },
    Eip1559 {
        access_list: AccessList,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
    },
    Eip7702 {
        access_list: AccessList,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
        authorization_list: Vec<SignedAuthorization>,
    }
}

enum TxKindData {
    SmartContract { 
        to: Address,
        code: Bytes,
        calldata: Bytes,
    },
    Transfer {
        to: Address,
    },
    SmartContractCreation {
        address: Address,
        init_code: Bytes,
    },
}

fn add_tx_type_data(tx_request: TransactionRequest, typed_transaction_data: TypedTransactionData) -> TransactionRequest {
    match typed_transaction_data {
        TypedTransactionData::Legacy { gas_price } => {
            let mut tx_request = tx_request
                .with_gas_price(gas_price);
            tx_request.max_fee_per_gas = None;
            tx_request.max_priority_fee_per_gas = None;
            tx_request
        }
        TypedTransactionData::Eip2930 { gas_price, access_list } => {
            let mut tx_request = tx_request
                .with_gas_price(gas_price)
                .with_access_list(access_list);
            tx_request.max_fee_per_gas = None;
            tx_request.max_priority_fee_per_gas = None;
            tx_request
        }
        TypedTransactionData::Eip1559 { access_list, max_fee_per_gas, max_priority_fee_per_gas } => {
            let mut tx_request = tx_request
                .with_access_list(access_list)
                .with_max_fee_per_gas(max_fee_per_gas)
                .with_max_priority_fee_per_gas(max_priority_fee_per_gas);
            tx_request.gas_price = None;
            tx_request
        }
        TypedTransactionData::Eip7702 { access_list, max_fee_per_gas, max_priority_fee_per_gas, authorization_list } => {
            let mut tx_request = tx_request
                .with_access_list(access_list)
                .with_max_fee_per_gas(max_fee_per_gas)
                .with_max_priority_fee_per_gas(max_priority_fee_per_gas)
                .with_authorization_list(authorization_list);
            tx_request.gas_price = None;
            tx_request
        }
    }
}

async fn prepare_tx(
    provider: &impl Provider,
    tx: Transaction
) -> Result<Option<TxData>> {
    let receipt = provider.get_transaction_receipt(tx.inner.hash().to_owned()).await?.ok_or_else(|| anyhow!("receipt must be found"))?;
    // TODO: can nonce affect EVM execution?
    let (gas_limit, tx_kind, value, input, typed_transaction_data) = match tx.clone().into_inner().into_typed_transaction() {
        EthereumTypedTransaction::Legacy(tx) => {
            (tx.gas_limit, tx.to, tx.value, tx.input, TypedTransactionData::Legacy {
                gas_price: tx.gas_price
            })
        }
        EthereumTypedTransaction::Eip2930(tx) => {
            (tx.gas_limit, tx.to, tx.value, tx.input, TypedTransactionData::Eip2930 { 
                gas_price: tx.gas_price,
                access_list: tx.access_list 
            })
        }
        EthereumTypedTransaction::Eip1559(tx) => {
            (tx.gas_limit, tx.to, tx.value, tx.input, TypedTransactionData::Eip1559 { 
                access_list: tx.access_list,
                max_fee_per_gas: tx.max_fee_per_gas, 
                max_priority_fee_per_gas: tx.max_priority_fee_per_gas 
            })
        }
        EthereumTypedTransaction::Eip7702(tx) => {
            (tx.gas_limit, TxKind::Call(tx.to), tx.value, tx.input, TypedTransactionData::Eip7702 {  
                authorization_list: tx.authorization_list,
                access_list: tx.access_list,
                max_fee_per_gas: tx.max_fee_per_gas,
                max_priority_fee_per_gas: tx.max_priority_fee_per_gas,
            })
        }
        _ => return Ok(None),
    };

    let tx_kind_data = match tx_kind {
        TxKind::Call(to) => {
            let code = provider.get_code_at(to).await?;
            if code.len() > 0 {
                TxKindData::SmartContract { to, code, calldata: input }
            } else {
                // not simulating calldata for EOA->EOA transfer
                // because it only affects gas consumption
                // technically it could result in some EOA address having more balance than it should
                // later down the block 
                // but this problem also exists for all calls to smart contracts that are GasKiller-ifeid
                TxKindData::Transfer { to }
            }
        },
        TxKind::Create => {
            let contract_address = receipt.contract_address.ok_or_else(|| anyhow!("contract address must be present"))?;
            TxKindData::SmartContractCreation { 
                address: contract_address, 
                init_code: input
            }
        }
    };

    Ok(Some(TxData { 
        tx: tx, 
        receipt: receipt, 
        gas_limit: gas_limit, 
        value: value, 
        typed_transaction_data: typed_transaction_data, 
        tx_kind_data: tx_kind_data 
    }))
}