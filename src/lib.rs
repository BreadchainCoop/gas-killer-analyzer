#[allow(dead_code)]
mod constants;
pub mod gk;
mod sol_types;

use std::str::FromStr;

use alloy::{
    primitives::{Address, Bytes, FixedBytes},
    providers::{Provider, ProviderBuilder, ext::DebugApi},
    rpc::types::{
        TransactionReceipt,
        eth::TransactionRequest,
        trace::geth::{
            DefaultFrame, GethDebugTracingOptions, GethDefaultTracingOptions, GethTrace, StructLog,
        },
    },
    sol_types::SolValue,
};
use alloy_eips::eip1898::BlockId;
use anyhow::{Result, bail};
use gk::{GasKillerDefault, WarmSlotsRule};
use sol_types::{IStateUpdateTypes, StateUpdate, StateUpdateType, StateUpdates};
use url::Url;

fn copy_memory(memory: &[u8], offset: usize, length: usize) -> Vec<u8> {
    if memory.len() >= offset + length {
        memory[offset..offset + length].to_vec()
    } else {
        let mut memory = memory.to_vec();
        memory.resize(offset + length, 0);
        memory[offset..offset + length].to_vec()
    }
}

fn parse_trace_memory(memory: Vec<String>) -> Vec<u8> {
    memory
        .join("")
        .chars()
        .collect::<Vec<char>>()
        .chunks(2)
        .map(|c| c.iter().collect::<String>())
        .map(|s| u8::from_str_radix(&s, 16).expect("invalid hex"))
        .collect::<Vec<u8>>()
}

fn append_to_state_updates(
    state_updates: &mut Vec<StateUpdate>,
    struct_log: StructLog,
) -> Result<()> {
    let mut stack = struct_log.stack.expect("stack is empty");
    stack.reverse();
    let memory = match struct_log.memory {
        Some(memory) => parse_trace_memory(memory),
        None => match struct_log.op.as_str() {
            "CALL" | "LOG0" | "LOG1" | "LOG2" | "LOG3" | "LOG4" if struct_log.depth == 1 => {
                bail!("There is no memory for {:?} in depth 1", struct_log.op)
            }
            _ => return Ok(()),
        },
    };
    match struct_log.op.as_str() {
        "DELEGATECALL" | "CALLCODE" | "CREATE" | "CREATE2" | "SELFDESTRUCT" => {
            bail!("Opcode not allowed: {:?}", struct_log.op)
        }
        "SSTORE" => state_updates.push(StateUpdate::Store(IStateUpdateTypes::Store {
            slot: stack[0].into(),
            value: stack[1].into(),
        })),
        "CALL" => {
            let args_offset: usize = stack[3].try_into().expect("invalid args offset");
            let args_length: usize = stack[4].try_into().expect("invalid args length");
            let args = copy_memory(&memory, args_offset, args_length);
            state_updates.push(StateUpdate::Call(IStateUpdateTypes::Call {
                target: Address::from_word(stack[1].into()),
                value: stack[2],
                callargs: args.into(),
            }));
        }
        "LOG0" => {
            let data_offset: usize = stack[0].try_into().expect("invalid data offset");
            let data_length: usize = stack[1].try_into().expect("invalid data length");
            let data = copy_memory(&memory, data_offset, data_length);
            state_updates.push(StateUpdate::Log0(IStateUpdateTypes::Log0 {
                data: data.into(),
            }));
        }
        "LOG1" => {
            let data_offset: usize = stack[0].try_into().expect("invalid data offset");
            let data_length: usize = stack[1].try_into().expect("invalid data length");
            let data = copy_memory(&memory, data_offset, data_length);
            state_updates.push(StateUpdate::Log1(IStateUpdateTypes::Log1 {
                data: data.into(),
                topic1: stack[2].into(),
            }));
        }
        "LOG2" => {
            let data_offset: usize = stack[0].try_into().expect("invalid data offset");
            let data_length: usize = stack[1].try_into().expect("invalid data length");
            let data = copy_memory(&memory, data_offset, data_length);
            state_updates.push(StateUpdate::Log2(IStateUpdateTypes::Log2 {
                data: data.into(),
                topic1: stack[2].into(),
                topic2: stack[3].into(),
            }));
        }
        "LOG3" => {
            let data_offset: usize = stack[0].try_into().expect("invalid data offset");
            let data_length: usize = stack[1].try_into().expect("invalid data length");
            let data = copy_memory(&memory, data_offset, data_length);
            state_updates.push(StateUpdate::Log3(IStateUpdateTypes::Log3 {
                data: data.into(),
                topic1: stack[2].into(),
                topic2: stack[3].into(),
                topic3: stack[4].into(),
            }));
        }
        "LOG4" => {
            let data_offset: usize = stack[0].try_into().expect("invalid data offset");
            let data_length: usize = stack[1].try_into().expect("invalid data length");
            let data = copy_memory(&memory, data_offset, data_length);
            state_updates.push(StateUpdate::Log4(IStateUpdateTypes::Log4 {
                data: data.into(),
                topic1: stack[2].into(),
                topic2: stack[3].into(),
                topic3: stack[4].into(),
                topic4: stack[5].into(),
            }));
        }
        _ => {}
    }
    Ok(())
}

async fn compute_state_updates(trace: DefaultFrame) -> Result<Vec<StateUpdate>> {
    let mut state_updates: Vec<StateUpdate> = Vec::new();
    // depth for which we care about state updates happening in
    let mut target_depth = 1;
    for struct_log in trace.struct_logs {
        // Whenever stepping up (leaving a CALL/CALLCODE/DELEGATECALL) reset the target depth
        if struct_log.depth < target_depth {
            target_depth = struct_log.depth;
        } else if struct_log.depth == target_depth {
            // If we're going to step into a new execution context, increase the target depth
            // else, try to add the state update
            if struct_log.op.as_str() == "DELEGATECALL" || struct_log.op.as_str() == "CALLCODE" {
                target_depth = struct_log.depth + 1;
            } else {
                append_to_state_updates(&mut state_updates, struct_log)?;
            }
        }
    }
    Ok(state_updates)
}

async fn compute_state_updates_block(trace: Vec<DefaultFrame>) -> Result<Vec<Vec<StateUpdate>>> {
    let mut state_updates: Vec<Vec<StateUpdate>> = Vec::new();
    for frame in trace {
        if let Ok(new_update) = compute_state_updates(frame).await {
            state_updates.push(new_update);
        }
    }
    Ok(state_updates)
}

async fn get_tx_trace<P: Provider>(provider: &P, tx_hash: FixedBytes<32>) -> Result<DefaultFrame> {
    let options = GethDebugTracingOptions {
        config: GethDefaultTracingOptions {
            enable_memory: Some(true),
            ..Default::default()
        },
        ..Default::default()
    };

    let GethTrace::Default(trace) = provider.debug_trace_transaction(tx_hash, options).await?
    else {
        return Err(anyhow::anyhow!("Expected default trace"));
    };
    Ok(trace)
}

async fn get_block_trace<P: Provider>(
    provider: &P,
    block_id: BlockId,
) -> Result<Vec<DefaultFrame>> {
    let block = provider
        .get_block(block_id)
        .await?
        .expect("block retrieval failed");

    let mut traces = Vec::new();

    for tx_hash in block.transactions.hashes() {
        println!("getting trace for transaction {:x}", tx_hash);
        let trace = get_tx_trace(provider, tx_hash).await?;
        traces.push(trace)
    }
    Ok(traces)
}

pub async fn get_trace_from_call(
    rpc_url: Url,
    tx_request: TransactionRequest,
) -> Result<DefaultFrame> {
    let provider = ProviderBuilder::new().connect_anvil_with_wallet_and_config(|config| {
        config
            .fork(rpc_url)
            .arg("--steps-tracing")
            .arg("--auto-impersonate")
    })?;
    let tx_hash = provider.send_transaction(tx_request).await?.watch().await?;
    get_tx_trace(&provider, tx_hash).await
}

fn encode_state_updates_to_sol(
    state_updates: &[StateUpdate],
) -> (Vec<StateUpdateType>, Vec<Bytes>) {
    let state_update_types: Vec<StateUpdateType> = state_updates
        .iter()
        .map(|state_update| match state_update {
            StateUpdate::Store(_) => StateUpdateType::STORE,
            StateUpdate::Call(_) => StateUpdateType::CALL,
            StateUpdate::Log0(_) => StateUpdateType::LOG0,
            StateUpdate::Log1(_) => StateUpdateType::LOG1,
            StateUpdate::Log2(_) => StateUpdateType::LOG2,
            StateUpdate::Log3(_) => StateUpdateType::LOG3,
            StateUpdate::Log4(_) => StateUpdateType::LOG4,
        })
        .collect::<Vec<_>>();
    // This is ugly but I can't bother doing it with traits
    let datas: Vec<Bytes> = state_updates
        .iter()
        .map(|state_update| {
            Bytes::copy_from_slice(&match state_update {
                StateUpdate::Store(x) => x.abi_encode(),
                StateUpdate::Call(x) => x.abi_encode(),
                StateUpdate::Log0(x) => x.abi_encode(),
                StateUpdate::Log1(x) => x.abi_encode(),
                StateUpdate::Log2(x) => x.abi_encode(),
                StateUpdate::Log3(x) => x.abi_encode(),
                StateUpdate::Log4(x) => x.abi_encode(),
            })
        })
        .collect::<Vec<_>>();
    (state_update_types, datas)
}

fn encode_state_updates_to_abi(state_updates: &[StateUpdate]) -> Bytes {
    let (state_update_types, datas) = encode_state_updates_to_sol(state_updates);
    let state_updates = StateUpdates {
        types: state_update_types
            .iter()
            .map(|x| *x as u8)
            .collect::<Vec<_>>(),
        data: datas,
    };
    let encoded = StateUpdates::abi_encode(&state_updates);
    Bytes::copy_from_slice(&encoded)
}

pub async fn tx_to_encoded_state_updates(
    provider: impl Provider,
    tx_hash: FixedBytes<32>,
) -> Result<Bytes> {
    let trace = get_tx_trace(&provider, tx_hash).await?;
    let state_updates = compute_state_updates(trace).await?;
    Ok(encode_state_updates_to_abi(&state_updates))
}
pub async fn tx_request_to_encoded_state_updates(
    url: Url,
    tx_request: TransactionRequest,
) -> Result<Bytes> {
    let trace = get_trace_from_call(url, tx_request).await?;
    let state_updates = compute_state_updates(trace).await?;
    Ok(encode_state_updates_to_abi(&state_updates))
}

pub async fn tx_to_encoded_state_updates_with_gas_estimate(
    provider: impl Provider,
    tx_hash: FixedBytes<32>,
    gk: GasKillerDefault,
) -> Result<(Bytes, u64)> {
    let trace = get_tx_trace(&provider, tx_hash).await?;
    let state_updates = compute_state_updates(trace).await?;
    let gas_estimate = gk
        .estimate_state_changes_gas(&state_updates, WarmSlotsRule::AllStore)
        .await?;
    Ok((encode_state_updates_to_abi(&state_updates), gas_estimate))
}

pub async fn invokes_smart_contract(
    provider: impl Provider,
    receipt: TransactionReceipt,
) -> Result<bool> {
    let to_address = receipt.to;
    match to_address {
        None => Ok(false),
        Some(address) => {
            let code = provider
                .get_code_at(address)
                .await
                .expect("couldn't fetch code");
            if code == Bytes::from_str("0x")? {
                Ok(false)
            } else {
                Ok(true)
            }
        }
    }
}

// computes state updates and estimates for each transaction one by one, nicer for CLI
pub async fn gas_estimate_block(
    provider: impl Provider,
    block_id: BlockId,
    gk: GasKillerDefault,
) -> Result<()> {
    let block = provider
        .get_block(block_id)
        .await?
        .expect("block retrieval failed");

    for tx_hash in block.transactions.hashes() {
        let receipt = provider
            .get_transaction_receipt(tx_hash)
            .await?
            .expect("fetch transaction receipt failed");
        let gas_used = receipt.gas_used;
        if let Ok(true) = invokes_smart_contract(&provider, receipt).await {
            println!("getting trace for transaction {:x}", tx_hash);
            let Ok(trace) = get_tx_trace(&provider, tx_hash).await else {
                continue;
            };
            let Ok(state_updates) = compute_state_updates(trace).await else {
                continue;
            };
            println!("computing gas killer estimate for transaction");
            let gas_estimate = gk
                .estimate_state_changes_gas(&state_updates, WarmSlotsRule::AllStore)
                .await?;
            println!(
                "actual gas used: {}, gas killer estimate: {}, percent savings: {:.2}",
                gas_used,
                gas_estimate,
                ((gas_used - gas_estimate) * 100) as f64 / gas_used as f64
            );
        } else {
            continue;
        }
    }
    Ok(())
}

pub async fn gas_estimate_tx(
    provider: impl Provider,
    tx_hash: FixedBytes<32>,
    gk: GasKillerDefault,
) -> Result<()> {
    let receipt = provider
        .get_transaction_receipt(tx_hash)
        .await?
        .expect("fetch transaction receipt failed");
    let gas_used = receipt.gas_used;
    if let Ok(true) = invokes_smart_contract(&provider, receipt).await {
        println!("analyzing transaction {:x}", tx_hash);
        let trace = get_tx_trace(&provider, tx_hash).await?;
        let state_updates = compute_state_updates(trace).await?;
        println!("computing gas killer estimate");
        let gas_estimate = gk
            .estimate_state_changes_gas(&state_updates, WarmSlotsRule::AllStore)
            .await?;
        println!(
            "actual gas used: {}, gas killer estimate: {}, percent savings: {:.2}",
            gas_used,
            gas_estimate,
            ((gas_used - gas_estimate) * 100) as f64 / gas_used as f64
        );
    } else {
        println!("transaction doesn't invoke a smart contract")
    }
    Ok(())
}

// fetches all transaction traces and then computes state updates and estimates
pub async fn tx_to_encoded_state_updates_with_gas_estimate_block(
    provider: impl Provider,
    block_id: BlockId,
    gk: GasKillerDefault,
) -> Result<(Vec<Bytes>, Vec<u64>)> {
    println!("getting traces for transactions in block...");
    let trace = get_block_trace(&provider, block_id).await?;
    println!("computing state updates for each transaction...");
    let state_updates = compute_state_updates_block(trace).await?;
    let mut gk_estimates = Vec::new();
    let mut encoded_state_updates = Vec::new();
    for updates in state_updates {
        println!("estimating gas for a transaction...");
        let gas_estimate = gk
            .estimate_state_changes_gas(&updates, WarmSlotsRule::AllStore)
            .await?;
        gk_estimates.push(gas_estimate);
        let encoded_updates = encode_state_updates_to_abi(&updates);
        encoded_state_updates.push(encoded_updates)
    }
    Ok((encoded_state_updates, gk_estimates))
}

pub async fn call_to_encoded_state_updates_with_gas_estimate(
    url: Url,
    tx_request: TransactionRequest,
    gk: GasKillerDefault,
) -> Result<(Bytes, u64)> {
    let trace = get_trace_from_call(url, tx_request).await?;
    let state_updates = compute_state_updates(trace).await?;
    let gas_estimate = gk
        .estimate_state_changes_gas(&state_updates, WarmSlotsRule::AllStore)
        .await?;
    Ok((encode_state_updates_to_abi(&state_updates), gas_estimate))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{U256, address, b256, bytes};
    use constants::*;
    use sol_types::SimpleStorage;

    #[tokio::test]
    async fn test_compute_state_updates_set() -> Result<()> {
        dotenv::dotenv().ok();

        let rpc_url = std::env::var("RPC_URL")
            .expect("RPC_URL must be set")
            .parse()?;
        let provider = ProviderBuilder::new().connect_http(rpc_url);

        let tx_hash = SIMPLE_STORAGE_SET_TX_HASH;
        let trace = get_tx_trace(&provider, tx_hash).await?;
        let state_updates = compute_state_updates(trace).await?;

        let gk = GasKillerDefault::new().await?;
        let gas_estimate = gk
            .estimate_state_changes_gas(&state_updates, WarmSlotsRule::AllStore)
            .await?;
        assert_eq!(gas_estimate, 32958);

        assert_eq!(state_updates.len(), 2);
        assert!(matches!(state_updates[0], StateUpdate::Store(_)));
        let StateUpdate::Store(store) = &state_updates[0] else {
            bail!("Expected Store");
        };

        assert_eq!(
            store.slot,
            b256!("0x0000000000000000000000000000000000000000000000000000000000000000")
        );
        assert_eq!(
            store.value,
            b256!("0x0000000000000000000000000000000000000000000000000000000000000001")
        );

        assert!(matches!(state_updates[1], StateUpdate::Log1(_)));
        let StateUpdate::Log1(log) = &state_updates[1] else {
            bail!("Expected Log1");
        };
        assert_eq!(
            log.data,
            bytes!("0x0000000000000000000000000000000000000000000000000000000000000001")
        );
        assert_eq!(
            log.topic1,
            b256!("0x9455957c3b77d1d4ed071e2b469dd77e37fc5dfd3b4d44dc8a997cc97c7b3d49")
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_compute_state_updates_deposit() -> Result<()> {
        dotenv::dotenv().ok();

        let rpc_url = std::env::var("RPC_URL")
            .expect("RPC_URL must be set")
            .parse()?;
        let provider = ProviderBuilder::new().connect_http(rpc_url);

        let tx_hash = SIMPLE_STORAGE_DEPOSIT_TX_HASH;
        let trace = get_tx_trace(&provider, tx_hash).await?;
        let state_updates = compute_state_updates(trace).await?;

        assert_eq!(state_updates.len(), 2);
        assert!(matches!(state_updates[0], StateUpdate::Store(_)));
        let StateUpdate::Store(store) = &state_updates[0] else {
            bail!("Expected Store");
        };

        assert_eq!(
            store.slot,
            b256!("0x440be2d9467c2219d5dbcccf352e669f171177c1a3ff408399184565c5a56cca")
        );
        assert_eq!(
            store.value,
            b256!("0x00000000000000000000000000000000000000000000000000005af3107a4000")
        );

        assert!(matches!(state_updates[1], StateUpdate::Log2(_)));
        let StateUpdate::Log2(log) = &state_updates[1] else {
            bail!("Expected Log2");
        };
        assert_eq!(
            log.data,
            bytes!("0x00000000000000000000000000000000000000000000000000005af3107a4000")
        );
        assert_eq!(
            log.topic1,
            b256!("0x8ad64a0ac7700dd8425ab0499f107cb6e2cd1581d803c5b8c1c79dcb8190b1af")
        );
        assert_eq!(
            log.topic2,
            b256!("0x000000000000000000000000cb7c611933f1697f6e56929f4eee39af8f5b313e")
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_compute_state_updates_delegatecall() -> Result<()> {
        dotenv::dotenv().ok();

        let rpc_url = std::env::var("RPC_URL")
            .expect("RPC_URL must be set")
            .parse()?;
        let provider = ProviderBuilder::new().connect_http(rpc_url);

        let tx_hash = DELEGATECALL_CONTRACT_MAIN_RUN_TX_HASH;
        let trace = get_tx_trace(&provider, tx_hash).await?;
        let state_updates = compute_state_updates(trace).await?;

        assert_eq!(state_updates.len(), 4);
        let StateUpdate::Store(IStateUpdateTypes::Store { slot, value }) = &state_updates[0] else {
            bail!("Expected Store, got {:?}", state_updates[0]);
        };
        assert_eq!(
            slot,
            &b256!("0x0000000000000000000000000000000000000000000000000000000000000003")
        );
        assert_eq!(
            value,
            &b256!("0x0000000000000000000000000000000000000000000000000000000000000001")
        );

        let StateUpdate::Call(IStateUpdateTypes::Call {
            target,
            value,
            callargs,
        }) = &state_updates[1]
        else {
            bail!("Expected Call, got {:?}", state_updates[1]);
        };
        assert_eq!(target, &DELEGATE_CONTRACT_A_ADDRESS);
        assert_eq!(value, &U256::from(0));
        assert_eq!(callargs, &bytes!("0xaea01afc"));

        let StateUpdate::Store(IStateUpdateTypes::Store { slot, value }) = &state_updates[2] else {
            bail!("Expected Store, got {:?}", state_updates[2]);
        };
        assert_eq!(
            slot,
            &b256!("0x0000000000000000000000000000000000000000000000000000000000000002")
        );
        assert_eq!(
            value,
            &b256!("0x0000000000000000000000000000000000000000000000000de0b6b3a7640000")
        ); // 1 ether (use cast to-dec)

        let StateUpdate::Store(IStateUpdateTypes::Store { slot, value }) = &state_updates[3] else {
            bail!("Expected Store, got {:?}", state_updates[3]);
        };
        assert_eq!(
            slot,
            &b256!("0x0000000000000000000000000000000000000000000000000000000000000002")
        );
        assert_eq!(
            value,
            &b256!("0x00000000000000000000000000000000000000000000000029a2241af62c0000")
        ); // 3 ether (use cast to-dec)

        Ok(())
    }

    #[tokio::test]
    async fn test_compute_state_updates_call_external() -> Result<()> {
        dotenv::dotenv().ok();

        let rpc_url = std::env::var("RPC_URL")
            .expect("RPC_URL must be set")
            .parse()?;
        let provider = ProviderBuilder::new().connect_http(rpc_url);

        let tx_hash = SIMPLE_STORAGE_CALL_EXTERNAL_TX_HASH;
        let trace = get_tx_trace(&provider, tx_hash).await?;
        let state_updates = compute_state_updates(trace).await?;

        assert_eq!(state_updates.len(), 1);
        assert!(matches!(state_updates[0], StateUpdate::Call(_)));
        let StateUpdate::Call(call) = &state_updates[0] else {
            bail!("Expected Call");
        };

        assert_eq!(
            call.target,
            address!("0x523a103bb468a26295d7dbcb37ad919b0afbf294")
        );
        assert_eq!(call.value, U256::from(0));
        assert_eq!(call.callargs, bytes!("0x3a32b549"));

        Ok(())
    }

    #[tokio::test]
    async fn test_compute_state_update_simulate_call() -> Result<()> {
        dotenv::dotenv().ok();

        let rpc_url: Url = std::env::var("RPC_URL")
            .expect("RPC_URL must be set")
            .parse()?;

        let provider = ProviderBuilder::new().connect_http(rpc_url.clone());

        let simple_storage =
            SimpleStorage::SimpleStorageInstance::new(SIMPLE_STORAGE_ADDRESS, &provider);
        let tx_request = simple_storage.set(U256::from(1)).into_transaction_request();

        let trace = get_trace_from_call(rpc_url, tx_request).await?;
        let state_updates = compute_state_updates(trace).await?;

        assert_eq!(state_updates.len(), 2);
        assert!(matches!(state_updates[0], StateUpdate::Store(_)));
        let StateUpdate::Store(store) = &state_updates[0] else {
            bail!("Expected Store");
        };

        assert_eq!(
            store.slot,
            b256!("0x0000000000000000000000000000000000000000000000000000000000000000")
        );
        assert_eq!(
            store.value,
            b256!("0x0000000000000000000000000000000000000000000000000000000000000001")
        );

        assert!(matches!(state_updates[1], StateUpdate::Log1(_)));
        let StateUpdate::Log1(log) = &state_updates[1] else {
            bail!("Expected Log1");
        };
        assert_eq!(
            log.data,
            bytes!("0x0000000000000000000000000000000000000000000000000000000000000001")
        );
        assert_eq!(
            log.topic1,
            b256!("0x9455957c3b77d1d4ed071e2b469dd77e37fc5dfd3b4d44dc8a997cc97c7b3d49")
        );
        Ok(())
    }
}
