pub mod commands;
// pub mod gk;
pub mod sol_types;
pub mod structs;

use std::{collections::HashSet, str::FromStr};
use structs::Opcode;

use alloy::{
    primitives::{Address, Bytes, FixedBytes, TxKind},
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

use anyhow::{Result, bail};
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

pub fn append_to_state_updates(
    state_updates: &mut Vec<StateUpdate>,
    struct_log: StructLog,
) -> Result<Option<Opcode>> {
    let mut stack = struct_log.stack.expect("stack is empty");
    stack.reverse();
    let memory = match struct_log.memory {
        Some(memory) => parse_trace_memory(memory),
        None => match struct_log.op.as_str() {
            "CALL" | "LOG0" | "LOG1" | "LOG2" | "LOG3" | "LOG4" if struct_log.depth == 1 => {
                bail!("There is no memory for {:?} in depth 1", struct_log.op)
            }
            _ => return Ok(None),
        },
    };
    match struct_log.op.as_str() {
        "CREATE" | "CREATE2" | "SELFDESTRUCT" => {
            return Ok(Some(struct_log.op));
        }
        "DELEGATECALL" | "CALLCODE" => {
            bail!(
                "Calling opcode {:?}, this shouldn't even happen!",
                struct_log.op
            );
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
    Ok(None)
}

pub async fn compute_state_updates(
    trace: DefaultFrame,
) -> Result<(Vec<StateUpdate>, HashSet<Opcode>)> {
    let mut state_updates: Vec<StateUpdate> = Vec::new();
    // depth for which we care about state updates happening in
    let mut target_depth = 1;
    let mut skipped_opcodes = HashSet::new();
    for struct_log in trace.struct_logs {
        // Whenever stepping up (leaving a CALL/CALLCODE/DELEGATECALL) reset the target depth
        if struct_log.depth < target_depth {
            target_depth = struct_log.depth;
        } else if struct_log.depth == target_depth {
            // If we're going to step into a new execution context, increase the target depth
            // else, try to add the state update
            if struct_log.op.as_str() == "DELEGATECALL" || struct_log.op.as_str() == "CALLCODE" {
                target_depth = struct_log.depth + 1;
            } else if let Some(opcode) = append_to_state_updates(&mut state_updates, struct_log)? {
                skipped_opcodes.insert(opcode);
            }
        }
    }
    Ok((state_updates, skipped_opcodes))
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
    let tx_receipt = provider
        .send_transaction(tx_request)
        .await?
        .get_receipt()
        .await?;
    if !tx_receipt.status() {
        bail!("transaction failed");
    }
    let tx_hash = tx_receipt.transaction_hash;
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
                StateUpdate::Store(x) => x.abi_encode_sequence(),
                StateUpdate::Call(x) => x.abi_encode_sequence(),
                StateUpdate::Log0(x) => x.abi_encode_sequence(),
                StateUpdate::Log1(x) => x.abi_encode_sequence(),
                StateUpdate::Log2(x) => x.abi_encode_sequence(),
                StateUpdate::Log3(x) => x.abi_encode_sequence(),
                StateUpdate::Log4(x) => x.abi_encode_sequence(),
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

pub async fn invokes_smart_contract(
    provider: impl Provider,
    receipt: &TransactionReceipt,
) -> Result<bool> {
    let to_address = receipt.to;
    match to_address {
        None => Ok(false),
        Some(address) => {
            let code = provider.get_code_at(address).await?;
            if code == Bytes::from_str("0x")? {
                Ok(false)
            } else {
                Ok(true)
            }
        }
    }
}
