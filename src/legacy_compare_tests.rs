//! Legacy implementation comparison tests.
//!
//! This module contains the original (legacy) state update computation implementation
//! and tests that verify the new opcode-tracer based implementation produces identical
//! results for all test cases.

use alloy::{
    primitives::Address,
    rpc::types::trace::geth::{DefaultFrame, StructLog},
};
use anyhow::{Result, bail};
use std::collections::HashSet;

use crate::parse_trace_memory;
use crate::sol_types::{IStateUpdateTypes, StateUpdate};
use crate::structs::Opcode;

/// Copy memory with bounds checking (legacy helper).
fn copy_memory_legacy(memory: &[u8], offset: usize, length: usize) -> Vec<u8> {
    if memory.len() >= offset + length {
        memory[offset..offset + length].to_vec()
    } else {
        let mut memory = memory.to_vec();
        memory.resize(offset + length, 0);
        memory[offset..offset + length].to_vec()
    }
}

/// Legacy implementation: append state update from a struct log.
fn append_to_state_updates_legacy(
    state_updates: &mut Vec<StateUpdate>,
    struct_log: StructLog,
) -> Result<Option<Opcode>> {
    let mut stack = struct_log.stack.expect("stack is empty");
    stack.reverse();
    let memory = match struct_log.memory {
        Some(memory) => parse_trace_memory(memory),
        None => match struct_log.op.as_ref() {
            "CALL" | "LOG0" | "LOG1" | "LOG2" | "LOG3" | "LOG4" if struct_log.depth == 1 => {
                bail!("There is no memory for {:?} in depth 1", struct_log.op)
            }
            _ => return Ok(None),
        },
    };
    match struct_log.op.as_ref() {
        "CREATE" | "CREATE2" | "SELFDESTRUCT" => {
            return Ok(Some(struct_log.op.to_string()));
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
            let args = copy_memory_legacy(&memory, args_offset, args_length);
            state_updates.push(StateUpdate::Call(IStateUpdateTypes::Call {
                target: Address::from_word(stack[1].into()),
                value: stack[2],
                callargs: args.into(),
            }));
        }
        "LOG0" => {
            let data_offset: usize = stack[0].try_into().expect("invalid data offset");
            let data_length: usize = stack[1].try_into().expect("invalid data length");
            let data = copy_memory_legacy(&memory, data_offset, data_length);
            state_updates.push(StateUpdate::Log0(IStateUpdateTypes::Log0 {
                data: data.into(),
            }));
        }
        "LOG1" => {
            let data_offset: usize = stack[0].try_into().expect("invalid data offset");
            let data_length: usize = stack[1].try_into().expect("invalid data length");
            let data = copy_memory_legacy(&memory, data_offset, data_length);
            state_updates.push(StateUpdate::Log1(IStateUpdateTypes::Log1 {
                data: data.into(),
                topic1: stack[2].into(),
            }));
        }
        "LOG2" => {
            let data_offset: usize = stack[0].try_into().expect("invalid data offset");
            let data_length: usize = stack[1].try_into().expect("invalid data length");
            let data = copy_memory_legacy(&memory, data_offset, data_length);
            state_updates.push(StateUpdate::Log2(IStateUpdateTypes::Log2 {
                data: data.into(),
                topic1: stack[2].into(),
                topic2: stack[3].into(),
            }));
        }
        "LOG3" => {
            let data_offset: usize = stack[0].try_into().expect("invalid data offset");
            let data_length: usize = stack[1].try_into().expect("invalid data length");
            let data = copy_memory_legacy(&memory, data_offset, data_length);
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
            let data = copy_memory_legacy(&memory, data_offset, data_length);
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

/// Legacy implementation: compute state updates from a Geth trace.
/// This is the original implementation before the opcode-tracer refactor.
pub fn compute_state_updates_legacy(
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
            if &*struct_log.op == "DELEGATECALL" || &*struct_log.op == "CALLCODE" {
                target_depth = struct_log.depth + 1;
            } else if let Some(opcode) =
                append_to_state_updates_legacy(&mut state_updates, struct_log)?
            {
                skipped_opcodes.insert(opcode);
            }
        }
    }
    Ok((state_updates, skipped_opcodes))
}

/// Compare two state update vectors for equality.
fn compare_state_updates(legacy: &[StateUpdate], new: &[StateUpdate]) -> Result<()> {
    if legacy.len() != new.len() {
        bail!(
            "Length mismatch: legacy has {} updates, new has {}",
            legacy.len(),
            new.len()
        );
    }

    for (i, (l, n)) in legacy.iter().zip(new.iter()).enumerate() {
        match (l, n) {
            (StateUpdate::Store(lg), StateUpdate::Store(nw)) => {
                if lg.slot != nw.slot {
                    bail!(
                        "Store slot mismatch at index {}: {:?} vs {:?}",
                        i,
                        lg.slot,
                        nw.slot
                    );
                }
                if lg.value != nw.value {
                    bail!(
                        "Store value mismatch at index {}: {:?} vs {:?}",
                        i,
                        lg.value,
                        nw.value
                    );
                }
            }
            (StateUpdate::Call(lg), StateUpdate::Call(nw)) => {
                if lg.target != nw.target {
                    bail!(
                        "Call target mismatch at index {}: {:?} vs {:?}",
                        i,
                        lg.target,
                        nw.target
                    );
                }
                if lg.value != nw.value {
                    bail!(
                        "Call value mismatch at index {}: {:?} vs {:?}",
                        i,
                        lg.value,
                        nw.value
                    );
                }
                if lg.callargs != nw.callargs {
                    bail!(
                        "Call args mismatch at index {}: {:?} vs {:?}",
                        i,
                        lg.callargs,
                        nw.callargs
                    );
                }
            }
            (StateUpdate::Log0(lg), StateUpdate::Log0(nw)) => {
                if lg.data != nw.data {
                    bail!(
                        "Log0 data mismatch at index {}: {:?} vs {:?}",
                        i,
                        lg.data,
                        nw.data
                    );
                }
            }
            (StateUpdate::Log1(lg), StateUpdate::Log1(nw)) => {
                if lg.data != nw.data {
                    bail!("Log1 data mismatch at index {}", i);
                }
                if lg.topic1 != nw.topic1 {
                    bail!("Log1 topic1 mismatch at index {}", i);
                }
            }
            (StateUpdate::Log2(lg), StateUpdate::Log2(nw)) => {
                if lg.data != nw.data {
                    bail!("Log2 data mismatch at index {}", i);
                }
                if lg.topic1 != nw.topic1 {
                    bail!("Log2 topic1 mismatch at index {}", i);
                }
                if lg.topic2 != nw.topic2 {
                    bail!("Log2 topic2 mismatch at index {}", i);
                }
            }
            (StateUpdate::Log3(lg), StateUpdate::Log3(nw)) => {
                if lg.data != nw.data {
                    bail!("Log3 data mismatch at index {}", i);
                }
                if lg.topic1 != nw.topic1 {
                    bail!("Log3 topic1 mismatch at index {}", i);
                }
                if lg.topic2 != nw.topic2 {
                    bail!("Log3 topic2 mismatch at index {}", i);
                }
                if lg.topic3 != nw.topic3 {
                    bail!("Log3 topic3 mismatch at index {}", i);
                }
            }
            (StateUpdate::Log4(lg), StateUpdate::Log4(nw)) => {
                if lg.data != nw.data {
                    bail!("Log4 data mismatch at index {}", i);
                }
                if lg.topic1 != nw.topic1 {
                    bail!("Log4 topic1 mismatch at index {}", i);
                }
                if lg.topic2 != nw.topic2 {
                    bail!("Log4 topic2 mismatch at index {}", i);
                }
                if lg.topic3 != nw.topic3 {
                    bail!("Log4 topic3 mismatch at index {}", i);
                }
                if lg.topic4 != nw.topic4 {
                    bail!("Log4 topic4 mismatch at index {}", i);
                }
            }
            _ => {
                bail!(
                    "State update type mismatch at index {}: {:?} vs {:?}",
                    i,
                    std::mem::discriminant(l),
                    std::mem::discriminant(n)
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::*;
    use crate::sol_types::SimpleStorage;
    use crate::{compute_state_updates, get_trace_from_call, get_tx_trace};
    use alloy::primitives::U256;
    use alloy::providers::ProviderBuilder;
    use url::Url;

    /// Test comparing legacy vs new implementation for SimpleStorage SET transaction.
    #[tokio::test]
    #[ignore = "requires RPC_URL with pre-deployed test contracts"]
    async fn test_compare_simple_storage_set() -> Result<()> {
        dotenv::dotenv().ok();

        let rpc_url = std::env::var("RPC_URL")
            .expect("RPC_URL must be set")
            .parse()?;
        let provider = ProviderBuilder::new().connect_http(rpc_url);

        let tx_hash = SIMPLE_STORAGE_SET_TX_HASH;
        let trace = get_tx_trace(&provider, tx_hash).await?;

        // Run legacy implementation
        let (legacy_updates, legacy_skipped) = compute_state_updates_legacy(trace.clone())?;

        // Run new implementation
        let (new_updates, new_skipped) = compute_state_updates(trace)?;

        // Compare results
        compare_state_updates(&legacy_updates, &new_updates)?;
        assert_eq!(legacy_skipped, new_skipped, "Skipped opcodes mismatch");

        println!(
            "SUCCESS: SimpleStorage SET - both implementations produced {} identical state updates",
            legacy_updates.len()
        );

        Ok(())
    }

    /// Test comparing legacy vs new implementation for SimpleStorage DEPOSIT transaction.
    #[tokio::test]
    #[ignore = "requires RPC_URL with pre-deployed test contracts"]
    async fn test_compare_simple_storage_deposit() -> Result<()> {
        dotenv::dotenv().ok();

        let rpc_url = std::env::var("RPC_URL")
            .expect("RPC_URL must be set")
            .parse()?;
        let provider = ProviderBuilder::new().connect_http(rpc_url);

        let tx_hash = SIMPLE_STORAGE_DEPOSIT_TX_HASH;
        let trace = get_tx_trace(&provider, tx_hash).await?;

        // Run legacy implementation
        let (legacy_updates, legacy_skipped) = compute_state_updates_legacy(trace.clone())?;

        // Run new implementation
        let (new_updates, new_skipped) = compute_state_updates(trace)?;

        // Compare results
        compare_state_updates(&legacy_updates, &new_updates)?;
        assert_eq!(legacy_skipped, new_skipped, "Skipped opcodes mismatch");

        println!(
            "SUCCESS: SimpleStorage DEPOSIT - both implementations produced {} identical state updates",
            legacy_updates.len()
        );

        Ok(())
    }

    /// Test comparing legacy vs new implementation for DELEGATECALL transaction.
    #[tokio::test]
    #[ignore = "requires RPC_URL with pre-deployed test contracts"]
    async fn test_compare_delegatecall() -> Result<()> {
        dotenv::dotenv().ok();

        let rpc_url = std::env::var("RPC_URL")
            .expect("RPC_URL must be set")
            .parse()?;
        let provider = ProviderBuilder::new().connect_http(rpc_url);

        let tx_hash = DELEGATECALL_CONTRACT_MAIN_RUN_TX_HASH;
        let trace = get_tx_trace(&provider, tx_hash).await?;

        // Run legacy implementation
        let (legacy_updates, legacy_skipped) = compute_state_updates_legacy(trace.clone())?;

        // Run new implementation
        let (new_updates, new_skipped) = compute_state_updates(trace)?;

        // Compare results
        compare_state_updates(&legacy_updates, &new_updates)?;
        assert_eq!(legacy_skipped, new_skipped, "Skipped opcodes mismatch");

        println!(
            "SUCCESS: DELEGATECALL - both implementations produced {} identical state updates",
            legacy_updates.len()
        );

        Ok(())
    }

    /// Test comparing legacy vs new implementation for CALL external transaction.
    #[tokio::test]
    #[ignore = "requires RPC_URL with pre-deployed test contracts"]
    async fn test_compare_call_external() -> Result<()> {
        dotenv::dotenv().ok();

        let rpc_url = std::env::var("RPC_URL")
            .expect("RPC_URL must be set")
            .parse()?;
        let provider = ProviderBuilder::new().connect_http(rpc_url);

        let tx_hash = SIMPLE_STORAGE_CALL_EXTERNAL_TX_HASH;
        let trace = get_tx_trace(&provider, tx_hash).await?;

        // Run legacy implementation
        let (legacy_updates, legacy_skipped) = compute_state_updates_legacy(trace.clone())?;

        // Run new implementation
        let (new_updates, new_skipped) = compute_state_updates(trace)?;

        // Compare results
        compare_state_updates(&legacy_updates, &new_updates)?;
        assert_eq!(legacy_skipped, new_skipped, "Skipped opcodes mismatch");

        println!(
            "SUCCESS: CALL external - both implementations produced {} identical state updates",
            legacy_updates.len()
        );

        Ok(())
    }

    /// Test comparing legacy vs new implementation for simulated call.
    #[tokio::test]
    #[ignore = "requires RPC_URL with pre-deployed test contracts"]
    async fn test_compare_simulate_call() -> Result<()> {
        dotenv::dotenv().ok();

        let rpc_url: Url = std::env::var("RPC_URL")
            .expect("RPC_URL must be set")
            .parse()?;

        let provider = ProviderBuilder::new().connect_http(rpc_url.clone());

        let simple_storage =
            SimpleStorage::SimpleStorageInstance::new(SIMPLE_STORAGE_ADDRESS, &provider);
        let tx_request = simple_storage.set(U256::from(1)).into_transaction_request();

        let trace = get_trace_from_call(rpc_url, tx_request).await?;

        // Run legacy implementation
        let (legacy_updates, legacy_skipped) = compute_state_updates_legacy(trace.clone())?;

        // Run new implementation
        let (new_updates, new_skipped) = compute_state_updates(trace)?;

        // Compare results
        compare_state_updates(&legacy_updates, &new_updates)?;
        assert_eq!(legacy_skipped, new_skipped, "Skipped opcodes mismatch");

        println!(
            "SUCCESS: Simulate call - both implementations produced {} identical state updates",
            legacy_updates.len()
        );

        Ok(())
    }

    /// Test comparing legacy vs new implementation for AccessControl transaction.
    #[tokio::test]
    #[ignore = "requires RPC_URL with pre-deployed test contracts"]
    async fn test_compare_access_control() -> Result<()> {
        dotenv::dotenv().ok();

        let rpc_url = std::env::var("RPC_URL")
            .expect("RPC_URL must be set")
            .parse()?;
        let provider = ProviderBuilder::new().connect_http(rpc_url);

        let tx_hash = ACCESS_CONTROL_MAIN_RUN_TX_HASH;
        let trace = get_tx_trace(&provider, tx_hash).await?;

        // Run legacy implementation
        let (legacy_updates, legacy_skipped) = compute_state_updates_legacy(trace.clone())?;

        // Run new implementation
        let (new_updates, new_skipped) = compute_state_updates(trace)?;

        // Compare results
        compare_state_updates(&legacy_updates, &new_updates)?;
        assert_eq!(legacy_skipped, new_skipped, "Skipped opcodes mismatch");

        println!(
            "SUCCESS: AccessControl - both implementations produced {} identical state updates",
            legacy_updates.len()
        );

        Ok(())
    }
}
