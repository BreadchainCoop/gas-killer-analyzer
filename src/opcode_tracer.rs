//! Opcode Tracer Integration Module
//!
//! This module integrates the opcode-tracer crate from sp1-contract-call
//! and provides utilities to compare state updates from both the Geth trace
//! approach and the opcode tracer approach.

use alloy::{
    primitives::Address,
    rpc::types::trace::geth::DefaultFrame,
};
use anyhow::{bail, Result};
use std::collections::HashSet;

use crate::sol_types::{IStateUpdateTypes, StateUpdate};
use crate::structs::Opcode;

// Re-export the opcode-tracer crate types for external use
pub use opcode_tracer::{
    trace_call, trace_function, CallTraceArena, CallTraceNode, CallTraceStep, OpcodeExecution,
    StorageChange, TraceConfig, TraceResult,
};

/// Compute state updates from an opcode-tracer TraceResult.
/// This processes the trace in the same way as `compute_state_updates` does for Geth traces.
pub fn compute_state_updates_from_trace(
    trace: &TraceResult,
) -> Result<(Vec<StateUpdate>, HashSet<Opcode>)> {
    let mut state_updates: Vec<StateUpdate> = Vec::new();
    let mut target_depth: usize = 1;
    let mut skipped_opcodes = HashSet::new();

    for step in &trace.opcodes {
        let depth = step.depth;

        // Whenever stepping up (leaving a CALL/CALLCODE/DELEGATECALL) reset the target depth
        if depth < target_depth {
            target_depth = depth;
        } else if depth == target_depth {
            // If we're going to step into a new execution context, increase the target depth
            // else, try to add the state update
            if step.name == "DELEGATECALL" || step.name == "CALLCODE" {
                target_depth = depth + 1;
            } else if let Some(opcode) =
                append_state_update_from_step(&mut state_updates, step)?
            {
                skipped_opcodes.insert(opcode);
            }
        }
    }

    Ok((state_updates, skipped_opcodes))
}

/// Copy memory with bounds checking.
fn copy_memory(memory: &[u8], offset: usize, length: usize) -> Vec<u8> {
    if memory.len() >= offset + length {
        memory[offset..offset + length].to_vec()
    } else {
        let mut result = memory.to_vec();
        result.resize(offset + length, 0);
        result[offset..offset + length].to_vec()
    }
}

/// Append a state update from an opcode execution step.
fn append_state_update_from_step(
    state_updates: &mut Vec<StateUpdate>,
    step: &OpcodeExecution,
) -> Result<Option<Opcode>> {
    let stack = &step.stack;
    let memory = &step.memory;
    let depth = step.depth;

    match step.name.as_str() {
        "CREATE" | "CREATE2" | "SELFDESTRUCT" => {
            return Ok(Some(step.name.clone()));
        }
        "DELEGATECALL" | "CALLCODE" => {
            bail!(
                "Calling opcode {:?}, this shouldn't even happen!",
                step.name
            );
        }
        "SSTORE" => {
            if stack.len() >= 2 {
                state_updates.push(StateUpdate::Store(IStateUpdateTypes::Store {
                    slot: stack[0].into(),
                    value: stack[1].into(),
                }));
            }
        }
        "CALL" => {
            if stack.len() >= 5 && depth == 1 {
                let args_offset: usize = stack[3].try_into().unwrap_or(0);
                let args_length: usize = stack[4].try_into().unwrap_or(0);
                let args = copy_memory(memory, args_offset, args_length);
                state_updates.push(StateUpdate::Call(IStateUpdateTypes::Call {
                    target: Address::from_word(stack[1].into()),
                    value: stack[2],
                    callargs: args.into(),
                }));
            }
        }
        "LOG0" => {
            if stack.len() >= 2 && depth == 1 {
                let data_offset: usize = stack[0].try_into().unwrap_or(0);
                let data_length: usize = stack[1].try_into().unwrap_or(0);
                let data = copy_memory(memory, data_offset, data_length);
                state_updates.push(StateUpdate::Log0(IStateUpdateTypes::Log0 {
                    data: data.into(),
                }));
            }
        }
        "LOG1" => {
            if stack.len() >= 3 && depth == 1 {
                let data_offset: usize = stack[0].try_into().unwrap_or(0);
                let data_length: usize = stack[1].try_into().unwrap_or(0);
                let data = copy_memory(memory, data_offset, data_length);
                state_updates.push(StateUpdate::Log1(IStateUpdateTypes::Log1 {
                    data: data.into(),
                    topic1: stack[2].into(),
                }));
            }
        }
        "LOG2" => {
            if stack.len() >= 4 && depth == 1 {
                let data_offset: usize = stack[0].try_into().unwrap_or(0);
                let data_length: usize = stack[1].try_into().unwrap_or(0);
                let data = copy_memory(memory, data_offset, data_length);
                state_updates.push(StateUpdate::Log2(IStateUpdateTypes::Log2 {
                    data: data.into(),
                    topic1: stack[2].into(),
                    topic2: stack[3].into(),
                }));
            }
        }
        "LOG3" => {
            if stack.len() >= 5 && depth == 1 {
                let data_offset: usize = stack[0].try_into().unwrap_or(0);
                let data_length: usize = stack[1].try_into().unwrap_or(0);
                let data = copy_memory(memory, data_offset, data_length);
                state_updates.push(StateUpdate::Log3(IStateUpdateTypes::Log3 {
                    data: data.into(),
                    topic1: stack[2].into(),
                    topic2: stack[3].into(),
                    topic3: stack[4].into(),
                }));
            }
        }
        "LOG4" => {
            if stack.len() >= 6 && depth == 1 {
                let data_offset: usize = stack[0].try_into().unwrap_or(0);
                let data_length: usize = stack[1].try_into().unwrap_or(0);
                let data = copy_memory(memory, data_offset, data_length);
                state_updates.push(StateUpdate::Log4(IStateUpdateTypes::Log4 {
                    data: data.into(),
                    topic1: stack[2].into(),
                    topic2: stack[3].into(),
                    topic3: stack[4].into(),
                    topic4: stack[5].into(),
                }));
            }
        }
        _ => {}
    }

    Ok(None)
}

/// Convert a Geth DefaultFrame trace to the opcode-tracer TraceResult format.
/// This allows us to use the same state update extraction logic for both
/// Geth traces and opcode-tracer traces.
pub fn convert_geth_trace_to_result(trace: &DefaultFrame) -> TraceResult {
    let mut opcodes = Vec::new();

    for struct_log in &trace.struct_logs {
        let stack = struct_log
            .stack
            .as_ref()
            .map(|s| {
                // In Geth traces, stack is already in natural order (bottom to top)
                // We need to reverse it so index 0 is top of stack
                s.iter().rev().copied().collect()
            })
            .unwrap_or_default();

        let memory = struct_log
            .memory
            .as_ref()
            .map(|m| crate::parse_trace_memory(m.clone()))
            .unwrap_or_default();

        opcodes.push(OpcodeExecution {
            pc: struct_log.pc as usize,
            opcode: 0, // Geth traces don't provide raw opcode byte
            name: struct_log.op.to_string(),
            gas_remaining: struct_log.gas,
            gas_cost: struct_log.gas_cost,
            depth: struct_log.depth as usize,
            stack,
            memory,
            storage_change: None, // Geth traces don't provide storage changes directly
        });
    }

    TraceResult {
        opcodes,
        call_frames: 1, // DefaultFrame doesn't track call frames
        total_gas_used: trace.gas,
        output: trace.return_value.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{b256, bytes, U256};

    #[test]
    fn test_compute_state_updates_from_trace_sstore() {
        // Create a simple trace with an SSTORE operation
        let trace = TraceResult {
            opcodes: vec![OpcodeExecution {
                pc: 0,
                opcode: 0x55, // SSTORE
                name: "SSTORE".to_string(),
                gas_remaining: 1000000,
                gas_cost: 20000,
                depth: 1,
                stack: vec![
                    U256::from(0), // slot
                    U256::from(1), // value
                ],
                memory: vec![],
                storage_change: Some(StorageChange {
                    slot: U256::from(0),
                    old_value: U256::ZERO,
                    new_value: U256::from(1),
                }),
            }],
            call_frames: 1,
            total_gas_used: 20000,
            output: vec![],
        };

        let (state_updates, skipped) = compute_state_updates_from_trace(&trace).unwrap();

        assert_eq!(state_updates.len(), 1);
        assert!(skipped.is_empty());

        match &state_updates[0] {
            StateUpdate::Store(store) => {
                assert_eq!(
                    store.slot,
                    b256!("0x0000000000000000000000000000000000000000000000000000000000000000")
                );
                assert_eq!(
                    store.value,
                    b256!("0x0000000000000000000000000000000000000000000000000000000000000001")
                );
            }
            _ => panic!("Expected Store state update"),
        }
    }

    #[test]
    fn test_compute_state_updates_from_trace_log1() {
        // Create a trace with a LOG1 operation
        let topic = U256::from_be_bytes(
            b256!("0x9455957c3b77d1d4ed071e2b469dd77e37fc5dfd3b4d44dc8a997cc97c7b3d49").0,
        );

        let trace = TraceResult {
            opcodes: vec![OpcodeExecution {
                pc: 0,
                opcode: 0xa1, // LOG1
                name: "LOG1".to_string(),
                gas_remaining: 1000000,
                gas_cost: 1000,
                depth: 1,
                stack: vec![
                    U256::from(0),  // data offset
                    U256::from(32), // data length
                    topic,          // topic1
                ],
                memory: vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 1,
                ],
                storage_change: None,
            }],
            call_frames: 1,
            total_gas_used: 1000,
            output: vec![],
        };

        let (state_updates, _) = compute_state_updates_from_trace(&trace).unwrap();

        assert_eq!(state_updates.len(), 1);

        match &state_updates[0] {
            StateUpdate::Log1(log) => {
                assert_eq!(
                    log.data,
                    bytes!("0x0000000000000000000000000000000000000000000000000000000000000001")
                );
                assert_eq!(
                    log.topic1,
                    b256!("0x9455957c3b77d1d4ed071e2b469dd77e37fc5dfd3b4d44dc8a997cc97c7b3d49")
                );
            }
            _ => panic!("Expected Log1 state update"),
        }
    }

    #[test]
    fn test_skips_delegatecall_depth() {
        // Create a trace where we step into DELEGATECALL context
        let trace = TraceResult {
            opcodes: vec![
                OpcodeExecution {
                    pc: 0,
                    opcode: 0xf4, // DELEGATECALL
                    name: "DELEGATECALL".to_string(),
                    gas_remaining: 1000000,
                    gas_cost: 100,
                    depth: 1,
                    stack: vec![],
                    memory: vec![],
                    storage_change: None,
                },
                OpcodeExecution {
                    pc: 0,
                    opcode: 0x55, // SSTORE inside DELEGATECALL
                    name: "SSTORE".to_string(),
                    gas_remaining: 900000,
                    gas_cost: 20000,
                    depth: 2, // Inside delegatecall
                    stack: vec![U256::from(0), U256::from(42)],
                    memory: vec![],
                    storage_change: Some(StorageChange {
                        slot: U256::from(0),
                        old_value: U256::ZERO,
                        new_value: U256::from(42),
                    }),
                },
            ],
            call_frames: 2,
            total_gas_used: 20100,
            output: vec![],
        };

        let (state_updates, _) = compute_state_updates_from_trace(&trace).unwrap();

        // The SSTORE inside DELEGATECALL should be captured because we increased target_depth
        assert_eq!(state_updates.len(), 1);

        match &state_updates[0] {
            StateUpdate::Store(store) => {
                assert_eq!(
                    store.value,
                    b256!("0x000000000000000000000000000000000000000000000000000000000000002a")
                );
            }
            _ => panic!("Expected Store state update"),
        }
    }
}
