use crate::memory::{extract_bytes, parse_trace_memory};
use crate::types::{IStateUpdateTypes, StateUpdate};
use alloy_primitives::{Address, FixedBytes};
use alloy_rpc_types::trace::geth::{DefaultFrame, StructLog};
use anyhow::Result;
use tracing::{debug, warn};

pub struct StateUpdateParser {
    current_depth: u64,
    skipped_opcodes: Vec<String>,
}

impl StateUpdateParser {
    pub fn new() -> Self {
        Self {
            current_depth: 0,
            skipped_opcodes: Vec::new(),
        }
    }

    pub fn parse_trace(&mut self, trace: DefaultFrame) -> Result<(Vec<StateUpdate>, Vec<String>)> {
        let mut updates = Vec::new();
        self.skipped_opcodes.clear();
        
        for log in &trace.struct_logs {
            if log.depth != self.current_depth {
                self.current_depth = log.depth;
            }
            
            match log.op.as_str() {
                "SSTORE" => {
                    if let Some(update) = self.extract_sstore(log) {
                        updates.push(update);
                    }
                }
                "CALL" | "STATICCALL" => {
                    if let Some(update) = self.extract_call(log) {
                        updates.push(update);
                    }
                }
                "LOG0" => {
                    if let Some(update) = self.extract_log0(log) {
                        updates.push(update);
                    }
                }
                "LOG1" => {
                    if let Some(update) = self.extract_log1(log) {
                        updates.push(update);
                    }
                }
                "LOG2" => {
                    if let Some(update) = self.extract_log2(log) {
                        updates.push(update);
                    }
                }
                "LOG3" => {
                    if let Some(update) = self.extract_log3(log) {
                        updates.push(update);
                    }
                }
                "LOG4" => {
                    if let Some(update) = self.extract_log4(log) {
                        updates.push(update);
                    }
                }
                "CREATE" | "CREATE2" | "SELFDESTRUCT" | "DELEGATECALL" => {
                    if !self.skipped_opcodes.contains(&log.op) {
                        self.skipped_opcodes.push(log.op.clone());
                        warn!("Skipping opcode: {}", log.op);
                    }
                }
                _ => {}
            }
        }
        
        Ok((updates, self.skipped_opcodes.clone()))
    }

    fn extract_sstore(&self, log: &StructLog) -> Option<StateUpdate> {
        let stack = log.stack.as_ref()?;
        if stack.len() < 2 {
            debug!("SSTORE: Insufficient stack items");
            return None;
        }
        
        let slot = stack[stack.len() - 1];
        let value = stack[stack.len() - 2];
        
        Some(StateUpdate::Store(IStateUpdateTypes::Store {
            slot: FixedBytes::from(slot),
            value: FixedBytes::from(value),
        }))
    }

    fn extract_call(&self, log: &StructLog) -> Option<StateUpdate> {
        let stack = log.stack.as_ref()?;
        if stack.len() < 7 {
            debug!("CALL: Insufficient stack items");
            return None;
        }
        
        let stack_len = stack.len();
        let target = Address::from_word(FixedBytes::from(stack[stack_len - 2]));
        let value = stack[stack_len - 3];
        let args_offset = stack[stack_len - 4].to::<usize>();
        let args_size = stack[stack_len - 5].to::<usize>();
        
        let callargs = if args_size > 0 {
            if let Some(memory_bytes) = parse_trace_memory(&log.memory) {
                extract_bytes(&memory_bytes, args_offset, args_size).into()
            } else {
                vec![].into()
            }
        } else {
            vec![].into()
        };
        
        Some(StateUpdate::Call(IStateUpdateTypes::Call {
            target,
            value,
            callargs,
        }))
    }

    fn extract_log0(&self, log: &StructLog) -> Option<StateUpdate> {
        let stack = log.stack.as_ref()?;
        if stack.len() < 2 {
            debug!("LOG0: Insufficient stack items");
            return None;
        }
        
        let stack_len = stack.len();
        let offset = stack[stack_len - 1].to::<usize>();
        let size = stack[stack_len - 2].to::<usize>();
        
        let data = if size > 0 {
            if let Some(memory_bytes) = parse_trace_memory(&log.memory) {
                extract_bytes(&memory_bytes, offset, size).into()
            } else {
                vec![].into()
            }
        } else {
            vec![].into()
        };
        
        Some(StateUpdate::Log0(IStateUpdateTypes::Log0 { data }))
    }

    fn extract_log1(&self, log: &StructLog) -> Option<StateUpdate> {
        let stack = log.stack.as_ref()?;
        if stack.len() < 3 {
            debug!("LOG1: Insufficient stack items");
            return None;
        }
        
        let stack_len = stack.len();
        let offset = stack[stack_len - 1].to::<usize>();
        let size = stack[stack_len - 2].to::<usize>();
        let topic1 = stack[stack_len - 3];
        
        let data = if size > 0 {
            if let Some(memory_bytes) = parse_trace_memory(&log.memory) {
                extract_bytes(&memory_bytes, offset, size).into()
            } else {
                vec![].into()
            }
        } else {
            vec![].into()
        };
        
        Some(StateUpdate::Log1(IStateUpdateTypes::Log1 {
            data,
            topic1: FixedBytes::from(topic1),
        }))
    }

    fn extract_log2(&self, log: &StructLog) -> Option<StateUpdate> {
        let stack = log.stack.as_ref()?;
        if stack.len() < 4 {
            debug!("LOG2: Insufficient stack items");
            return None;
        }
        
        let stack_len = stack.len();
        let offset = stack[stack_len - 1].to::<usize>();
        let size = stack[stack_len - 2].to::<usize>();
        let topic1 = stack[stack_len - 3];
        let topic2 = stack[stack_len - 4];
        
        let data = if size > 0 {
            if let Some(memory_bytes) = parse_trace_memory(&log.memory) {
                extract_bytes(&memory_bytes, offset, size).into()
            } else {
                vec![].into()
            }
        } else {
            vec![].into()
        };
        
        Some(StateUpdate::Log2(IStateUpdateTypes::Log2 {
            data,
            topic1: FixedBytes::from(topic1),
            topic2: FixedBytes::from(topic2),
        }))
    }

    fn extract_log3(&self, log: &StructLog) -> Option<StateUpdate> {
        let stack = log.stack.as_ref()?;
        if stack.len() < 5 {
            debug!("LOG3: Insufficient stack items");
            return None;
        }
        
        let stack_len = stack.len();
        let offset = stack[stack_len - 1].to::<usize>();
        let size = stack[stack_len - 2].to::<usize>();
        let topic1 = stack[stack_len - 3];
        let topic2 = stack[stack_len - 4];
        let topic3 = stack[stack_len - 5];
        
        let data = if size > 0 {
            if let Some(memory_bytes) = parse_trace_memory(&log.memory) {
                extract_bytes(&memory_bytes, offset, size).into()
            } else {
                vec![].into()
            }
        } else {
            vec![].into()
        };
        
        Some(StateUpdate::Log3(IStateUpdateTypes::Log3 {
            data,
            topic1: FixedBytes::from(topic1),
            topic2: FixedBytes::from(topic2),
            topic3: FixedBytes::from(topic3),
        }))
    }

    fn extract_log4(&self, log: &StructLog) -> Option<StateUpdate> {
        let stack = log.stack.as_ref()?;
        if stack.len() < 6 {
            debug!("LOG4: Insufficient stack items");
            return None;
        }
        
        let stack_len = stack.len();
        let offset = stack[stack_len - 1].to::<usize>();
        let size = stack[stack_len - 2].to::<usize>();
        let topic1 = stack[stack_len - 3];
        let topic2 = stack[stack_len - 4];
        let topic3 = stack[stack_len - 5];
        let topic4 = stack[stack_len - 6];
        
        let data = if size > 0 {
            if let Some(memory_bytes) = parse_trace_memory(&log.memory) {
                extract_bytes(&memory_bytes, offset, size).into()
            } else {
                vec![].into()
            }
        } else {
            vec![].into()
        };
        
        Some(StateUpdate::Log4(IStateUpdateTypes::Log4 {
            data,
            topic1: FixedBytes::from(topic1),
            topic2: FixedBytes::from(topic2),
            topic3: FixedBytes::from(topic3),
            topic4: FixedBytes::from(topic4),
        }))
    }
}

impl Default for StateUpdateParser {
    fn default() -> Self {
        Self::new()
    }
}