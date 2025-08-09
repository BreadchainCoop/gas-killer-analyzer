use crate::types::{EncodedUpdates, StateUpdate, StateUpdateType};
use alloy::sol_types::SolValue;
use alloy_primitives::Bytes;
use anyhow::Result;

pub struct SolidityEncoder;

impl SolidityEncoder {
    pub fn encode_state_updates(updates: Vec<StateUpdate>) -> Result<EncodedUpdates> {
        let mut types = Vec::new();
        let mut data = Vec::new();
        
        for update in updates {
            match update {
                StateUpdate::Store(store) => {
                    types.push(StateUpdateType::STORE as u8);
                    let encoded = (store.slot, store.value).abi_encode();
                    data.push(encoded.into());
                }
                StateUpdate::Call(call) => {
                    types.push(StateUpdateType::CALL as u8);
                    let encoded = (call.target, call.value, call.callargs).abi_encode();
                    data.push(encoded.into());
                }
                StateUpdate::Log0(log) => {
                    types.push(StateUpdateType::LOG0 as u8);
                    let encoded = log.data.abi_encode();
                    data.push(encoded.into());
                }
                StateUpdate::Log1(log) => {
                    types.push(StateUpdateType::LOG1 as u8);
                    let encoded = (log.data, log.topic1).abi_encode();
                    data.push(encoded.into());
                }
                StateUpdate::Log2(log) => {
                    types.push(StateUpdateType::LOG2 as u8);
                    let encoded = (log.data, log.topic1, log.topic2).abi_encode();
                    data.push(encoded.into());
                }
                StateUpdate::Log3(log) => {
                    types.push(StateUpdateType::LOG3 as u8);
                    let encoded = (log.data, log.topic1, log.topic2, log.topic3).abi_encode();
                    data.push(encoded.into());
                }
                StateUpdate::Log4(log) => {
                    types.push(StateUpdateType::LOG4 as u8);
                    let encoded = (log.data, log.topic1, log.topic2, log.topic3, log.topic4).abi_encode();
                    data.push(encoded.into());
                }
            }
        }
        
        Ok(EncodedUpdates { types, data })
    }
    
    pub fn to_abi_encoded(encoded: &EncodedUpdates) -> Bytes {
        (encoded.types.clone(), encoded.data.clone()).abi_encode().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::IStateUpdateTypes;
    use alloy_primitives::{Address, FixedBytes, U256};

    #[test]
    fn test_encode_store_update() {
        let store = IStateUpdateTypes::Store {
            slot: FixedBytes::from([1u8; 32]),
            value: FixedBytes::from([2u8; 32]),
        };
        
        let updates = vec![StateUpdate::Store(store)];
        let encoded = SolidityEncoder::encode_state_updates(updates).unwrap();
        
        assert_eq!(encoded.types.len(), 1);
        assert_eq!(encoded.types[0], StateUpdateType::STORE as u8);
        assert_eq!(encoded.data.len(), 1);
    }

    #[test]
    fn test_encode_call_update() {
        let call = IStateUpdateTypes::Call {
            target: Address::from([3u8; 20]),
            value: U256::from(1000),
            callargs: vec![4u8; 32].into(),
        };
        
        let updates = vec![StateUpdate::Call(call)];
        let encoded = SolidityEncoder::encode_state_updates(updates).unwrap();
        
        assert_eq!(encoded.types.len(), 1);
        assert_eq!(encoded.types[0], StateUpdateType::CALL as u8);
        assert_eq!(encoded.data.len(), 1);
    }
}