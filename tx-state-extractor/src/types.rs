use alloy::sol;
use alloy_primitives::{Address, Bytes, FixedBytes, U256};
use serde::{Deserialize, Serialize};

sol! {
    #[derive(Debug, Serialize, Deserialize)]
    enum StateUpdateType {
        STORE,
        CALL,
        LOG0,
        LOG1,
        LOG2,
        LOG3,
        LOG4
    }

    #[derive(Debug, Serialize, Deserialize)]
    interface IStateUpdateTypes {
        struct Store {
            bytes32 slot;
            bytes32 value;
        }

        struct Call {
            address target;
            uint256 value;
            bytes callargs;
        }

        struct Log0 {
            bytes data;
        }

        struct Log1 {
            bytes data;
            bytes32 topic1;
        }

        struct Log2 {
            bytes data;
            bytes32 topic1;
            bytes32 topic2;
        }

        struct Log3 {
            bytes data;
            bytes32 topic1;
            bytes32 topic2;
            bytes32 topic3;
        }

        struct Log4 {
            bytes data;
            bytes32 topic1;
            bytes32 topic2;
            bytes32 topic3;
            bytes32 topic4;
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StateUpdate {
    Store(IStateUpdateTypes::Store),
    Call(IStateUpdateTypes::Call),
    Log0(IStateUpdateTypes::Log0),
    Log1(IStateUpdateTypes::Log1),
    Log2(IStateUpdateTypes::Log2),
    Log3(IStateUpdateTypes::Log3),
    Log4(IStateUpdateTypes::Log4),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateUpdateReport {
    pub tx_hash: FixedBytes<32>,
    pub block_number: u64,
    pub from: Address,
    pub to: Option<Address>,
    pub value: U256,
    pub gas_used: u128,
    pub status: bool,
    pub state_updates: Vec<StateUpdate>,
    pub skipped_opcodes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncodedUpdates {
    pub types: Vec<u8>,
    pub data: Vec<Bytes>,
}