use alloy::primitives::{Address, FixedBytes, address, b256};

pub const SIMPLE_STORAGE_ADDRESS: Address = address!("0x2273cb304cF542E0Db67C78AAb2bD120D24655b2");
pub const SIMPLE_STORAGE_SET_TX_HASH: FixedBytes<32> =
    b256!("0x4ee771ec4fa5f3fb22bc7dfb146cf8d8e3f439ea05baf24809e3f901e96de05f");
pub const SIMPLE_STORAGE_DEPOSIT_TX_HASH: FixedBytes<32> =
    b256!("0x524480959eea76b1503ff3f291fb8de79daeff0f512c99b959e5585cb14b8442");
pub const SIMPLE_STORAGE_CALL_EXTERNAL_TX_HASH: FixedBytes<32> =
    b256!("0xecb274407af5a71944008d751eba5b4dcd53e36ec338225e6ae366aff2f9da10");
pub const DELEGATECALL_CONTRACT_MAIN_ADDRESS: Address =
    address!("0xB5C5a908b14670C954E78Ca5163ac7d3B7bE5D70");
pub const DELEGATE_CONTRACT_A_ADDRESS: Address =
    address!("0xde7600ee1bea19c2f5f23c4c474134a149d470d1");
pub const DELEGATECALL_CONTRACT_MAIN_RUN_TX_HASH: FixedBytes<32> =
    b256!("0xb5d369570ec8bbbc75dd9702a824ce2fd1c961655582fb62b0b1c96276bdb4f5");
