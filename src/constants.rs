use alloy::primitives::{Address, FixedBytes, address, b256};

// Contracts on Gnosis mainnet used for testing
pub const DELEGATECALL_CONTRACT_MAIN_ADDRESS: Address =
    address!("0x11A16BA2BbcBAaa23555eb5f6D4C938C14230b84");
pub const DELEGATE_CONTRACT_A_ADDRESS: Address =
    address!("0x276ec521ed87eFF06F2d1067AB61a28e969b6F88");
pub const ACCESS_CONTROL_MAIN_ADDRESS: Address =
    address!("0x8bB7AfE4BbDdeFf40859c963521DF3418345E8f7");

// Transactions on Gnosis mainnet used for testing
pub const DELEGATECALL_CONTRACT_MAIN_RUN_TX_HASH: FixedBytes<32> =
    b256!("0x66db1b5c186504525e6be240747f4458a4038afaa0898ad30ae0f22c92750dea");
pub const ACCESS_CONTROL_MAIN_RUN_TX_HASH: FixedBytes<32> =
    b256!("0xd009b3d1095790eb78eb25bc25c7312b98356655a8ab2bf8a5230d2b20c7fd1b");

// TODO: Update address to Gnosis mainnet address for other tests
pub const SIMPLE_STORAGE_ADDRESS: Address = address!("0x2273cb304cF542E0Db67C78AAb2bD120D24655b2");

// TODO: Update hashes to Gnosis mainnet transactions for other tests
pub const SIMPLE_STORAGE_SET_TX_HASH: FixedBytes<32> =
    b256!("0x66db1b5c186504525e6be240747f4458a4038afaa0898ad30ae0f22c92750dea");
pub const SIMPLE_STORAGE_DEPOSIT_TX_HASH: FixedBytes<32> =
    b256!("0x66db1b5c186504525e6be240747f4458a4038afaa0898ad30ae0f22c92750dea");
pub const SIMPLE_STORAGE_CALL_EXTERNAL_TX_HASH: FixedBytes<32> =
    b256!("0x66db1b5c186504525e6be240747f4458a4038afaa0898ad30ae0f22c92750dea");
pub const SIMPLE_ARRAY_ITERATION_TX_HASH: FixedBytes<32> =
    b256!("0x66db1b5c186504525e6be240747f4458a4038afaa0898ad30ae0f22c92750dea");

// Used for testing
pub const FAKE_ADDRESS: Address = address!("0xc76a6477c12dcb8554b1493482D85AB720b2A322");
