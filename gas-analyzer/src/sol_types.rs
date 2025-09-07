use alloy::sol;

sol! {
    enum StateUpdateType {
        STORE,
        CALL,
        LOG0,
        LOG1,
        LOG2,
        LOG3,
        LOG4
    }

    #[derive(Debug)]
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

    struct StateUpdates {
        uint8[] types;
        bytes[] data;
    }

    error RevertingContext(uint256 index, address target, bytes revertData, bytes callargs);
}


#[allow(warnings)]
#[derive(Debug)]
pub enum StateUpdate {
    Store(IStateUpdateTypes::Store),
    Call(IStateUpdateTypes::Call),
    Log0(IStateUpdateTypes::Log0),
    Log1(IStateUpdateTypes::Log1),
    Log2(IStateUpdateTypes::Log2),
    Log3(IStateUpdateTypes::Log3),
    Log4(IStateUpdateTypes::Log4),
}
