use tx_state_extractor::TxStateExtractor;

#[test]
fn test_library_creation() {
    let result = TxStateExtractor::new("https://eth.llamarpc.com");
    assert!(result.is_ok());
}

#[cfg(feature = "integration")]
#[tokio::test]
async fn test_mainnet_transaction() {
    use alloy_primitives::FixedBytes;
    
    let extractor = TxStateExtractor::new("https://eth.llamarpc.com").unwrap();
    
    // Test with a known mainnet transaction (you would replace with an actual tx hash)
    let tx_hash: FixedBytes<32> = "0x0000000000000000000000000000000000000000000000000000000000000000".parse().unwrap();
    
    // This would fail without a real transaction, but shows the API usage
    let result = extractor.extract_state_updates(tx_hash).await;
    
    // We expect this to fail since it's a dummy hash
    assert!(result.is_err());
}