use nostr_rs_relay::nip17;
use nostr_rs_relay::nip17_relay;
use nostr_rs_relay::event::Event;
use secp256k1::{SecretKey, PublicKey, Secp256k1};
use hex;

/// Helper function to create a secret key from a hex string
fn hex_to_secret_key(hex_str: &str) -> SecretKey {
    let bytes = hex::decode(hex_str).unwrap();
    SecretKey::from_slice(&bytes).unwrap()
}

#[test]
fn test_validate_dm_structure() {
    // Create a basic direct message event
    let event = Event {
        id: "test_id".to_string(),
        pubkey: "sender_pubkey".to_string(),
        created_at: 1234567890,
        kind: 14, // Direct message kind
        tags: vec![vec!["p".to_string(), "recipient_pubkey".to_string()]],
        content: "QjJDQVk1SmV2WThLeHBQeTZFYVpKZ2ZwZkRTNUFCWms=", // Base64 encoded
        sig: "signature".to_string(),
        delegated_by: None,
        tagidx: None,
    };
    
    // Test valid structure validation
    assert!(nip17_relay::validate_structure(&event));
    
    // Test complete event validation
    assert!(nip17_relay::validate_event(&event));
    
    // Test wrong kind
    let mut invalid_event = event.clone();
    invalid_event.kind = 1;
    assert!(!nip17_relay::validate_structure(&invalid_event));
    
    // Test missing p-tag
    let mut invalid_event = event.clone();
    invalid_event.tags = vec![];
    assert!(!nip17_relay::validate_structure(&invalid_event));
    
    // Test invalid base64 content
    let mut invalid_event = event.clone();
    invalid_event.content = "not valid base64!".to_string();
    assert!(!nip17_relay::validate_structure(&invalid_event));
}

#[test]
fn test_get_recipients() {
    // Create a direct message event with multiple recipients
    let event = Event {
        id: "test_id".to_string(),
        pubkey: "sender_pubkey".to_string(),
        created_at: 1234567890,
        kind: 14, // Direct message kind
        tags: vec![
            vec!["p".to_string(), "recipient1".to_string()],
            vec!["p".to_string(), "recipient2".to_string()],
            vec!["subject".to_string(), "Hello there".to_string()],
        ],
        content: "QjJDQVk1SmV2WThLeHBQeTZFYVpKZ2ZwZkRTNUFCWms=", // Base64 encoded
        sig: "signature".to_string(),
        delegated_by: None,
        tagidx: None,
    };
    
    // Test getting recipients
    let recipients = nip17_relay::get_recipients(&event);
    assert_eq!(recipients.len(), 2);
    assert!(recipients.contains(&"recipient1".to_string()));
    assert!(recipients.contains(&"recipient2".to_string()));
    
    // Test with non-DM event
    let mut non_dm = event.clone();
    non_dm.kind = 1;
    let recipients = nip17_relay::get_recipients(&non_dm);
    assert_eq!(recipients.len(), 0);
}

#[test]
fn test_should_route_to() {
    // Create a direct message event
    let event = Event {
        id: "test_id".to_string(),
        pubkey: "sender_pubkey".to_string(), 
        created_at: 1234567890,
        kind: 14, // Direct message kind
        tags: vec![
            vec!["p".to_string(), "recipient1".to_string()],
            vec!["p".to_string(), "recipient2".to_string()],
        ],
        content: "QjJDQVk1SmV2WThLeHBQeTZFYVpKZ2ZwZkRTNUFCWms=", // Base64 encoded
        sig: "signature".to_string(),
        delegated_by: None,
        tagidx: None,
    };
    
    // Test routing to recipients
    assert!(nip17_relay::should_route_to(&event, "recipient1"));
    assert!(nip17_relay::should_route_to(&event, "recipient2"));
    
    // Test routing to sender (unlike gift wraps, DMs should route to sender)
    assert!(nip17_relay::should_route_to(&event, "sender_pubkey"));
    
    // Test with non-matching pubkey
    assert!(!nip17_relay::should_route_to(&event, "other_pubkey"));
}

#[test]
fn test_create_index_entries() {
    // Create a direct message event
    let event = Event {
        id: "test_id".to_string(),
        pubkey: "sender_pubkey".to_string(),
        created_at: 1234567890,
        kind: 14, // Direct message kind
        tags: vec![
            vec!["p".to_string(), "recipient1".to_string()],
            vec!["p".to_string(), "recipient2".to_string()],
        ],
        content: "QjJDQVk1SmV2WThLeHBQeTZFYVpKZ2ZwZkRTNUFCWms=", // Base64 encoded
        sig: "signature".to_string(),
        delegated_by: None,
        tagidx: None,
    };
    
    // Test creating index entries
    let entries = nip17_relay::create_index_entries(&event);
    assert_eq!(entries.len(), 3); // 2 recipients + 1 sender
    
    // Check entry format (recipient, event_id)
    assert!(entries.contains(&("recipient1".to_string(), "test_id".to_string())));
    assert!(entries.contains(&("recipient2".to_string(), "test_id".to_string())));
    assert!(entries.contains(&("sender_pubkey".to_string(), "test_id".to_string())));
    
    // Test with non-DM event
    let mut non_dm = event.clone();
    non_dm.kind = 1;
    let entries = nip17_relay::create_index_entries(&non_dm);
    assert_eq!(entries.len(), 0);
}

#[test]
fn test_file_message() {
    // Create a file message event
    let event = Event {
        id: "test_id".to_string(),
        pubkey: "sender_pubkey".to_string(),
        created_at: 1234567890,
        kind: 15, // File message kind
        tags: vec![
            vec!["p".to_string(), "recipient1".to_string()],
            vec!["p".to_string(), "recipient2".to_string()],
            vec!["file-type".to_string(), "image/jpeg".to_string()],
            vec!["x".to_string(), "e8fbf31e397a9325ea55cacb486519f28c7dc7339dbf1d0b77b124f5977008d7".to_string()],
            vec!["size".to_string(), "1048576".to_string()],
            vec!["dim".to_string(), "800x600".to_string()],
        ],
        content: "QjJDQVk1SmV2WThLeHBQeTZFYVpKZ2ZwZkRTNUFCWms=", // Base64 encoded URL
        sig: "signature".to_string(),
        delegated_by: None,
        tagidx: None,
    };
    
    // Test file message detection
    assert!(nip17_relay::is_file_message(&event));
    
    // Test file metadata extraction
    let metadata = nip17_relay::get_file_metadata(&event).unwrap();
    assert_eq!(metadata.file_type, "image/jpeg");
    assert_eq!(metadata.file_hash, "e8fbf31e397a9325ea55cacb486519f28c7dc7339dbf1d0b77b124f5977008d7");
    assert_eq!(metadata.size, Some(1048576));
    assert_eq!(metadata.dimensions, Some((800, 600)));
    
    // Test with regular message (not a file)
    let mut regular_dm = event.clone();
    regular_dm.kind = 14;
    assert!(!nip17_relay::is_file_message(&regular_dm));
    assert!(nip17_relay::get_file_metadata(&regular_dm).is_none());
} 