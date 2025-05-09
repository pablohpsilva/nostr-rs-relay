use nostr_rs_relay::nip59;
use nostr_rs_relay::nip59_relay;
use nostr_rs_relay::event::Event;
use secp256k1::{SecretKey, PublicKey, Secp256k1};
use hex;

/// Helper function to create a secret key from a hex string
fn hex_to_secret_key(hex_str: &str) -> SecretKey {
    let bytes = hex::decode(hex_str).unwrap();
    SecretKey::from_slice(&bytes).unwrap()
}

#[test]
fn test_validate_gift_wrap_structure() {
    // Create test keys
    let sender_sk = hex_to_secret_key("0beebd062ec8735f4243466049d7747ef5d6594ee838de147f8aab842b15e273");
    let recipient_sk = hex_to_secret_key("e108399bd8424357a710b606ae0c13166d853d327e47a6e5e038197346bdbf45");
    
    let secp = Secp256k1::new();
    let sender_pk = PublicKey::from_secret_key(&secp, &sender_sk);
    let recipient_pk = PublicKey::from_secret_key(&secp, &recipient_sk);
    
    // Create a valid rumor
    let rumor = nip59::create_rumor(1, "Hello, this is a test message", vec![], 
                                     &hex::encode(sender_pk.serialize()), 1234567890).unwrap();
    
    // Create a seal
    let seal = nip59::create_seal(&rumor, &sender_sk, &recipient_pk, Some(1234567895)).unwrap();
    
    // Create a gift wrap
    let (gift_wrap, _ephemeral_sk) = nip59::create_gift_wrap(&seal, &recipient_pk, Some(1234567900)).unwrap();
    
    // Convert to Event struct that the relay uses
    let event = Event {
        id: gift_wrap.id.clone(),
        pubkey: gift_wrap.pubkey.clone(),
        created_at: gift_wrap.created_at,
        kind: gift_wrap.kind as u64,
        tags: gift_wrap.tags.clone(),
        content: gift_wrap.content.clone(),
        sig: gift_wrap.sig.clone().unwrap_or_default(),
        delegated_by: None,
        tagidx: None,
    };
    
    // Test valid structure validation
    assert!(nip59_relay::validate_structure(&event));
    
    // Test complete event validation
    assert!(nip59_relay::validate_event(&event));
    
    // Test wrong kind
    let mut invalid_event = event.clone();
    invalid_event.kind = 1;
    assert!(!nip59_relay::validate_structure(&invalid_event));
    
    // Test missing p-tag
    let mut invalid_event = event.clone();
    invalid_event.tags = vec![];
    assert!(!nip59_relay::validate_structure(&invalid_event));
    
    // Test invalid base64 content
    let mut invalid_event = event.clone();
    invalid_event.content = "not valid base64!".to_string();
    assert!(!nip59_relay::validate_structure(&invalid_event));
}

#[test]
fn test_get_recipients() {
    // Create a gift wrap event with multiple recipients
    let event = Event {
        id: "test_id".to_string(),
        pubkey: "ephemeral_key".to_string(),
        created_at: 1234567890,
        kind: 1059,
        tags: vec![
            vec!["p".to_string(), "recipient1".to_string()],
            vec!["p".to_string(), "recipient2".to_string()],
            vec!["other".to_string(), "value".to_string()],
        ],
        content: "base64_content".to_string(),
        sig: "signature".to_string(),
        delegated_by: None,
        tagidx: None,
    };
    
    // Test getting recipients
    let recipients = nip59_relay::get_recipients(&event);
    assert_eq!(recipients.len(), 2);
    assert!(recipients.contains(&"recipient1".to_string()));
    assert!(recipients.contains(&"recipient2".to_string()));
    
    // Test with non-gift-wrap event
    let mut non_gift = event.clone();
    non_gift.kind = 1;
    let recipients = nip59_relay::get_recipients(&non_gift);
    assert_eq!(recipients.len(), 0);
}

#[test]
fn test_should_route_to() {
    // Create a gift wrap event
    let event = Event {
        id: "test_id".to_string(),
        pubkey: "ephemeral_key".to_string(), 
        created_at: 1234567890,
        kind: 1059,
        tags: vec![
            vec!["p".to_string(), "recipient1".to_string()],
            vec!["p".to_string(), "recipient2".to_string()],
        ],
        content: "base64_content".to_string(),
        sig: "signature".to_string(),
        delegated_by: None,
        tagidx: None,
    };
    
    // Test routing to recipients
    assert!(nip59_relay::should_route_to(&event, "recipient1"));
    assert!(nip59_relay::should_route_to(&event, "recipient2"));
    
    // Test NOT routing to sender (ephemeral key)
    // Gift wraps should only be routed to p-tag recipients
    assert!(!nip59_relay::should_route_to(&event, "ephemeral_key"));
    
    // Test with non-matching pubkey
    assert!(!nip59_relay::should_route_to(&event, "other_pubkey"));
}

#[test]
fn test_create_index_entries() {
    // Create a gift wrap event
    let event = Event {
        id: "test_id".to_string(),
        pubkey: "ephemeral_key".to_string(),
        created_at: 1234567890,
        kind: 1059,
        tags: vec![
            vec!["p".to_string(), "recipient1".to_string()],
            vec!["p".to_string(), "recipient2".to_string()],
        ],
        content: "base64_content".to_string(),
        sig: "signature".to_string(),
        delegated_by: None,
        tagidx: None,
    };
    
    // Test creating index entries
    let entries = nip59_relay::create_index_entries(&event);
    assert_eq!(entries.len(), 2);
    
    // Check entry format (recipient, event_id)
    assert!(entries.contains(&("recipient1".to_string(), "test_id".to_string())));
    assert!(entries.contains(&("recipient2".to_string(), "test_id".to_string())));
    
    // Test with non-gift-wrap event
    let mut non_gift = event.clone();
    non_gift.kind = 1;
    let entries = nip59_relay::create_index_entries(&non_gift);
    assert_eq!(entries.len(), 0);
} 