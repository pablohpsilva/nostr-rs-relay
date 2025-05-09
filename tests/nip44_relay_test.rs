use nostr_rs_relay::nip44;
use nostr_rs_relay::nip44_relay;
use nostr_rs_relay::event::Event;
use secp256k1::{SecretKey, PublicKey, Secp256k1};
use hex;

/// Helper function to create a secret key from a hex string
fn hex_to_secret_key(hex_str: &str) -> SecretKey {
    let bytes = hex::decode(hex_str).unwrap();
    SecretKey::from_slice(&bytes).unwrap()
}

#[test]
fn test_validate_nip44_structure() {
    // Create test keys
    let sender_sk = hex_to_secret_key("0beebd062ec8735f4243466049d7747ef5d6594ee838de147f8aab842b15e273");
    let recipient_sk = hex_to_secret_key("e108399bd8424357a710b606ae0c13166d853d327e47a6e5e038197346bdbf45");
    
    let secp = Secp256k1::new();
    let recipient_pk = PublicKey::from_secret_key(&secp, &recipient_sk);
    
    // Create a valid NIP-44 encrypted message
    let plaintext = "This is a secret message for testing";
    let encrypted = nip44::Nip44::encrypt(plaintext, &sender_sk, &recipient_pk).unwrap();
    
    // Test valid structure validation
    assert!(nip44_relay::validate_structure(&encrypted));
    
    // Test invalid structure validation
    assert!(!nip44_relay::validate_structure("not-valid-base64!"));
    assert!(!nip44_relay::validate_structure("dGhpcyBpcyBub3QgYSB2YWxpZCBzdHJ1Y3R1cmU=")); // valid base64 but not NIP-44
}

#[test]
fn test_validate_nip44_event() {
    // Create a basic event with encrypted content
    let sender_sk = hex_to_secret_key("0beebd062ec8735f4243466049d7747ef5d6594ee838de147f8aab842b15e273");
    let recipient_sk = hex_to_secret_key("e108399bd8424357a710b606ae0c13166d853d327e47a6e5e038197346bdbf45");
    
    let secp = Secp256k1::new();
    let sender_pk = PublicKey::from_secret_key(&secp, &sender_sk);
    let recipient_pk = PublicKey::from_secret_key(&secp, &recipient_sk);
    
    // Create a valid NIP-44 encrypted message
    let plaintext = "This is a secret message for testing";
    let encrypted = nip44::Nip44::encrypt(plaintext, &sender_sk, &recipient_pk).unwrap();
    
    // Create a test event with the encrypted content
    let mut event = Event {
        id: "test_id".to_string(),
        pubkey: hex::encode(sender_pk.serialize()),
        created_at: 1234567890,
        kind: 4, // Direct message kind
        tags: vec![vec!["p".to_string(), hex::encode(recipient_pk.serialize())]],
        content: encrypted,
        sig: "test_sig".to_string(),
        delegated_by: None,
        tagidx: None,
    };
    
    // Test valid event validation
    assert!(nip44_relay::validate_event(&event));
    
    // Test invalid event - no p tag
    event.tags = vec![];
    assert!(!nip44_relay::validate_event(&event));
    
    // Test invalid event - invalid content
    event.tags = vec![vec!["p".to_string(), hex::encode(recipient_pk.serialize())]];
    event.content = "not-valid-nip44-content".to_string();
    assert!(!nip44_relay::validate_event(&event));
}

#[test]
fn test_get_recipients() {
    // Create a direct message event
    let mut event = Event {
        id: "test_id".to_string(),
        pubkey: "sender_pubkey".to_string(),
        created_at: 1234567890,
        kind: 4, // Direct message kind
        tags: vec![
            vec!["p".to_string(), "recipient1".to_string()],
            vec!["p".to_string(), "recipient2".to_string()]
        ],
        content: "encrypted-content".to_string(),
        sig: "test_sig".to_string(),
        delegated_by: None,
        tagidx: None,
    };
    
    // Test getting recipients from DM
    let recipients = nip44_relay::get_recipients(&event);
    assert_eq!(recipients.len(), 2);
    assert!(recipients.contains(&"recipient1".to_string()));
    assert!(recipients.contains(&"recipient2".to_string()));
    
    // Test with non-DM event
    event.kind = 1;
    let recipients = nip44_relay::get_recipients(&event);
    assert_eq!(recipients.len(), 0);
}

#[test]
fn test_should_route_to() {
    // Create a direct message event
    let event = Event {
        id: "test_id".to_string(),
        pubkey: "sender_pubkey".to_string(),
        created_at: 1234567890,
        kind: 4, // Direct message kind
        tags: vec![
            vec!["p".to_string(), "recipient1".to_string()],
            vec!["p".to_string(), "recipient2".to_string()]
        ],
        content: "encrypted-content".to_string(),
        sig: "test_sig".to_string(),
        delegated_by: None,
        tagidx: None,
    };
    
    // Test routing to recipient
    assert!(nip44_relay::should_route_to(&event, "recipient1"));
    assert!(nip44_relay::should_route_to(&event, "recipient2"));
    
    // Test routing to sender
    assert!(nip44_relay::should_route_to(&event, "sender_pubkey"));
    
    // Test non-matching pubkey
    assert!(!nip44_relay::should_route_to(&event, "other_pubkey"));
} 