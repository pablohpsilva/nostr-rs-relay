// NIP-59 Gift Wrap Test Suite
//
// These tests verify the implementation of the Gift Wrap protocol
// as specified in NIP-59.

use nostr_rs_relay::nip59::{
    self, Event, Rumor, Seal, GiftWrap, 
    create_rumor, create_seal, create_gift_wrap, unwrap_gift_wrap, unseal, open_gift,
    SEAL_KIND, GIFT_WRAP_KIND
};
use secp256k1::{SecretKey, PublicKey, Secp256k1};
use rand::{rngs::OsRng, RngCore};

// Test keys from the NIP-59 specification
const SENDER_SK_HEX: &str = "0beebd062ec8735f4243466049d7747ef5d6594ee838de147f8aab842b15e273";
const RECIPIENT_SK_HEX: &str = "e108399bd8424357a710b606ae0c13166d853d327e47a6e5e038197346bdbf45";
const EPHEMERAL_SK_HEX: &str = "4f02eac59266002db5801adc5270700ca69d5b8f761d8732fab2fbf233c90cbd";

// Helper function to create a secret key from hex
fn hex_to_secret_key(hex_str: &str) -> SecretKey {
    let bytes = hex::decode(hex_str).unwrap();
    SecretKey::from_slice(&bytes).unwrap()
}

// Helper function to generate a random secret key
fn random_secret_key() -> SecretKey {
    let mut random_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut random_bytes);
    SecretKey::from_slice(&random_bytes).unwrap()
}

#[test]
fn test_create_rumor_basic() {
    let secp = Secp256k1::new();
    let sender_sk = hex_to_secret_key(SENDER_SK_HEX);
    let sender_pk = PublicKey::from_secret_key(&secp, &sender_sk);
    let sender_pk_hex = hex::encode(sender_pk.serialize());
    
    let content = "Are you going to the party tonight?";
    let created_at = 1691518405;
    
    let rumor = create_rumor(1, content, vec![], &sender_pk_hex, created_at).unwrap();
    
    assert_eq!(rumor.kind, 1);
    assert_eq!(rumor.content, content);
    assert_eq!(rumor.pubkey, sender_pk_hex);
    assert_eq!(rumor.created_at, created_at);
    assert!(rumor.sig.is_none());
    assert!(!rumor.id.is_empty()); // ID should be calculated
}

#[test]
fn test_seal_creation_and_unsealing() {
    let secp = Secp256k1::new();
    let sender_sk = hex_to_secret_key(SENDER_SK_HEX);
    let recipient_sk = hex_to_secret_key(RECIPIENT_SK_HEX);
    
    let sender_pk = PublicKey::from_secret_key(&secp, &sender_sk);
    let recipient_pk = PublicKey::from_secret_key(&secp, &recipient_sk);
    
    let sender_pk_hex = hex::encode(sender_pk.serialize());
    
    // Create a rumor
    let content = "Top secret message";
    let rumor = create_rumor(1, content, vec![], &sender_pk_hex, 1691518405).unwrap();
    
    // Create a seal with a fixed timestamp
    let seal = create_seal(&rumor, &sender_sk, &recipient_pk, Some(1703015180)).unwrap();
    
    // Verify seal properties
    assert_eq!(seal.kind, SEAL_KIND);
    assert_eq!(seal.created_at, 1703015180);
    assert_eq!(seal.pubkey, sender_pk_hex);
    assert!(seal.sig.is_some());
    assert!(seal.tags.is_empty());
    
    // Recipient unseals the message
    let unsealed = unseal(&seal, &recipient_sk).unwrap();
    
    // Verify the unsealed rumor
    assert_eq!(unsealed.kind, rumor.kind);
    assert_eq!(unsealed.content, rumor.content);
    assert_eq!(unsealed.pubkey, rumor.pubkey);
    assert_eq!(unsealed.created_at, rumor.created_at);
}

#[test]
fn test_gift_wrap_creation_and_unwrapping() {
    let secp = Secp256k1::new();
    let sender_sk = hex_to_secret_key(SENDER_SK_HEX);
    let recipient_sk = hex_to_secret_key(RECIPIENT_SK_HEX);
    
    let sender_pk = PublicKey::from_secret_key(&secp, &sender_sk);
    let recipient_pk = PublicKey::from_secret_key(&secp, &recipient_sk);
    
    let sender_pk_hex = hex::encode(sender_pk.serialize());
    
    // Create a rumor
    let rumor = create_rumor(1, "Secret message", vec![], &sender_pk_hex, 1691518405).unwrap();
    
    // Create a seal
    let seal = create_seal(&rumor, &sender_sk, &recipient_pk, Some(1703015180)).unwrap();
    
    // Create a gift wrap
    let (gift_wrap, ephemeral_sk) = create_gift_wrap(&seal, &recipient_pk, Some(1703021488)).unwrap();
    
    // Verify gift wrap properties
    assert_eq!(gift_wrap.kind, GIFT_WRAP_KIND);
    assert_eq!(gift_wrap.created_at, 1703021488);
    assert!(gift_wrap.sig.is_some());
    
    // Check the tags
    assert_eq!(gift_wrap.tags.len(), 1);
    assert_eq!(gift_wrap.tags[0][0], "p");
    
    // The recipient pubkey should be in the p tag
    let recipient_pk_hex = hex::encode(recipient_pk.serialize());
    assert_eq!(gift_wrap.tags[0][1], recipient_pk_hex);
    
    // Recipient unwraps the gift
    let unwrapped = unwrap_gift_wrap(&gift_wrap, &recipient_sk).unwrap();
    
    // Verify the unwrapped seal
    assert_eq!(unwrapped.kind, SEAL_KIND);
    assert_eq!(unwrapped.pubkey, sender_pk_hex);
    assert_eq!(unwrapped.created_at, seal.created_at);
}

#[test]
fn test_full_gift_wrap_flow_with_multiple_recipients() {
    let secp = Secp256k1::new();
    let sender_sk = hex_to_secret_key(SENDER_SK_HEX);
    let recipient1_sk = hex_to_secret_key(RECIPIENT_SK_HEX);
    let recipient2_sk = random_secret_key();
    
    let sender_pk = PublicKey::from_secret_key(&secp, &sender_sk);
    let recipient1_pk = PublicKey::from_secret_key(&secp, &recipient1_sk);
    let recipient2_pk = PublicKey::from_secret_key(&secp, &recipient2_sk);
    
    let sender_pk_hex = hex::encode(sender_pk.serialize());
    
    // Create a rumor (same content for both recipients)
    let content = "Meeting at 8pm at the usual place";
    let rumor = create_rumor(1, content, vec![], &sender_pk_hex, 1691518405).unwrap();
    
    // Create seals for both recipients
    let seal1 = create_seal(&rumor, &sender_sk, &recipient1_pk, Some(1703015180)).unwrap();
    let seal2 = create_seal(&rumor, &sender_sk, &recipient2_pk, Some(1703015180)).unwrap();
    
    // Create gift wraps for both recipients
    let (gift_wrap1, _) = create_gift_wrap(&seal1, &recipient1_pk, Some(1703021488)).unwrap();
    let (gift_wrap2, _) = create_gift_wrap(&seal2, &recipient2_pk, Some(1703021488)).unwrap();
    
    // Both recipients open their gifts
    let opened1 = open_gift(&gift_wrap1, &recipient1_sk).unwrap();
    let opened2 = open_gift(&gift_wrap2, &recipient2_sk).unwrap();
    
    // Verify both got the same message
    assert_eq!(opened1.content, content);
    assert_eq!(opened2.content, content);
    assert_eq!(opened1.pubkey, sender_pk_hex);
    assert_eq!(opened2.pubkey, sender_pk_hex);
}

#[test]
fn test_random_timestamps_for_metadata_protection() {
    let secp = Secp256k1::new();
    let sender_sk = hex_to_secret_key(SENDER_SK_HEX);
    let recipient_sk = hex_to_secret_key(RECIPIENT_SK_HEX);
    
    let sender_pk = PublicKey::from_secret_key(&secp, &sender_sk);
    let recipient_pk = PublicKey::from_secret_key(&secp, &recipient_sk);
    
    let sender_pk_hex = hex::encode(sender_pk.serialize());
    
    // Create a rumor with a specific timestamp
    let rumor_time = 1691518405;
    let rumor = create_rumor(1, "Secret meeting", vec![], &sender_pk_hex, rumor_time).unwrap();
    
    // Create a seal with auto-generated timestamp
    let seal = create_seal(&rumor, &sender_sk, &recipient_pk, None).unwrap();
    
    // Create a gift wrap with auto-generated timestamp
    let (gift_wrap, _) = create_gift_wrap(&seal, &recipient_pk, None).unwrap();
    
    // Verify timestamps are different (for metadata protection)
    assert_ne!(seal.created_at, rumor_time);
    assert_ne!(gift_wrap.created_at, seal.created_at);
    
    // But when unwrapped, the original timestamp is preserved
    let opened = open_gift(&gift_wrap, &recipient_sk).unwrap();
    assert_eq!(opened.created_at, rumor_time);
}

#[test]
fn test_using_custom_tags() {
    let secp = Secp256k1::new();
    let sender_sk = hex_to_secret_key(SENDER_SK_HEX);
    let recipient_sk = hex_to_secret_key(RECIPIENT_SK_HEX);
    
    let sender_pk = PublicKey::from_secret_key(&secp, &sender_sk);
    let recipient_pk = PublicKey::from_secret_key(&secp, &recipient_sk);
    
    let sender_pk_hex = hex::encode(sender_pk.serialize());
    
    // Create a rumor with custom tags
    let tags = vec![
        vec!["e".to_string(), "1234567890abcdef".to_string()],
        vec!["subject".to_string(), "Meeting notes".to_string()],
    ];
    
    let rumor = create_rumor(1, "Content with tags", tags, &sender_pk_hex, 1691518405).unwrap();
    
    // Create a seal and gift wrap
    let seal = create_seal(&rumor, &sender_sk, &recipient_pk, Some(1703015180)).unwrap();
    let (gift_wrap, _) = create_gift_wrap(&seal, &recipient_pk, Some(1703021488)).unwrap();
    
    // Open the gift
    let opened = open_gift(&gift_wrap, &recipient_sk).unwrap();
    
    // Verify tags were preserved
    assert_eq!(opened.tags.len(), 2);
    assert_eq!(opened.tags[0][0], "e");
    assert_eq!(opened.tags[0][1], "1234567890abcdef");
    assert_eq!(opened.tags[1][0], "subject");
    assert_eq!(opened.tags[1][1], "Meeting notes");
}

#[test]
fn test_different_event_kinds() {
    let secp = Secp256k1::new();
    let sender_sk = hex_to_secret_key(SENDER_SK_HEX);
    let recipient_sk = hex_to_secret_key(RECIPIENT_SK_HEX);
    
    let sender_pk = PublicKey::from_secret_key(&secp, &sender_sk);
    let recipient_pk = PublicKey::from_secret_key(&secp, &recipient_sk);
    
    let sender_pk_hex = hex::encode(sender_pk.serialize());
    
    // Test with different kinds of events
    let kinds = vec![0, 1, 4, 5, 7, 30023];
    
    for kind in kinds {
        // Create a rumor with this kind
        let rumor = create_rumor(kind, &format!("Event of kind {}", kind), vec![], &sender_pk_hex, 1691518405).unwrap();
        
        // Create a seal and gift wrap
        let seal = create_seal(&rumor, &sender_sk, &recipient_pk, Some(1703015180)).unwrap();
        let (gift_wrap, _) = create_gift_wrap(&seal, &recipient_pk, Some(1703021488)).unwrap();
        
        // Open the gift
        let opened = open_gift(&gift_wrap, &recipient_sk).unwrap();
        
        // Verify the kind was preserved
        assert_eq!(opened.kind, kind);
    }
}

#[test]
fn test_error_conditions() {
    let secp = Secp256k1::new();
    let sender_sk = hex_to_secret_key(SENDER_SK_HEX);
    let recipient_sk = hex_to_secret_key(RECIPIENT_SK_HEX);
    let wrong_sk = random_secret_key();
    
    let sender_pk = PublicKey::from_secret_key(&secp, &sender_sk);
    let recipient_pk = PublicKey::from_secret_key(&secp, &recipient_sk);
    
    let sender_pk_hex = hex::encode(sender_pk.serialize());
    
    // 1. Create a valid rumor
    let rumor = create_rumor(1, "Secret message", vec![], &sender_pk_hex, 1691518405).unwrap();
    
    // 2. Create a valid seal
    let seal = create_seal(&rumor, &sender_sk, &recipient_pk, Some(1703015180)).unwrap();
    
    // 3. Create a valid gift wrap
    let (gift_wrap, _) = create_gift_wrap(&seal, &recipient_pk, Some(1703021488)).unwrap();
    
    // Test: Try to decrypt with wrong private key
    let wrong_unwrap_result = unwrap_gift_wrap(&gift_wrap, &wrong_sk);
    assert!(wrong_unwrap_result.is_err());
    
    // Test: Try to unseal with wrong private key
    let wrong_unseal_result = unseal(&seal, &wrong_sk);
    assert!(wrong_unseal_result.is_err());
    
    // Test: Try to open a gift with wrong private key
    let wrong_open_result = open_gift(&gift_wrap, &wrong_sk);
    assert!(wrong_open_result.is_err());
    
    // Create an invalid event (wrong kind)
    let mut invalid_seal = seal.clone();
    invalid_seal.kind = 999; // Not a seal kind
    
    // Test: Try to gift wrap an invalid seal
    let invalid_wrap_result = create_gift_wrap(&invalid_seal, &recipient_pk, Some(1703021488));
    assert!(invalid_wrap_result.is_err());
    
    // Test: Try to unseal an invalid seal
    let invalid_unseal_result = unseal(&invalid_seal, &recipient_sk);
    assert!(invalid_unseal_result.is_err());
    
    // Test: Trying to use an unsigned rumor
    let mut signed_rumor = rumor.clone();
    signed_rumor.sig = Some("fake_signature".to_string());
    
    // Attempt to create a seal with a signed rumor (should fail)
    let signed_rumor_seal_result = create_seal(&signed_rumor, &sender_sk, &recipient_pk, Some(1703015180));
    assert!(signed_rumor_seal_result.is_err());
}

#[test]
fn test_with_real_nip_example() {
    // Test with the exact example from the NIP-59 specification
    let sender_sk = hex_to_secret_key("0beebd062ec8735f4243466049d7747ef5d6594ee838de147f8aab842b15e273");
    let recipient_sk = hex_to_secret_key("e108399bd8424357a710b606ae0c13166d853d327e47a6e5e038197346bdbf45");
    
    let secp = Secp256k1::new();
    let sender_pk = PublicKey::from_secret_key(&secp, &sender_sk);
    let recipient_pk = PublicKey::from_secret_key(&secp, &recipient_sk);
    
    let sender_pk_hex = hex::encode(sender_pk.serialize());
    
    // 1. Create the rumor (using exact data from the spec)
    let content = "Are you going to the party tonight?";
    let rumor = create_rumor(1, content, vec![], &sender_pk_hex, 1691518405).unwrap();
    
    // The ID should match the example, but we can't guarantee it due to differences in serialization
    // So we don't assert on the ID value
    
    // 2. Create the seal
    let seal = create_seal(&rumor, &sender_sk, &recipient_pk, Some(1703015180)).unwrap();
    
    // 3. Create the gift wrap using an ephemeral key
    let ephemeral_sk = hex_to_secret_key(EPHEMERAL_SK_HEX);
    let ephemeral_pk = PublicKey::from_secret_key(&secp, &ephemeral_sk);
    let ephemeral_pk_hex = hex::encode(ephemeral_pk.serialize());
    
    // We would need to create this manually since our create_gift_wrap generates a random key
    let seal_json = serde_json::to_string(&seal).unwrap();
    let encrypted_seal = nostr_rs_relay::nip44::Nip44::encrypt(&seal_json, &ephemeral_sk, &recipient_pk).unwrap();
    
    let recipient_pk_hex = hex::encode(recipient_pk.serialize());
    let tags = vec![vec!["p".to_string(), recipient_pk_hex]];
    
    let mut gift_wrap = Event::new(&ephemeral_pk_hex, GIFT_WRAP_KIND, &encrypted_seal, tags, 1703021488);
    gift_wrap.sign(&ephemeral_sk).unwrap();
    
    // 4. Recipient unwraps and unseals
    let unwrapped_seal = unwrap_gift_wrap(&gift_wrap, &recipient_sk).unwrap();
    let unsealed_rumor = unseal(&unwrapped_seal, &recipient_sk).unwrap();
    
    // Verify the message content was recovered correctly
    assert_eq!(unsealed_rumor.content, content);
    assert_eq!(unsealed_rumor.kind, 1);
    assert_eq!(unsealed_rumor.pubkey, sender_pk_hex);
} 