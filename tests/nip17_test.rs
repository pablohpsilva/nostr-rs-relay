use nostr_rs_relay::nip17::{
    self, DirectMessage, FileMessage,
    DIRECT_MESSAGE_KIND, FILE_MESSAGE_KIND
};
use nostr_rs_relay::nip59;
use secp256k1::{SecretKey, PublicKey, Secp256k1};
use hex;

/// Helper function to create a secret key from a hex string
fn hex_to_secret_key(hex_str: &str) -> SecretKey {
    let bytes = hex::decode(hex_str).unwrap();
    SecretKey::from_slice(&bytes).unwrap()
}

/// Test keys for all tests
struct TestKeys {
    sender_sk: SecretKey,
    recipient_sk: SecretKey,
    sender_pk: PublicKey,
    recipient_pk: PublicKey,
}

impl TestKeys {
    fn new() -> Self {
        // Use consistent test keys
        let sender_sk = hex_to_secret_key("0beebd062ec8735f4243466049d7747ef5d6594ee838de147f8aab842b15e273");
        let recipient_sk = hex_to_secret_key("e108399bd8424357a710b606ae0c13166d853d327e47a6e5e038197346bdbf45");
        
        let secp = Secp256k1::new();
        let sender_pk = PublicKey::from_secret_key(&secp, &sender_sk);
        let recipient_pk = PublicKey::from_secret_key(&secp, &recipient_sk);
        
        Self {
            sender_sk,
            recipient_sk,
            sender_pk,
            recipient_pk,
        }
    }
}

#[test]
fn test_create_direct_message() {
    let keys = TestKeys::new();
    
    // Test with minimal parameters
    let message_content = "Hello, this is a test message!";
    let gift_wraps = nip17::create_direct_message(
        message_content,
        &keys.sender_sk,
        &[keys.recipient_pk],
        None,
        None,
    ).unwrap();
    
    // Should create wraps for both sender and recipient
    assert_eq!(gift_wraps.len(), 2);
    
    // Gift wraps should have kind 1059
    assert_eq!(gift_wraps[0].kind, 1059);
    assert_eq!(gift_wraps[1].kind, 1059);
    
    // Both should have p tags
    assert!(gift_wraps[0].tags.iter().any(|tag| !tag.is_empty() && tag[0] == "p"));
    assert!(gift_wraps[1].tags.iter().any(|tag| !tag.is_empty() && tag[0] == "p"));
}

#[test]
fn test_create_and_open_direct_message() {
    let keys = TestKeys::new();
    
    // Create a direct message with all optional parameters
    let message_content = "Hello, this is a test message!";
    let reply_id = "abcdef123456789";
    let subject = "Test Subject";
    
    let gift_wraps = nip17::create_direct_message(
        message_content,
        &keys.sender_sk,
        &[keys.recipient_pk],
        Some(reply_id),
        Some(subject),
    ).unwrap();
    
    // Open the message as recipient
    let dm = nip17::open_direct_message(&gift_wraps[0], &keys.recipient_sk).unwrap();
    
    // Verify message content
    assert_eq!(dm.content, message_content);
    
    // Verify subject
    let extracted_subject = nip17::get_subject(&dm);
    assert_eq!(extracted_subject, Some(subject.to_string()));
    
    // Verify reply ID
    let extracted_reply = nip17::get_reply_to(&dm);
    assert_eq!(extracted_reply, Some(reply_id.to_string()));
    
    // Verify recipients
    let recipients = nip17::get_recipients(&dm);
    assert!(recipients.contains(&hex::encode(keys.recipient_pk.serialize())));
}

#[test]
fn test_direct_message_multiple_recipients() {
    let keys = TestKeys::new();
    
    // Create a second recipient
    let second_recipient_sk = hex_to_secret_key("f1398b4bbc4755c0045297f4056985117dc2886d66258966ca65e8e92a0c571e");
    let secp = Secp256k1::new();
    let second_recipient_pk = PublicKey::from_secret_key(&secp, &second_recipient_sk);
    
    // Create a direct message with multiple recipients
    let message_content = "Hello to both of you!";
    let gift_wraps = nip17::create_direct_message(
        message_content,
        &keys.sender_sk,
        &[keys.recipient_pk, second_recipient_pk],
        None,
        None,
    ).unwrap();
    
    // Should create 3 wraps (one for each recipient plus the sender)
    assert_eq!(gift_wraps.len(), 3);
    
    // First recipient should be able to decrypt
    let dm1 = nip17::open_direct_message(&gift_wraps[0], &keys.recipient_sk).unwrap();
    assert_eq!(dm1.content, message_content);
    
    // Second recipient should be able to decrypt
    let dm2 = nip17::open_direct_message(&gift_wraps[1], &second_recipient_sk).unwrap();
    assert_eq!(dm2.content, message_content);
    
    // The direct message should have p tags for both recipients
    let recipients = nip17::get_recipients(&dm1);
    assert_eq!(recipients.len(), 2);
    assert!(recipients.contains(&hex::encode(keys.recipient_pk.serialize())));
    assert!(recipients.contains(&hex::encode(second_recipient_pk.serialize())));
}

#[test]
fn test_create_file_message() {
    let keys = TestKeys::new();
    
    // Create a file message with minimal required parameters
    let file_url = "https://example.com/encrypted-image.jpg";
    let file_hash = "e8fbf31e397a9325ea55cacb486519f28c7dc7339dbf1d0b77b124f5977008d7";
    
    let gift_wraps = nip17::create_file_message(
        file_url,
        "image/jpeg",
        "aes-gcm",
        "aabbccddeeff00112233445566778899",
        "112233445566778899aabbcc",
        file_hash,
        &keys.sender_sk,
        &[keys.recipient_pk],
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    ).unwrap();
    
    // Should create wraps for both sender and recipient
    assert_eq!(gift_wraps.len(), 2);
    
    // Gift wraps should have kind 1059
    assert_eq!(gift_wraps[0].kind, 1059);
    assert_eq!(gift_wraps[1].kind, 1059);
}

#[test]
fn test_create_and_open_file_message() {
    let keys = TestKeys::new();
    
    // Create a file message with all optional parameters
    let file_url = "https://example.com/encrypted-image.jpg";
    let file_hash = "e8fbf31e397a9325ea55cacb486519f28c7dc7339dbf1d0b77b124f5977008d7";
    let file_size = 1024 * 1024; // 1MB
    let dimensions = (800, 600);
    let blurhash = "LGF5.+Yk^6oi%2NHM%NH%2NH";
    let thumb_url = "https://example.com/encrypted-thumbnail.jpg";
    let fallback_urls = vec!["https://backup.example.com/encrypted-image.jpg".to_string()];
    let subject = "Encrypted Image";
    let reply_id = "previous_message_id";
    
    let gift_wraps = nip17::create_file_message(
        file_url,
        "image/jpeg",
        "aes-gcm",
        "aabbccddeeff00112233445566778899",
        "112233445566778899aabbcc",
        file_hash,
        &keys.sender_sk,
        &[keys.recipient_pk],
        Some(reply_id),
        Some(subject),
        Some(file_size),
        Some(dimensions),
        Some(blurhash),
        Some(thumb_url),
        Some(fallback_urls.clone()),
    ).unwrap();
    
    // Open the message as recipient
    let fm = nip17::open_file_message(&gift_wraps[0], &keys.recipient_sk).unwrap();
    
    // Verify file URL
    assert_eq!(fm.content, file_url);
    
    // Check subject
    let extracted_subject = nip17::get_subject(&DirectMessage { content: fm.content.clone(), tags: fm.tags.clone() });
    assert_eq!(extracted_subject, Some(subject.to_string()));
    
    // Check reply_id
    let extracted_reply = nip17::get_reply_to(&DirectMessage { content: fm.content.clone(), tags: fm.tags.clone() });
    assert_eq!(extracted_reply, Some(reply_id.to_string()));
    
    // Check required file metadata tags
    let file_type = fm.tags.iter()
        .find(|tag| !tag.is_empty() && tag[0] == "file-type")
        .and_then(|tag| tag.get(1).cloned());
    assert_eq!(file_type, Some("image/jpeg".to_string()));
    
    let encryption_algorithm = fm.tags.iter()
        .find(|tag| !tag.is_empty() && tag[0] == "encryption-algorithm")
        .and_then(|tag| tag.get(1).cloned());
    assert_eq!(encryption_algorithm, Some("aes-gcm".to_string()));
    
    let x_tag = fm.tags.iter()
        .find(|tag| !tag.is_empty() && tag[0] == "x")
        .and_then(|tag| tag.get(1).cloned());
    assert_eq!(x_tag, Some(file_hash.to_string()));
    
    // Check optional metadata tags
    let size_tag = fm.tags.iter()
        .find(|tag| !tag.is_empty() && tag[0] == "size")
        .and_then(|tag| tag.get(1).cloned());
    assert_eq!(size_tag, Some(file_size.to_string()));
    
    let dim_tag = fm.tags.iter()
        .find(|tag| !tag.is_empty() && tag[0] == "dim")
        .and_then(|tag| tag.get(1).cloned());
    assert_eq!(dim_tag, Some(format!("{}x{}", dimensions.0, dimensions.1)));
    
    let blurhash_tag = fm.tags.iter()
        .find(|tag| !tag.is_empty() && tag[0] == "blurhash")
        .and_then(|tag| tag.get(1).cloned());
    assert_eq!(blurhash_tag, Some(blurhash.to_string()));
    
    let thumb_tag = fm.tags.iter()
        .find(|tag| !tag.is_empty() && tag[0] == "thumb")
        .and_then(|tag| tag.get(1).cloned());
    assert_eq!(thumb_tag, Some(thumb_url.to_string()));
    
    // Check fallback tags
    let fallback_tags: Vec<String> = fm.tags.iter()
        .filter(|tag| !tag.is_empty() && tag[0] == "fallback")
        .filter_map(|tag| tag.get(1).cloned())
        .collect();
    assert_eq!(fallback_tags, fallback_urls);
}

#[test]
fn test_error_handling() {
    let keys = TestKeys::new();
    
    // Test empty recipients list
    let result = nip17::create_direct_message(
        "Test message",
        &keys.sender_sk,
        &[],
        None,
        None,
    );
    assert!(result.is_err());
    
    // Test opening a message with wrong key
    let message_content = "Hello, this is a test message!";
    let gift_wraps = nip17::create_direct_message(
        message_content,
        &keys.sender_sk,
        &[keys.recipient_pk],
        None,
        None,
    ).unwrap();
    
    // Try to open with sender's key (wrong key for this gift wrap)
    let result = nip17::open_direct_message(&gift_wraps[0], &keys.sender_sk);
    assert!(result.is_err());
    
    // Create a direct message gift wrap
    let dm_gift_wraps = nip17::create_direct_message(
        "Test message",
        &keys.sender_sk,
        &[keys.recipient_pk],
        None,
        None,
    ).unwrap();
    
    // Try to open a direct message as a file message
    let result = nip17::open_file_message(&dm_gift_wraps[0], &keys.recipient_sk);
    assert!(result.is_err());
}

#[test]
fn test_message_round_trip_with_sender_copy() {
    let keys = TestKeys::new();
    
    // Create a direct message
    let message_content = "This message should be readable by both sender and recipient";
    let gift_wraps = nip17::create_direct_message(
        message_content,
        &keys.sender_sk,
        &[keys.recipient_pk],
        None,
        None,
    ).unwrap();
    
    // There should be two gift wraps
    assert_eq!(gift_wraps.len(), 2);
    
    // First is for the recipient
    let recipient_dm = nip17::open_direct_message(&gift_wraps[0], &keys.recipient_sk).unwrap();
    assert_eq!(recipient_dm.content, message_content);
    
    // Second is for the sender
    let sender_dm = nip17::open_direct_message(&gift_wraps[1], &keys.sender_sk).unwrap();
    assert_eq!(sender_dm.content, message_content);
}

#[test]
fn test_direct_message_tags() {
    let keys = TestKeys::new();
    
    // Create a direct message with custom tags
    let message_content = "Hello with tags!";
    let subject = "Custom Subject";
    let reply_id = "prev_message_id";
    
    let gift_wraps = nip17::create_direct_message(
        message_content,
        &keys.sender_sk,
        &[keys.recipient_pk],
        Some(reply_id),
        Some(subject),
    ).unwrap();
    
    // Open the message
    let dm = nip17::open_direct_message(&gift_wraps[0], &keys.recipient_sk).unwrap();
    
    // Get all tag types
    let e_tags: Vec<Vec<String>> = dm.tags.iter()
        .filter(|tag| !tag.is_empty() && tag[0] == "e")
        .cloned()
        .collect();
    
    let p_tags: Vec<Vec<String>> = dm.tags.iter()
        .filter(|tag| !tag.is_empty() && tag[0] == "p")
        .cloned()
        .collect();
    
    let subject_tags: Vec<Vec<String>> = dm.tags.iter()
        .filter(|tag| !tag.is_empty() && tag[0] == "subject")
        .cloned()
        .collect();
    
    // Verify tags
    assert_eq!(e_tags.len(), 1);
    assert_eq!(e_tags[0][1], reply_id);
    
    assert_eq!(p_tags.len(), 1);
    assert_eq!(p_tags[0][1], hex::encode(keys.recipient_pk.serialize()));
    
    assert_eq!(subject_tags.len(), 1);
    assert_eq!(subject_tags[0][1], subject);
} 