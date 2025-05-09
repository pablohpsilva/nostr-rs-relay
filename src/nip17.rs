/// NIP-17: Private Direct Messages
///
/// This module implements private direct messaging using NIP-44 encryption and 
/// NIP-59 gift wraps and seals.
///
/// Event kinds:
/// - Kind 14: Direct message
/// - Kind 15: File message
use std::time::{SystemTime, UNIX_EPOCH};
use rand::Rng;
use serde::{Serialize, Deserialize};
use secp256k1::{SecretKey, PublicKey};
use thiserror::Error;

use crate::nip44;
use crate::nip59;
use crate::error::Result as NostrResult;

/// Error types for NIP-17 operations
#[derive(Debug, Error)]
pub enum Error {
    /// Error from NIP-44 operations
    #[error("NIP-44 error: {0}")]
    Nip44Error(#[from] nip44::Error),

    /// Error from NIP-59 operations
    #[error("NIP-59 error: {0}")]
    Nip59Error(#[from] nip59::Error),

    /// Error with event creation
    #[error("Event error: {0}")]
    EventError(String),

    /// Missing field
    #[error("Missing field: {0}")]
    MissingField(String),
}

/// Result type for NIP-17 operations
pub type Result<T> = std::result::Result<T, Error>;

/// Kinds for NIP-17 events
pub const DIRECT_MESSAGE_KIND: u32 = 14;
pub const FILE_MESSAGE_KIND: u32 = 15;

/// Direct message event content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectMessage {
    pub content: String,
    pub tags: Vec<Vec<String>>,
}

/// File message event content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMessage {
    pub content: String,
    pub tags: Vec<Vec<String>>,
}

/// Generate a random timestamp up to 2 days in the past
fn random_past_timestamp() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let two_days_in_secs = 2 * 24 * 60 * 60;
    let random_offset = rand::thread_rng().gen_range(0..two_days_in_secs);
    now - random_offset
}

/// Create an encrypted direct message
pub fn create_direct_message(
    content: &str,
    sender_sk: &SecretKey,
    recipients: &[PublicKey],
    reply_to: Option<&str>,
    subject: Option<&str>,
) -> Result<Vec<nip59::GiftWrap>> {
    if recipients.is_empty() {
        return Err(Error::EventError("At least one recipient is required".to_string()));
    }

    // Build tags
    let mut tags = Vec::new();
    
    // Add recipient tags
    for recipient in recipients {
        let recipient_hex = hex::encode(recipient.serialize());
        tags.push(vec!["p".to_string(), recipient_hex]);
    }
    
    // Add reply tag if specified
    if let Some(event_id) = reply_to {
        tags.push(vec!["e".to_string(), event_id.to_string()]);
    }
    
    // Add subject tag if specified
    if let Some(subject_text) = subject {
        tags.push(vec!["subject".to_string(), subject_text.to_string()]);
    }
    
    // Create the unsigned direct message event (rumor)
    let sender_pubkey = hex::encode(PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), sender_sk).serialize());
    let created_at = random_past_timestamp();
    
    let direct_message = nip59::create_rumor(
        DIRECT_MESSAGE_KIND,
        content,
        tags,
        &sender_pubkey,
        created_at,
    ).map_err(Error::Nip59Error)?;
    
    // Create sealed and gift-wrapped messages for each recipient and the sender
    let mut gift_wraps = Vec::new();
    
    // Include the sender in the list of recipients to get a copy
    let mut all_recipients = recipients.to_vec();
    let sender_pk = PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), sender_sk);
    if !all_recipients.contains(&sender_pk) {
        all_recipients.push(sender_pk);
    }
    
    // Create gift wraps for each recipient
    for recipient_pk in all_recipients {
        // Create a seal
        let seal = nip59::create_seal(
            &direct_message,
            sender_sk,
            &recipient_pk,
            None, // Use random timestamp
        ).map_err(Error::Nip59Error)?;
        
        // Create a gift wrap
        let (gift_wrap, _) = nip59::create_gift_wrap(
            &seal,
            &recipient_pk,
            None, // Use random timestamp
        ).map_err(Error::Nip59Error)?;
        
        gift_wraps.push(gift_wrap);
    }
    
    Ok(gift_wraps)
}

/// Create an encrypted file message
pub fn create_file_message(
    file_url: &str,
    file_type: &str,
    encryption_algorithm: &str,
    decryption_key: &str,
    decryption_nonce: &str,
    file_hash: &str,
    sender_sk: &SecretKey,
    recipients: &[PublicKey],
    reply_to: Option<&str>,
    subject: Option<&str>,
    size: Option<u64>,
    dimensions: Option<(u32, u32)>,
    blurhash: Option<&str>,
    thumb_url: Option<&str>,
    fallback_urls: Option<Vec<String>>,
) -> Result<Vec<nip59::GiftWrap>> {
    if recipients.is_empty() {
        return Err(Error::EventError("At least one recipient is required".to_string()));
    }

    // Build tags
    let mut tags = Vec::new();
    
    // Add recipient tags
    for recipient in recipients {
        let recipient_hex = hex::encode(recipient.serialize());
        tags.push(vec!["p".to_string(), recipient_hex]);
    }
    
    // Add reply tag if specified
    if let Some(event_id) = reply_to {
        tags.push(vec!["e".to_string(), event_id.to_string(), "reply".to_string()]);
    }
    
    // Add subject tag if specified
    if let Some(subject_text) = subject {
        tags.push(vec!["subject".to_string(), subject_text.to_string()]);
    }
    
    // Add file metadata tags
    tags.push(vec!["file-type".to_string(), file_type.to_string()]);
    tags.push(vec!["encryption-algorithm".to_string(), encryption_algorithm.to_string()]);
    tags.push(vec!["decryption-key".to_string(), decryption_key.to_string()]);
    tags.push(vec!["decryption-nonce".to_string(), decryption_nonce.to_string()]);
    tags.push(vec!["x".to_string(), file_hash.to_string()]);
    
    // Add optional tags
    if let Some(size_bytes) = size {
        tags.push(vec!["size".to_string(), size_bytes.to_string()]);
    }
    
    if let Some((width, height)) = dimensions {
        tags.push(vec!["dim".to_string(), format!("{}x{}", width, height)]);
    }
    
    if let Some(hash) = blurhash {
        tags.push(vec!["blurhash".to_string(), hash.to_string()]);
    }
    
    if let Some(thumb) = thumb_url {
        tags.push(vec!["thumb".to_string(), thumb.to_string()]);
    }
    
    if let Some(fallbacks) = fallback_urls {
        for fallback in fallbacks {
            tags.push(vec!["fallback".to_string(), fallback]);
        }
    }
    
    // Create the unsigned file message event (rumor)
    let sender_pubkey = hex::encode(PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), sender_sk).serialize());
    let created_at = random_past_timestamp();
    
    let file_message = nip59::create_rumor(
        FILE_MESSAGE_KIND,
        file_url,
        tags,
        &sender_pubkey,
        created_at,
    ).map_err(Error::Nip59Error)?;
    
    // Create sealed and gift-wrapped messages for each recipient and the sender
    let mut gift_wraps = Vec::new();
    
    // Include the sender in the list of recipients to get a copy
    let mut all_recipients = recipients.to_vec();
    let sender_pk = PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), sender_sk);
    if !all_recipients.contains(&sender_pk) {
        all_recipients.push(sender_pk);
    }
    
    // Create gift wraps for each recipient
    for recipient_pk in all_recipients {
        // Create a seal
        let seal = nip59::create_seal(
            &file_message,
            sender_sk,
            &recipient_pk,
            None, // Use random timestamp
        ).map_err(Error::Nip59Error)?;
        
        // Create a gift wrap
        let (gift_wrap, _) = nip59::create_gift_wrap(
            &seal,
            &recipient_pk,
            None, // Use random timestamp
        ).map_err(Error::Nip59Error)?;
        
        gift_wraps.push(gift_wrap);
    }
    
    Ok(gift_wraps)
}

/// Open and decrypt a NIP-17 direct message
pub fn open_direct_message(gift_wrap: &nip59::GiftWrap, recipient_sk: &SecretKey) -> Result<DirectMessage> {
    // Unwrap and unseal the gift wrap
    let rumor = nip59::open_gift(gift_wrap, recipient_sk).map_err(Error::Nip59Error)?;
    
    // Verify it's a direct message
    if rumor.kind != DIRECT_MESSAGE_KIND {
        return Err(Error::EventError(format!(
            "Invalid kind for direct message: {}, expected {}",
            rumor.kind, DIRECT_MESSAGE_KIND
        )));
    }
    
    Ok(DirectMessage {
        content: rumor.content,
        tags: rumor.tags,
    })
}

/// Open and decrypt a NIP-17 file message
pub fn open_file_message(gift_wrap: &nip59::GiftWrap, recipient_sk: &SecretKey) -> Result<FileMessage> {
    // Unwrap and unseal the gift wrap
    let rumor = nip59::open_gift(gift_wrap, recipient_sk).map_err(Error::Nip59Error)?;
    
    // Verify it's a file message
    if rumor.kind != FILE_MESSAGE_KIND {
        return Err(Error::EventError(format!(
            "Invalid kind for file message: {}, expected {}",
            rumor.kind, FILE_MESSAGE_KIND
        )));
    }
    
    Ok(FileMessage {
        content: rumor.content,
        tags: rumor.tags,
    })
}

/// Extract recipients from a direct message or file message
pub fn get_recipients(message: &DirectMessage) -> Vec<String> {
    message.tags.iter()
        .filter(|tag| !tag.is_empty() && tag[0] == "p")
        .filter_map(|tag| tag.get(1).cloned())
        .collect()
}

/// Extract subject from a direct message or file message
pub fn get_subject(message: &DirectMessage) -> Option<String> {
    message.tags.iter()
        .filter(|tag| !tag.is_empty() && tag[0] == "subject")
        .filter_map(|tag| tag.get(1).cloned())
        .next()
}

/// Extract parent message ID from a direct message or file message
pub fn get_reply_to(message: &DirectMessage) -> Option<String> {
    message.tags.iter()
        .filter(|tag| !tag.is_empty() && tag[0] == "e")
        .filter_map(|tag| tag.get(1).cloned())
        .next()
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::Secp256k1;
    
    fn hex_to_secret_key(hex_str: &str) -> SecretKey {
        let bytes = hex::decode(hex_str).unwrap();
        SecretKey::from_slice(&bytes).unwrap()
    }
    
    #[test]
    fn test_create_and_open_direct_message() {
        // Test keys
        let sender_sk = hex_to_secret_key("0beebd062ec8735f4243466049d7747ef5d6594ee838de147f8aab842b15e273");
        let recipient_sk = hex_to_secret_key("e108399bd8424357a710b606ae0c13166d853d327e47a6e5e038197346bdbf45");
        
        let secp = Secp256k1::new();
        let recipient_pk = PublicKey::from_secret_key(&secp, &recipient_sk);
        
        // Create a direct message
        let message_content = "Hello, this is a test message!";
        let gift_wraps = create_direct_message(
            message_content,
            &sender_sk,
            &[recipient_pk],
            None,
            Some("Test Subject"),
        ).unwrap();
        
        // There should be two gift wraps (one for recipient, one for sender)
        assert_eq!(gift_wraps.len(), 2);
        
        // Open the message as recipient
        let dm = open_direct_message(&gift_wraps[0], &recipient_sk).unwrap();
        
        // Verify message content
        assert_eq!(dm.content, message_content);
        
        // Verify subject
        let subject = get_subject(&dm);
        assert_eq!(subject, Some("Test Subject".to_string()));
    }
    
    #[test]
    fn test_create_and_open_file_message() {
        // Test keys
        let sender_sk = hex_to_secret_key("0beebd062ec8735f4243466049d7747ef5d6594ee838de147f8aab842b15e273");
        let recipient_sk = hex_to_secret_key("e108399bd8424357a710b606ae0c13166d853d327e47a6e5e038197346bdbf45");
        
        let secp = Secp256k1::new();
        let recipient_pk = PublicKey::from_secret_key(&secp, &recipient_sk);
        
        // Create a file message
        let file_url = "https://example.com/encrypted-image.jpg";
        let file_hash = "e8fbf31e397a9325ea55cacb486519f28c7dc7339dbf1d0b77b124f5977008d7";
        
        let gift_wraps = create_file_message(
            file_url,
            "image/jpeg",
            "aes-gcm",
            "aabbccddeeff00112233445566778899",
            "112233445566778899aabbcc",
            file_hash,
            &sender_sk,
            &[recipient_pk],
            None,
            Some("Image Subject"),
            Some(1024 * 1024), // 1MB
            Some((800, 600)),
            Some("LGF5.+Yk^6oi%2NHM%NH%2NH"),
            Some("https://example.com/encrypted-thumbnail.jpg"),
            Some(vec!["https://backup.example.com/encrypted-image.jpg".to_string()]),
        ).unwrap();
        
        // There should be two gift wraps (one for recipient, one for sender)
        assert_eq!(gift_wraps.len(), 2);
        
        // Open the message as recipient
        let fm = open_file_message(&gift_wraps[0], &recipient_sk).unwrap();
        
        // Verify file URL
        assert_eq!(fm.content, file_url);
        
        // Verify subject
        let subject = get_subject(&FileMessage { content: fm.content.clone(), tags: fm.tags.clone() });
        assert_eq!(subject, Some("Image Subject".to_string()));
        
        // Verify file metadata tags exist
        let file_type = fm.tags.iter()
            .find(|tag| !tag.is_empty() && tag[0] == "file-type")
            .and_then(|tag| tag.get(1).cloned());
        assert_eq!(file_type, Some("image/jpeg".to_string()));
        
        let x_tag = fm.tags.iter()
            .find(|tag| !tag.is_empty() && tag[0] == "x")
            .and_then(|tag| tag.get(1).cloned());
        assert_eq!(x_tag, Some(file_hash.to_string()));
    }
} 