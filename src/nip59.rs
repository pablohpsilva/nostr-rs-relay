/// NIP-59: Gift Wrap
///
/// This module implements the Gift Wrap protocol as specified in NIP-59.
/// It provides functionality for encapsulating any nostr event to obscure metadata.
///
/// The protocol uses three main concepts:
/// - Rumor: An unsigned nostr event
/// - Seal (kind 13): Wraps and encrypts a rumor
/// - Gift Wrap (kind 1059): Wraps and encrypts a seal with a one-time key
///
/// This implementation relies on the NIP-44 implementation for encryption.
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use secp256k1::{SecretKey, PublicKey, Secp256k1, Message, Schnorr};
use rand::{rngs::OsRng, RngCore};
use thiserror::Error;
use bitcoin_hashes::{sha256, Hash};
use crate::nip44;

/// Event kinds for NIP-59
pub const SEAL_KIND: u32 = 13;
pub const GIFT_WRAP_KIND: u32 = 1059;

/// Error types specific to NIP-59 operations
#[derive(Debug, Error)]
pub enum Error {
    /// Error occurred during encryption/decryption
    #[error("Encryption error: {0}")]
    EncryptionError(#[from] nip44::Error),
    
    /// Error with JSON serialization/deserialization
    #[error("JSON error: {0}")]
    JsonError(String),
    
    /// Invalid event data
    #[error("Invalid event data: {0}")]
    InvalidEvent(String),
    
    /// Missing required field
    #[error("Missing required field: {0}")]
    MissingField(String),
    
    /// Invalid kind for the specific operation
    #[error("Invalid event kind, expected {expected} but got {actual}")]
    InvalidKind { expected: u32, actual: u32 },
    
    /// Error calculating event id
    #[error("Event id calculation error: {0}")]
    IdError(String),
    
    /// Error signing event
    #[error("Event signing error: {0}")]
    SigningError(String),
}

/// Type alias for Result with NIP-59 Error
pub type Result<T> = std::result::Result<T, Error>;

/// Basic nostr event structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

/// Represents an unsigned event (Rumor)
pub type Rumor = Event;

/// Represents a Seal (kind 13)
pub type Seal = Event;

/// Represents a Gift Wrap (kind 1059)
pub type GiftWrap = Event;

impl Event {
    /// Create a new event with the given data
    pub fn new(pubkey: &str, kind: u32, content: &str, tags: Vec<Vec<String>>, created_at: u64) -> Self {
        Event {
            id: String::new(), // Will be calculated later
            pubkey: pubkey.to_string(),
            created_at,
            kind,
            tags,
            content: content.to_string(),
            sig: None,
        }
    }
    
    /// Calculate the SHA-256 hash for the event ID
    pub fn calculate_id(&self) -> Result<String> {
        // Create a clone without the signature for hashing
        let event_for_id = Event {
            id: String::new(),
            pubkey: self.pubkey.clone(),
            created_at: self.created_at,
            kind: self.kind,
            tags: self.tags.clone(),
            content: self.content.clone(),
            sig: None,
        };
        
        // Serialize to JSON in canonical format for hashing
        let serialized = serde_json::to_string(&[
            0, // Version
            event_for_id.pubkey,
            event_for_id.created_at,
            event_for_id.kind,
            event_for_id.tags,
            event_for_id.content,
        ]).map_err(|e| Error::JsonError(e.to_string()))?;
        
        // Calculate SHA-256
        let hash = sha256::Hash::hash(serialized.as_bytes());
        Ok(hex::encode(hash))
    }
    
    /// Sign the event with the provided private key
    pub fn sign(&mut self, secret_key: &SecretKey) -> Result<()> {
        // Calculate ID first
        self.id = self.calculate_id()?;
        
        // Convert the id to a Message for signing
        let id_bytes = hex::decode(&self.id).map_err(|e| Error::IdError(e.to_string()))?;
        let message = Message::from_slice(&id_bytes).map_err(|e| Error::SigningError(e.to_string()))?;
        
        // Sign the message
        let secp = Secp256k1::new();
        let sig = secp.sign_schnorr(&message, secret_key);
        
        // Convert signature to hex
        self.sig = Some(hex::encode(sig.as_ref()));
        
        Ok(())
    }
    
    /// Verify the event signature
    pub fn verify(&self) -> Result<bool> {
        // Check if signature exists
        let sig_str = self.sig.as_ref().ok_or_else(|| Error::MissingField("sig".to_string()))?;
        
        // Parse the signature
        let sig_bytes = hex::decode(sig_str).map_err(|e| Error::SigningError(e.to_string()))?;
        let sig = Schnorr::from_slice(&sig_bytes).map_err(|e| Error::SigningError(e.to_string()))?;
        
        // Parse the pubkey
        let pubkey_bytes = hex::decode(&self.pubkey).map_err(|e| Error::InvalidEvent(e.to_string()))?;
        let pubkey = PublicKey::from_slice(&pubkey_bytes).map_err(|e| Error::InvalidEvent(e.to_string()))?;
        
        // Parse the ID as a message
        let id_bytes = hex::decode(&self.id).map_err(|e| Error::IdError(e.to_string()))?;
        let message = Message::from_slice(&id_bytes).map_err(|e| Error::SigningError(e.to_string()))?;
        
        // Verify the signature
        let secp = Secp256k1::new();
        let result = secp.verify_schnorr(&sig, &message, &pubkey).is_ok();
        
        Ok(result)
    }
}

/// Creates a rumor event (unsigned) from an event template
pub fn create_rumor(kind: u32, content: &str, tags: Vec<Vec<String>>, pubkey: &str, created_at: u64) -> Result<Rumor> {
    let mut rumor = Event::new(pubkey, kind, content, tags, created_at);
    rumor.id = rumor.calculate_id()?;
    Ok(rumor)
}

/// Creates a seal (kind 13) containing an encrypted rumor
pub fn create_seal(rumor: &Rumor, sender_sk: &SecretKey, recipient_pk: &PublicKey, created_at: Option<u64>) -> Result<Seal> {
    // Verify the rumor is not signed
    if rumor.sig.is_some() {
        return Err(Error::InvalidEvent("Rumor must not be signed".to_string()));
    }
    
    // Serialize the rumor to JSON
    let rumor_json = serde_json::to_string(rumor).map_err(|e| Error::JsonError(e.to_string()))?;
    
    // Encrypt the rumor using NIP-44
    let encrypted_rumor = nip44::Nip44::encrypt(&rumor_json, sender_sk, recipient_pk)?;
    
    // Create a seal event
    let secp = Secp256k1::new();
    let sender_pubkey = PublicKey::from_secret_key(&secp, sender_sk);
    let sender_pubkey_hex = hex::encode(sender_pubkey.serialize());
    
    // Use provided timestamp or generate a random one
    let timestamp = created_at.unwrap_or_else(|| {
        const TWO_DAYS: u64 = 2 * 24 * 60 * 60;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now - (rand::random::<u64>() % TWO_DAYS)
    });
    
    // Create and sign the seal
    let mut seal = Event::new(&sender_pubkey_hex, SEAL_KIND, &encrypted_rumor, vec![], timestamp);
    seal.sign(sender_sk)?;
    
    Ok(seal)
}

/// Creates a gift wrap (kind 1059) containing an encrypted seal
pub fn create_gift_wrap(seal: &Seal, recipient_pk: &PublicKey, created_at: Option<u64>) -> Result<(GiftWrap, SecretKey)> {
    // Verify the seal is correctly formed
    if seal.kind != SEAL_KIND {
        return Err(Error::InvalidKind { expected: SEAL_KIND, actual: seal.kind });
    }
    if seal.sig.is_none() {
        return Err(Error::MissingField("sig".to_string()));
    }
    
    // Serialize the seal to JSON
    let seal_json = serde_json::to_string(seal).map_err(|e| Error::JsonError(e.to_string()))?;
    
    // Generate a random one-time-use key
    let mut random_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut random_bytes);
    let ephemeral_sk = SecretKey::from_slice(&random_bytes).map_err(|e| Error::SigningError(e.to_string()))?;
    
    // Get the pubkey for the ephemeral key
    let secp = Secp256k1::new();
    let ephemeral_pk = PublicKey::from_secret_key(&secp, &ephemeral_sk);
    let ephemeral_pk_hex = hex::encode(ephemeral_pk.serialize());
    
    // Encrypt the seal using NIP-44 with the ephemeral key
    let encrypted_seal = nip44::Nip44::encrypt(&seal_json, &ephemeral_sk, recipient_pk)?;
    
    // Use provided timestamp or generate a random one
    let timestamp = created_at.unwrap_or_else(|| {
        const TWO_DAYS: u64 = 2 * 24 * 60 * 60;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now - (rand::random::<u64>() % TWO_DAYS)
    });
    
    // Create tags with recipient pubkey
    let recipient_pk_hex = hex::encode(recipient_pk.serialize());
    let tags = vec![vec!["p".to_string(), recipient_pk_hex]];
    
    // Create and sign the gift wrap
    let mut gift_wrap = Event::new(&ephemeral_pk_hex, GIFT_WRAP_KIND, &encrypted_seal, tags, timestamp);
    gift_wrap.sign(&ephemeral_sk)?;
    
    Ok((gift_wrap, ephemeral_sk))
}

/// Unwraps a gift wrap (kind 1059) to reveal the seal inside
pub fn unwrap_gift_wrap(gift_wrap: &GiftWrap, recipient_sk: &SecretKey) -> Result<Seal> {
    // Verify the gift wrap is correctly formed
    if gift_wrap.kind != GIFT_WRAP_KIND {
        return Err(Error::InvalidKind { expected: GIFT_WRAP_KIND, actual: gift_wrap.kind });
    }
    
    // Extract the sender pubkey
    let sender_pubkey_str = &gift_wrap.pubkey;
    let sender_pubkey_bytes = hex::decode(sender_pubkey_str).map_err(|e| Error::InvalidEvent(e.to_string()))?;
    let sender_pubkey = PublicKey::from_slice(&sender_pubkey_bytes).map_err(|e| Error::InvalidEvent(e.to_string()))?;
    
    // Decrypt the content using NIP-44
    let decrypted_content = nip44::Nip44::decrypt(&gift_wrap.content, recipient_sk, &sender_pubkey)?;
    
    // Parse the content as a Seal
    let seal: Seal = serde_json::from_str(&decrypted_content).map_err(|e| Error::JsonError(e.to_string()))?;
    
    Ok(seal)
}

/// Unseals a seal (kind 13) to reveal the rumor inside
pub fn unseal(seal: &Seal, recipient_sk: &SecretKey) -> Result<Rumor> {
    // Verify the seal is correctly formed
    if seal.kind != SEAL_KIND {
        return Err(Error::InvalidKind { expected: SEAL_KIND, actual: seal.kind });
    }
    
    // Extract the sender pubkey
    let sender_pubkey_str = &seal.pubkey;
    let sender_pubkey_bytes = hex::decode(sender_pubkey_str).map_err(|e| Error::InvalidEvent(e.to_string()))?;
    let sender_pubkey = PublicKey::from_slice(&sender_pubkey_bytes).map_err(|e| Error::InvalidEvent(e.to_string()))?;
    
    // Decrypt the content using NIP-44
    let decrypted_content = nip44::Nip44::decrypt(&seal.content, recipient_sk, &sender_pubkey)?;
    
    // Parse the content as a Rumor
    let rumor: Rumor = serde_json::from_str(&decrypted_content).map_err(|e| Error::JsonError(e.to_string()))?;
    
    Ok(rumor)
}

/// Complete function to unwrap and unseal a gift wrap to reveal the rumor inside
pub fn open_gift(gift_wrap: &GiftWrap, recipient_sk: &SecretKey) -> Result<Rumor> {
    let seal = unwrap_gift_wrap(gift_wrap, recipient_sk)?;
    let rumor = unseal(&seal, recipient_sk)?;
    Ok(rumor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nip44;
    
    fn hex_to_secret_key(hex_str: &str) -> SecretKey {
        let bytes = hex::decode(hex_str).unwrap();
        SecretKey::from_slice(&bytes).unwrap()
    }
    
    #[test]
    fn test_create_rumor() {
        let pubkey = "611df01bfcf85c26ae65453b772d8f1dfd25c264621c0277e1fc1518686faef9";
        let rumor = create_rumor(1, "Are you going to the party tonight?", vec![], pubkey, 1691518405).unwrap();
        
        assert_eq!(rumor.kind, 1);
        assert_eq!(rumor.content, "Are you going to the party tonight?");
        assert_eq!(rumor.pubkey, pubkey);
        assert_eq!(rumor.created_at, 1691518405);
        assert!(rumor.sig.is_none());
    }
    
    #[test]
    fn test_create_seal() {
        let sender_sk = hex_to_secret_key("0beebd062ec8735f4243466049d7747ef5d6594ee838de147f8aab842b15e273");
        let recipient_sk = hex_to_secret_key("e108399bd8424357a710b606ae0c13166d853d327e47a6e5e038197346bdbf45");
        
        let secp = Secp256k1::new();
        let recipient_pk = PublicKey::from_secret_key(&secp, &recipient_sk);
        
        let pubkey = hex::encode(PublicKey::from_secret_key(&secp, &sender_sk).serialize());
        let rumor = create_rumor(1, "Are you going to the party tonight?", vec![], &pubkey, 1691518405).unwrap();
        
        let seal = create_seal(&rumor, &sender_sk, &recipient_pk, Some(1703015180)).unwrap();
        
        assert_eq!(seal.kind, SEAL_KIND);
        assert_eq!(seal.created_at, 1703015180);
        assert_eq!(seal.pubkey, pubkey);
        assert!(seal.sig.is_some());
        assert!(seal.tags.is_empty());
    }
    
    #[test]
    fn test_create_gift_wrap() {
        let sender_sk = hex_to_secret_key("0beebd062ec8735f4243466049d7747ef5d6594ee838de147f8aab842b15e273");
        let recipient_sk = hex_to_secret_key("e108399bd8424357a710b606ae0c13166d853d327e47a6e5e038197346bdbf45");
        
        let secp = Secp256k1::new();
        let recipient_pk = PublicKey::from_secret_key(&secp, &recipient_sk);
        
        let pubkey = hex::encode(PublicKey::from_secret_key(&secp, &sender_sk).serialize());
        let rumor = create_rumor(1, "Are you going to the party tonight?", vec![], &pubkey, 1691518405).unwrap();
        
        let seal = create_seal(&rumor, &sender_sk, &recipient_pk, Some(1703015180)).unwrap();
        let (gift_wrap, _) = create_gift_wrap(&seal, &recipient_pk, Some(1703021488)).unwrap();
        
        assert_eq!(gift_wrap.kind, GIFT_WRAP_KIND);
        assert_eq!(gift_wrap.created_at, 1703021488);
        assert!(gift_wrap.sig.is_some());
        assert_eq!(gift_wrap.tags.len(), 1);
        assert_eq!(gift_wrap.tags[0][0], "p");
        
        // The recipient pubkey should be in the p tag
        let recipient_pk_hex = hex::encode(recipient_pk.serialize());
        assert_eq!(gift_wrap.tags[0][1], recipient_pk_hex);
    }
    
    #[test]
    fn test_full_gift_wrap_flow() {
        // The test keys from the NIP-59 specification
        let sender_sk = hex_to_secret_key("0beebd062ec8735f4243466049d7747ef5d6594ee838de147f8aab842b15e273");
        let recipient_sk = hex_to_secret_key("e108399bd8424357a710b606ae0c13166d853d327e47a6e5e038197346bdbf45");
        
        let secp = Secp256k1::new();
        let sender_pk = PublicKey::from_secret_key(&secp, &sender_sk);
        let recipient_pk = PublicKey::from_secret_key(&secp, &recipient_sk);
        
        let sender_pk_hex = hex::encode(sender_pk.serialize());
        
        // 1. Create a rumor
        let rumor = create_rumor(1, "Are you going to the party tonight?", vec![], &sender_pk_hex, 1691518405).unwrap();
        
        // 2. Create a seal
        let seal = create_seal(&rumor, &sender_sk, &recipient_pk, Some(1703015180)).unwrap();
        
        // 3. Create a gift wrap
        let (gift_wrap, _) = create_gift_wrap(&seal, &recipient_pk, Some(1703021488)).unwrap();
        
        // 4. Recipient unwraps and unseals to get the original message
        let unwrapped_seal = unwrap_gift_wrap(&gift_wrap, &recipient_sk).unwrap();
        let unsealed_rumor = unseal(&unwrapped_seal, &recipient_sk).unwrap();
        
        // Verify the original message was recovered
        assert_eq!(unsealed_rumor.kind, rumor.kind);
        assert_eq!(unsealed_rumor.content, rumor.content);
        assert_eq!(unsealed_rumor.pubkey, rumor.pubkey);
        assert_eq!(unsealed_rumor.created_at, rumor.created_at);
    }
    
    #[test]
    fn test_open_gift() {
        // The test keys from the NIP-59 specification
        let sender_sk = hex_to_secret_key("0beebd062ec8735f4243466049d7747ef5d6594ee838de147f8aab842b15e273");
        let recipient_sk = hex_to_secret_key("e108399bd8424357a710b606ae0c13166d853d327e47a6e5e038197346bdbf45");
        
        let secp = Secp256k1::new();
        let sender_pk = PublicKey::from_secret_key(&secp, &sender_sk);
        let recipient_pk = PublicKey::from_secret_key(&secp, &recipient_sk);
        
        let sender_pk_hex = hex::encode(sender_pk.serialize());
        
        // 1. Create a rumor
        let rumor = create_rumor(1, "Are you going to the party tonight?", vec![], &sender_pk_hex, 1691518405).unwrap();
        
        // 2. Create a seal
        let seal = create_seal(&rumor, &sender_sk, &recipient_pk, Some(1703015180)).unwrap();
        
        // 3. Create a gift wrap
        let (gift_wrap, _) = create_gift_wrap(&seal, &recipient_pk, Some(1703021488)).unwrap();
        
        // 4. Use the combined open_gift function
        let opened_rumor = open_gift(&gift_wrap, &recipient_sk).unwrap();
        
        // Verify the original message was recovered
        assert_eq!(opened_rumor.kind, rumor.kind);
        assert_eq!(opened_rumor.content, rumor.content);
        assert_eq!(opened_rumor.pubkey, rumor.pubkey);
        assert_eq!(opened_rumor.created_at, rumor.created_at);
    }
} 