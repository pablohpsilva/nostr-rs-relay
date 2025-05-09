/// NIP-44: Encrypted Payloads (Versioned)
/// 
/// This module implements the NIP-44 protocol for encrypted payloads.
/// Currently, only Version 2 is implemented.
/// 
/// The implementation follows the specification:
/// - secp256k1 ECDH for key exchange
/// - HKDF for key derivation
/// - padding for plaintext
/// - ChaCha20 for encryption
/// - HMAC-SHA256 for message authentication
/// - base64 for encoding
use std::io::{self};
use thiserror::Error;
use bitcoin_hashes::{sha256, Hash, HashEngine, hmac};
use secp256k1::{SecretKey, PublicKey, Secp256k1};
use rand::{rngs::OsRng, RngCore};
use base64::{Engine as _, engine::general_purpose};
use chacha20::{
    ChaCha20,
    cipher::{KeyIvInit, StreamCipher},
};

/// Version byte for the encryption algorithm
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Version {
    /// Version 2 algorithm (secp256k1, HKDF, ChaCha20-Poly1305)
    V2 = 2,
}

impl From<u8> for Version {
    fn from(v: u8) -> Self {
        match v {
            2 => Version::V2,
            _ => Version::V2, // Default to V2 for now
        }
    }
}

/// Errors that can occur during encryption/decryption
#[derive(Debug, Error)]
pub enum Error {
    /// Invalid base64 encoding
    #[error("Invalid base64 encoding")]
    InvalidBase64,
    
    /// Decryption failed (usually due to incorrect keys or tampered ciphertext)
    #[error("Decryption failed")]
    DecryptionFailed,
    
    /// Invalid key for encryption/decryption
    #[error("Invalid key")]
    InvalidKey,
    
    /// Unsupported version
    #[error("Unsupported version")]
    UnsupportedVersion,
    
    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Random generation error
    #[error("Random generation error")]
    Random,
    
    /// Message authentication failed
    #[error("Authentication failed")]
    AuthenticationFailed,
}

/// Constants for the encryption
const NONCE_SIZE: usize = 32;
const CHACHA_NONCE_SIZE: usize = 12;
const VERSION_SIZE: usize = 1;
const MAC_SIZE: usize = 32;
const CONVERSATION_KEY_SIZE: usize = 32;
const EXPECTED_KEY_SIZE: usize = 32;

/// Calculate shared key between two parties
fn calculate_shared_key(secret_key: &SecretKey, public_key: &PublicKey) -> Result<[u8; CONVERSATION_KEY_SIZE], Error> {
    let secp = Secp256k1::new();
    
    // Calculate the shared point
    let shared_point = secp256k1::ecdh::SharedSecret::new(public_key, secret_key).as_ref().try_into()
        .map_err(|_| Error::InvalidKey)?;
        
    Ok(shared_point)
}

/// Derive encryption and authentication keys from a shared secret
fn derive_keys(conversation_key: &[u8], nonce: &[u8]) -> Result<([u8; EXPECTED_KEY_SIZE], [u8; EXPECTED_KEY_SIZE]), Error> {
    let mut t = [0u8; 32];
    let info = [0u8; 0]; // Empty info as per NIP-44 spec
    
    // Apply HKDF extraction
    let mut hmac_engine = hmac::HmacEngine::<sha256::Hash>::new(nonce);
    hmac_engine.input(conversation_key);
    let prk = hmac::Hmac::<sha256::Hash>::from_engine(hmac_engine);
    
    // First key
    let mut hmac_engine = hmac::HmacEngine::<sha256::Hash>::new(prk.as_inner());
    hmac_engine.input(&[1u8]);
    hmac_engine.input(&info);
    
    // Get the first HMAC result
    let hmac_result = hmac::Hmac::<sha256::Hash>::from_engine(hmac_engine);
    t.copy_from_slice(hmac_result.as_inner());
    
    let encryption_key = t;
    
    // Second key
    let mut hmac_engine = hmac::HmacEngine::<sha256::Hash>::new(prk.as_inner());
    hmac_engine.input(&t);
    hmac_engine.input(&[2u8]);
    hmac_engine.input(&info);
    
    // Get the second HMAC result
    let hmac_result = hmac::Hmac::<sha256::Hash>::from_engine(hmac_engine);
    t.copy_from_slice(hmac_result.as_inner());
    
    let auth_key = t;
    
    Ok((encryption_key, auth_key))
}

/// Create an HMAC for the given data using the provided key
fn create_hmac(auth_key: &[u8], data: &[u8]) -> [u8; MAC_SIZE] {
    let mut hmac_engine = hmac::HmacEngine::<sha256::Hash>::new(auth_key);
    hmac_engine.input(data);
    let result = hmac::Hmac::<sha256::Hash>::from_engine(hmac_engine);
    let mut mac = [0u8; MAC_SIZE];
    mac.copy_from_slice(result.as_inner());
    mac
}

/// Verify an HMAC for the given data using the provided key
fn verify_hmac(auth_key: &[u8], data: &[u8], expected_mac: &[u8]) -> bool {
    let computed_mac = create_hmac(auth_key, data);
    constant_time_eq(&computed_mac, expected_mac)
}

/// Constant-time comparison of two byte arrays
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// ChaCha20 encryption with the provided key, nonce, and plaintext
fn chacha20_encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    // Convert key and nonce to expected formats
    let key_array: [u8; 32] = key.try_into().map_err(|_| Error::InvalidKey)?;
    let nonce_array: [u8; 12] = nonce[..CHACHA_NONCE_SIZE].try_into().map_err(|_| Error::InvalidKey)?;
    
    // Create ChaCha20 cipher
    let mut cipher = ChaCha20::new(&key_array.into(), &nonce_array.into());
    
    // Create output buffer with copied plaintext
    let mut ciphertext = plaintext.to_vec();
    
    // Apply keystream (encrypt in place)
    cipher.apply_keystream(&mut ciphertext);
    
    Ok(ciphertext)
}

/// ChaCha20 decryption with the provided key, nonce, and ciphertext
fn chacha20_decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    // ChaCha20 encryption and decryption are the same operation
    chacha20_encrypt(key, nonce, ciphertext)
}

/// Pad plaintext according to NIP-44 spec
fn pad_plaintext(plaintext: &[u8]) -> Vec<u8> {
    let mut padded = Vec::from(plaintext);
    padded.push(1); // Always add a 1 byte
    
    // Add zero bytes to reach a multiple of 32
    let remainder = (padded.len()) % 32;
    if remainder != 0 {
        let padding_needed = 32 - remainder;
        padded.resize(padded.len() + padding_needed, 0);
    }
    
    padded
}

/// Remove padding from decrypted text
fn unpad_plaintext(padded: &[u8]) -> Result<Vec<u8>, Error> {
    // Find the last non-zero byte, which should be 1
    let mut i = padded.len();
    
    while i > 0 {
        i -= 1;
        if padded[i] == 1 {
            return Ok(padded[0..i].to_vec());
        }
        if padded[i] != 0 {
            return Err(Error::DecryptionFailed);
        }
    }
    
    Err(Error::DecryptionFailed)
}

/// The main NIP-44 encryption/decryption API
pub struct Nip44;

impl Nip44 {
    /// Encrypt plaintext with the recipient's public key and sender's secret key
    pub fn encrypt(plaintext: &str, sender_sk: &SecretKey, recipient_pk: &PublicKey) -> Result<String, Error> {
        Self::encrypt_with_nonce(plaintext, sender_sk, recipient_pk, None)
    }
    
    /// Encrypt plaintext with custom nonce
    pub fn encrypt_with_nonce(plaintext: &str, sender_sk: &SecretKey, recipient_pk: &PublicKey, custom_nonce: Option<[u8; NONCE_SIZE]>) -> Result<String, Error> {
        // Generate or use provided nonce
        let nonce = if let Some(n) = custom_nonce {
            n
        } else {
            let mut n = [0u8; NONCE_SIZE];
            OsRng.fill_bytes(&mut n);
            n
        };
        
        // Calculate the shared secret
        let conversation_key = calculate_shared_key(sender_sk, recipient_pk)?;
        
        // Derive encryption and auth keys
        let (encryption_key, auth_key) = derive_keys(&conversation_key, &nonce)?;
        
        // Pad the plaintext
        let padded_plaintext = pad_plaintext(plaintext.as_bytes());
        
        // Generate ChaCha20 nonce (first 12 bytes of the nonce)
        let chacha_nonce = &nonce[0..CHACHA_NONCE_SIZE];
        
        // Encrypt the padded plaintext
        let ciphertext = chacha20_encrypt(&encryption_key, chacha_nonce, &padded_plaintext)?;
        
        // Create a payload with all the necessary data
        let mut payload = Vec::with_capacity(VERSION_SIZE + NONCE_SIZE + ciphertext.len() + MAC_SIZE);
        
        // Add version byte
        payload.push(Version::V2 as u8);
        
        // Add nonce
        payload.extend_from_slice(&nonce);
        
        // Add ciphertext
        payload.extend_from_slice(&ciphertext);
        
        // Calculate and add MAC
        let mac = create_hmac(&auth_key, &payload);
        payload.extend_from_slice(&mac);
        
        // Base64 encode
        let encoded = general_purpose::STANDARD.encode(&payload);
        
        Ok(encoded)
    }
    
    /// Decrypt a NIP-44 encrypted message using recipient's secret key and sender's public key
    pub fn decrypt(encoded_payload: &str, recipient_sk: &SecretKey, sender_pk: &PublicKey) -> Result<String, Error> {
        // Decode base64
        let payload = general_purpose::STANDARD.decode(encoded_payload)
            .map_err(|_| Error::InvalidBase64)?;
        
        if payload.len() < VERSION_SIZE + NONCE_SIZE + MAC_SIZE {
            return Err(Error::DecryptionFailed);
        }
        
        // Extract version
        let version = Version::from(payload[0]);
        if version != Version::V2 {
            return Err(Error::UnsupportedVersion);
        }
        
        // Extract nonce
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&payload[VERSION_SIZE..VERSION_SIZE + NONCE_SIZE]);
        
        // Extract MAC
        let mac_start = payload.len() - MAC_SIZE;
        let mac = &payload[mac_start..];
        
        // Calculate the shared secret
        let conversation_key = calculate_shared_key(recipient_sk, sender_pk)?;
        
        // Derive keys
        let (encryption_key, auth_key) = derive_keys(&conversation_key, &nonce)?;
        
        // Verify MAC
        if !verify_hmac(&auth_key, &payload[0..mac_start], mac) {
            return Err(Error::AuthenticationFailed);
        }
        
        // Extract ciphertext
        let ciphertext = &payload[VERSION_SIZE + NONCE_SIZE..mac_start];
        
        // Generate ChaCha20 nonce
        let chacha_nonce = &nonce[0..CHACHA_NONCE_SIZE];
        
        // Decrypt
        let padded_plaintext = chacha20_decrypt(&encryption_key, chacha_nonce, ciphertext)?;
        
        // Unpad
        let plaintext = unpad_plaintext(&padded_plaintext)?;
        
        // Convert to string
        let result = String::from_utf8(plaintext)
            .map_err(|_| Error::DecryptionFailed)?;
            
        Ok(result)
    }
    
    /// Get conversation key from two keypairs
    pub fn get_conversation_key(sender_sk: &SecretKey, recipient_pk: &PublicKey) -> Result<String, Error> {
        let conversation_key = calculate_shared_key(sender_sk, recipient_pk)?;
        Ok(hex::encode(conversation_key))
    }
} 