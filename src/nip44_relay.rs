/// NIP-44 Relay Integration
/// 
/// This module integrates NIP-44 encrypted payloads with the relay infrastructure.
/// It doesn't decrypt messages (that's the client's job) but ensures proper:
/// - Validation of encrypted message structure
/// - Routing to intended recipients
/// - Storage of encrypted content
/// 
/// NIP-44 is used in conjunction with NIP-17 (private direct messages).

use crate::error::Result;
use crate::event::Event;
use crate::nip44::{self, Version};
use base64::{Engine as _, engine::general_purpose};

/// NIP-44 event kinds
pub const NIP44_MESSAGE_KIND: u64 = 4;
pub const NIP44_DM_REPOST_KIND: u64 = 44;

/// Validate that a message conforms to NIP-44 structure
/// without actually decrypting it
pub fn validate_structure(content: &str) -> bool {
    // Try to decode the base64 content
    if let Ok(payload) = general_purpose::STANDARD.decode(content) {
        // NIP-44 must be at least 1 byte for version + 32 bytes for nonce + 32 bytes for MAC
        if payload.len() < 65 {
            return false;
        }

        // Check version byte
        let version = Version::from(payload[0]);
        if version != Version::V2 {
            return false;
        }

        // We don't actually decrypt - we just validate the structure looks valid
        // The structure is: [version(1 byte)][nonce(32 bytes)][ciphertext(variable)][MAC(32 bytes)]
        true
    } else {
        false
    }
}

/// Validate an event containing NIP-44 encrypted content
pub fn validate_event(event: &Event) -> bool {
    // Check if this is an event that should contain NIP-44 encrypted content
    match event.kind {
        // Direct messages
        NIP44_MESSAGE_KIND | NIP44_DM_REPOST_KIND => {
            // Must have a "p" tag for the recipient
            if event.tag_values_by_name("p").is_empty() {
                return false;
            }
            
            // Content should be valid NIP-44 structure
            validate_structure(&event.content)
        },
        // For gift wraps (NIP-17), structure validation happens in the NIP-17 module
        _ => true
    }
}

/// Extract recipient pubkeys for encrypted messages
pub fn get_recipients(event: &Event) -> Vec<String> {
    match event.kind {
        // Standard DMs
        NIP44_MESSAGE_KIND | NIP44_DM_REPOST_KIND => {
            event.tag_values_by_name("p")
        },
        // For other kinds, empty list (recipients handled elsewhere)
        _ => Vec::new()
    }
}

/// Determine if the event should be routed to a given pubkey
pub fn should_route_to(event: &Event, pubkey: &str) -> bool {
    // For standard DMs
    if event.kind == NIP44_MESSAGE_KIND || event.kind == NIP44_DM_REPOST_KIND {
        return event.tag_values_by_name("p").contains(&pubkey.to_string()) ||
               event.pubkey == pubkey;
    }
    
    false
} 