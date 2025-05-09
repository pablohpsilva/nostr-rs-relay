/// NIP-59 Relay Integration
/// 
/// This module integrates Gift Wrap protocol (NIP-59) with the relay infrastructure.
/// It provides functionality for validating, routing, and handling gift wrap events.
/// 
/// Gift Wraps allow encapsulating events to obscure metadata, and are commonly used
/// with NIP-17 private messages.

use crate::error::Result;
use crate::event::Event;
use crate::nip59;
use base64::{Engine as _, engine::general_purpose};

/// Gift Wrap event kind
pub const GIFT_WRAP_KIND: u64 = 1059;
/// Seal event kind
pub const SEAL_KIND: u64 = 13;

/// Validate that a message conforms to NIP-59 gift wrap structure
/// without actually unwrapping it
pub fn validate_structure(event: &Event) -> bool {
    // Check if this is a gift wrap event
    if event.kind != GIFT_WRAP_KIND {
        return false;
    }
    
    // Gift wraps must have at least one p-tag for routing
    if event.tag_values_by_name("p").is_empty() {
        return false;
    }
    
    // Content should be base64 encoded
    if let Err(_) = general_purpose::STANDARD.decode(&event.content) {
        return false;
    }
    
    // Signature must be present
    if event.sig.is_empty() {
        return false;
    }
    
    true
}

/// Extract recipient pubkeys from a gift wrap's p-tags
pub fn get_recipients(event: &Event) -> Vec<String> {
    if event.kind != GIFT_WRAP_KIND {
        return Vec::new();
    }
    
    event.tag_values_by_name("p")
}

/// Determine if the event should be routed to a given pubkey
pub fn should_route_to(event: &Event, pubkey: &str) -> bool {
    if event.kind != GIFT_WRAP_KIND {
        return false;
    }
    
    // Gift wraps should be routed to any pubkey listed in their p-tags
    event.tag_values_by_name("p").contains(&pubkey.to_string())
}

/// Validate a gift wrap event's overall structure
pub fn validate_event(event: &Event) -> bool {
    // Basic validation for gift wrap structure
    validate_structure(event)
}

/// Create index fields for a gift wrap event
/// This extracts all necessary data for efficient recipient queries
pub fn create_index_entries(event: &Event) -> Vec<(String, String)> {
    let mut entries = Vec::new();
    
    // Check if this is a gift wrap
    if event.kind != GIFT_WRAP_KIND {
        return entries;
    }
    
    // Extract p-tags and create an index entry for each recipient
    for recipient in get_recipients(event) {
        entries.push((recipient, event.id.clone()));
    }
    
    entries
} 