/// NIP-17 Relay Integration
/// 
/// This module integrates Private Direct Messages with the relay infrastructure.
/// It provides functionality for validating, routing, and handling encrypted message events.
/// 
/// NIP-17 covers:
/// - Direct messages (kind 14)
/// - File messages (kind 15)
/// - These are delivered as NIP-59 gift wraps (kind 1059)

use crate::error::Result;
use crate::event::Event;
use crate::nip17;
use base64::{Engine as _, engine::general_purpose};

/// Event kinds from NIP-17
pub const DIRECT_MESSAGE_KIND: u64 = 14;
pub const FILE_MESSAGE_KIND: u64 = 15;

/// Validate that a direct message conforms to NIP-17 structure
pub fn validate_structure(event: &Event) -> bool {
    if event.kind != DIRECT_MESSAGE_KIND && event.kind != FILE_MESSAGE_KIND {
        return false;
    }
    
    // Direct messages must have at least one p-tag for the recipient
    if event.tag_values_by_name("p").is_empty() {
        return false;
    }
    
    // Content should be encrypted using NIP-44
    // We don't decrypt, but it should be base64 encoded
    if let Err(_) = general_purpose::STANDARD.decode(&event.content) {
        return false;
    }
    
    // Signature must be present
    if event.sig.is_empty() {
        return false;
    }
    
    true
}

/// Extract recipient pubkeys from a direct message's p-tags
pub fn get_recipients(event: &Event) -> Vec<String> {
    if event.kind != DIRECT_MESSAGE_KIND && event.kind != FILE_MESSAGE_KIND {
        return Vec::new();
    }
    
    event.tag_values_by_name("p")
}

/// Determine if a direct message should be routed to a given pubkey
pub fn should_route_to(event: &Event, pubkey: &str) -> bool {
    if event.kind != DIRECT_MESSAGE_KIND && event.kind != FILE_MESSAGE_KIND {
        return false;
    }
    
    // Direct messages should be routed to recipients or sender
    event.tag_values_by_name("p").contains(&pubkey.to_string()) ||
    event.pubkey == pubkey
}

/// Validate a direct message event's structure
pub fn validate_event(event: &Event) -> bool {
    validate_structure(event)
}

/// Create index entries for a direct message to optimize retrieval by recipient
pub fn create_index_entries(event: &Event) -> Vec<(String, String)> {
    let mut entries = Vec::new();
    
    if event.kind != DIRECT_MESSAGE_KIND && event.kind != FILE_MESSAGE_KIND {
        return entries;
    }
    
    // Create an index entry for each recipient
    for recipient in get_recipients(event) {
        entries.push((recipient, event.id.clone()));
    }
    
    // Also create an entry for the sender so they can retrieve their own messages
    entries.push((event.pubkey.clone(), event.id.clone()));
    
    entries
}

/// Determine if this is a file message
pub fn is_file_message(event: &Event) -> bool {
    event.kind == FILE_MESSAGE_KIND
}

/// Extract file-related metadata from a file message
pub fn get_file_metadata(event: &Event) -> Option<FileMetadata> {
    if !is_file_message(event) {
        return None;
    }
    
    // Extract required file metadata from tags
    let file_type = event.tags.iter()
        .find(|tag| !tag.is_empty() && tag[0] == "file-type")
        .and_then(|tag| tag.get(1).cloned());
    
    let file_hash = event.tags.iter()
        .find(|tag| !tag.is_empty() && tag[0] == "x")
        .and_then(|tag| tag.get(1).cloned());
        
    if file_type.is_none() || file_hash.is_none() {
        return None;
    }
    
    // Extract optional file metadata
    let size = event.tags.iter()
        .find(|tag| !tag.is_empty() && tag[0] == "size")
        .and_then(|tag| tag.get(1).cloned())
        .and_then(|s| s.parse::<u64>().ok());
        
    let dimensions = event.tags.iter()
        .find(|tag| !tag.is_empty() && tag[0] == "dim")
        .and_then(|tag| tag.get(1).cloned())
        .and_then(|dim| {
            let parts: Vec<&str> = dim.split('x').collect();
            if parts.len() == 2 {
                let width = parts[0].parse::<u32>().ok()?;
                let height = parts[1].parse::<u32>().ok()?;
                Some((width, height))
            } else {
                None
            }
        });
    
    Some(FileMetadata {
        file_type: file_type.unwrap(),
        file_hash: file_hash.unwrap(),
        size,
        dimensions,
    })
}

/// File metadata extracted from a NIP-17 file message
#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub file_type: String,
    pub file_hash: String,
    pub size: Option<u64>,
    pub dimensions: Option<(u32, u32)>,
} 