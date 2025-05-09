use nostr_rs_relay::nip17;
use secp256k1::{SecretKey, PublicKey, Secp256k1};
use hex;

fn main() {
    // Create example keys
    let sender_sk_hex = "0beebd062ec8735f4243466049d7747ef5d6594ee838de147f8aab842b15e273";
    let recipient_sk_hex = "e108399bd8424357a710b606ae0c13166d853d327e47a6e5e038197346bdbf45";
    
    let sender_sk = hex_to_secret_key(sender_sk_hex);
    let recipient_sk = hex_to_secret_key(recipient_sk_hex);
    
    let secp = Secp256k1::new();
    let recipient_pk = PublicKey::from_secret_key(&secp, &recipient_sk);
    
    println!("Demonstrating NIP-17 Direct Messages\n");
    
    // Create a direct message
    println!("Creating an encrypted direct message...");
    let message_content = "Hello, this is a private message using NIP-17!";
    let gift_wraps = nip17::create_direct_message(
        message_content,
        &sender_sk,
        &[recipient_pk],
        None,
        Some("Private Conversation"),
    ).unwrap();
    
    println!("Created {} gift wraps (one for recipient, one for sender)", gift_wraps.len());
    
    // Open the message as recipient
    println!("Opening the message as the recipient...");
    let dm = nip17::open_direct_message(&gift_wraps[0], &recipient_sk).unwrap();
    
    // Display the decrypted message content
    println!("Decrypted message content: {}", dm.content);
    
    // Extract metadata
    let subject = nip17::get_subject(&dm);
    println!("Message subject: {}", subject.unwrap_or_else(|| "None".to_string()));
    
    println!("\nDemonstrating NIP-17 File Messages\n");
    
    // Create a file message
    println!("Creating an encrypted file message...");
    let file_url = "https://example.com/encrypted-image.jpg";
    let file_hash = "e8fbf31e397a9325ea55cacb486519f28c7dc7339dbf1d0b77b124f5977008d7";
    
    let gift_wraps = nip17::create_file_message(
        file_url,
        "image/jpeg",
        "aes-gcm",
        "aabbccddeeff00112233445566778899", // Example encryption key
        "112233445566778899aabbcc",         // Example nonce
        file_hash,
        &sender_sk,
        &[recipient_pk],
        None,
        Some("Encrypted Image"),
        Some(1024 * 1024), // 1MB
        Some((800, 600)),  // Width x Height
        Some("LGF5.+Yk^6oi%2NHM%NH%2NH"), // Blurhash placeholder
        Some("https://example.com/encrypted-thumbnail.jpg"),
        Some(vec!["https://backup.example.com/encrypted-image.jpg".to_string()]),
    ).unwrap();
    
    println!("Created {} gift wraps (one for recipient, one for sender)", gift_wraps.len());
    
    // Open the message as recipient
    println!("Opening the file message as the recipient...");
    let fm = nip17::open_file_message(&gift_wraps[0], &recipient_sk).unwrap();
    
    // Display the decrypted file information
    println!("Decrypted file URL: {}", fm.content);
    
    // Extract metadata
    let subject = nip17::get_subject(&nip17::DirectMessage { 
        content: fm.content.clone(), 
        tags: fm.tags.clone() 
    });
    println!("File message subject: {}", subject.unwrap_or_else(|| "None".to_string()));
    
    // Extract file type
    let file_type = fm.tags.iter()
        .find(|tag| !tag.is_empty() && tag[0] == "file-type")
        .and_then(|tag| tag.get(1).cloned())
        .unwrap_or_else(|| "Unknown".to_string());
    println!("File type: {}", file_type);
    
    // Extract file dimensions
    let dimensions = fm.tags.iter()
        .find(|tag| !tag.is_empty() && tag[0] == "dim")
        .and_then(|tag| tag.get(1).cloned())
        .unwrap_or_else(|| "Unknown".to_string());
    println!("File dimensions: {}", dimensions);
    
    println!("\nNIP-17 implementation demonstration complete!");
}

fn hex_to_secret_key(hex_str: &str) -> SecretKey {
    let bytes = hex::decode(hex_str).unwrap();
    SecretKey::from_slice(&bytes).unwrap()
} 