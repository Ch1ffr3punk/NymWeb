use std::env;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("Nym Address Encoder to hex format - (c) 2026 Ch1ffr3punk");
        eprintln!();
        eprintln!("Usage: nym-address-encoder <nym-address>");
        eprintln!();
        eprintln!("Example:");
        eprintln!("  nym-address-encoder BC9QVHnyJwKDZHXCHRDbsq9HRJ1wA6ryGc74c28RiwSQ.6aNiAeRaVuy1Tf96CmcJdjZpcums5M9p6jxt52rtU4Va@38zcSsvjXsAX7C28ko2H3Lt55X4TYxfZYkPADxKXZHUj");
        process::exit(1);
    }

    let nym_address = &args[1];

    // Validate format
    let parts: Vec<&str> = nym_address.split(|c| c == '.' || c == '@').collect();
    if parts.len() != 3 {
        eprintln!("Error: Expected format: identity.encryption@gateway");
        process::exit(1);
    }

    // Decode each base58 key to raw bytes
    let id_bytes = match bs58::decode(parts[0]).into_vec() {
        Ok(b) if b.len() == 32 => b,
        _ => {
            eprintln!("Error: Invalid identity key (must be 32 bytes base58)");
            process::exit(1);
        }
    };

    let enc_bytes = match bs58::decode(parts[1]).into_vec() {
        Ok(b) if b.len() == 32 => b,
        _ => {
            eprintln!("Error: Invalid encryption key (must be 32 bytes base58)");
            process::exit(1);
        }
    };

    let gw_bytes = match bs58::decode(parts[2]).into_vec() {
        Ok(b) if b.len() == 32 => b,
        _ => {
            eprintln!("Error: Invalid gateway key (must be 32 bytes base58)");
            process::exit(1);
        }
    };

    // Concatenate all 96 bytes and hex-encode (lowercase)
    let mut all_bytes = Vec::with_capacity(96);
    all_bytes.extend_from_slice(&id_bytes);
    all_bytes.extend_from_slice(&enc_bytes);
    all_bytes.extend_from_slice(&gw_bytes);

    let hex_encoded = hex::encode(&all_bytes); // lowercase by default

    println!();
    println!("Original Nym Address:");
    println!("  {}", nym_address);
    println!();
    println!("Hex Encoded (lowercase, 192 chars):");
    println!("  {}", hex_encoded);
    println!();
    println!("URL for Browser:");
    println!("  http://{}/", hex_encoded);
    println!();
    println!("Length: {} characters", hex_encoded.len());
    println!();
    println!("All lowercase - safe for browser hostname normalization");
}
