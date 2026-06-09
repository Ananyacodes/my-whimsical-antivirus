use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
pub struct Signature {
    pub name: String,
    pub sha256: String,
}

#[derive(Deserialize)]
pub struct SignatureDB {
    pub signatures: Vec<Signature>,
}

pub fn load_signatures() -> SignatureDB {
    let data = fs::read_to_string("signatures.json")
        .expect("Failed to read signatures.json");

    serde_json::from_str(&data)
        .expect("Invalid JSON format")
}

pub fn check_hash(hash: &str, db: &SignatureDB) -> Option<String> {
    for sig in &db.signatures {
        if sig.sha256 == hash {
            return Some(sig.name.clone());
        }
    }
    None
}