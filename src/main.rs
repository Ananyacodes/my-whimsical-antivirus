mod scanner;
mod signatures;
use scanner::*;
use signatures::*;
use std::path::Path;
fn main() {
    let target = ".";
    let path = Path::new(target);
    let results = scan_directory(path);
    let sig_db = load_signatures();
    for file in results {
        match check_hash(&file.sha256, &sig_db) {
            Some(name) => {
                println!("MALWARE DETECTED: {} -> {}", file.path, name);
            }
            None => {
                println!("CLEAN: {}", file.path);
            }
        }
    }
}