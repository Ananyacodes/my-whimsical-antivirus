#[path = "../logs/logger.rs"]
mod logger;
mod scanner;
mod signatures;
mod yara_scan;
#[path = "../quarantine/quarantine.rs"]
mod quarantine;

use chrono::Utc;
use logger::*;
use scanner::*;
use signatures::*;
use std::error::Error;
use std::path::PathBuf;
use yara_scan::*;

fn main() -> Result<(), Box<dyn Error>> {
    let target = PathBuf::from(".");
    let results = scan_directory(target.as_path());
    let sig_db = load_signatures()?;
    let yara_rules = load_rules("rules.yar")?;

    for file in results {
        let mut result = "clean".to_string();
        let mut triggered: Option<String> = None;

        if let Some(name) = check_hash(&file.sha256, &sig_db) {
            result = "matched".to_string();
            triggered = Some(format!("Signature: {}", name));
        }

        let yara_matches = scan_file(&yara_rules, file.path.as_path())?;
        if !yara_matches.is_empty() {
            result = "matched".to_string();
            triggered = Some(format!("YARA: {:?}", yara_matches));
        }

        println!("Scanned: {} -> {}", file.path.display(), result);

        log_result(LogEntry {
            filename: file.path.clone(),
            hash: file.sha256.clone(),
            timestamp: Utc::now().to_rfc3339(),
            result,
            signature: triggered,
        })?;
    }

    Ok(())
}