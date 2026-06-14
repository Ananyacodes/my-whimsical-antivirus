use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

#[derive(Serialize)]
pub struct LogEntry {
    pub filename: PathBuf,
    pub hash: String,
    pub timestamp: String,
    pub result: String,
    pub signature: Option<String>,
}

pub fn log_result(entry: LogEntry) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all("logs")?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("logs/scan.log")?;
    let line = serde_json::to_string(&entry)?;
    writeln!(file, "{}", line)?;
    Ok(())
}
