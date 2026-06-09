use sha2::{Sha256, Digest};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use walkdir::WalkDir;
use serde::Serialize;

#[derive(Serialize)]
pub struct FileInfo {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub magic_bytes: String,
}

pub fn get_file_info(path: &Path) -> Option<FileInfo> {
    let metadata = fs::metadata(path).ok()?;
    let size = metadata.len();

    let mut file = File::open(path).ok()?;

    // Read first 8 bytes (magic bytes)
    let mut magic_buf = [0u8; 8];
    let _ = file.read(&mut magic_buf);

    let magic_bytes = magic_buf
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join(" ");
    let mut file = File::open(path).ok()?;
    let mut hasher = Sha256::new();

    let mut buffer = [0u8; 1024];

    loop {
        let n = file.read(&mut buffer).ok()?;
        if n == 0 { break; }
        hasher.update(&buffer[..n]);
    }

    let sha256 = format!("{:x}", hasher.finalize());

    Some(FileInfo {
        path: path.display().to_string(),
        size,
        sha256,
        magic_bytes,
    })
}

pub fn scan_directory(path: &Path) -> Vec<FileInfo> {
    let mut results = Vec::new();

    if path.is_file() {
        if let Some(info) = get_file_info(path) {
            results.push(info);
        }
    } else {
        for entry in WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
        {
            if let Some(info) = get_file_info(entry.path()) {
                results.push(info);
            }
        }
    }

    results
}