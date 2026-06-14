use chrono::Utc;
use std::fs;
use std::path::{Path, PathBuf};

pub fn quarantine_file(src: &Path, quarantine_dir: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    fs::create_dir_all(quarantine_dir)?;

    let filename = src.file_name().ok_or("invalid filename")?;
    let timestamp = Utc::now().format("%Y%m%d_%H%M%S").to_string();
    let dest = quarantine_dir.join(format!("{}_{}", timestamp, filename.to_string_lossy()));

    fs::rename(src, &dest)?;

    let mut perms = fs::metadata(&dest)?.permissions();
    perms.set_readonly(true);
    fs::set_permissions(&dest, perms)?;

    println!("Quarantined: {:?}", dest);
    Ok(dest)
}
