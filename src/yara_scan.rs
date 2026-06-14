use std::error::Error;
use std::path::Path;

// If compiled with the `yara` feature, use the real yara crate.
#[cfg(feature = "yara")]
use yara::{Compiler, Rules};

#[cfg(feature = "yara")]
pub fn load_rules(path: impl AsRef<Path>) -> Result<Rules, Box<dyn Error>> {
    yara::initialize()?;

    let mut compiler = Compiler::new()?;
    compiler.add_rules_file(path.as_ref())?;

    Ok(compiler.compile_rules()?)
}

#[cfg(feature = "yara")]
pub fn scan_file(rules: &Rules, file_path: impl AsRef<Path>) -> Result<Vec<String>, Box<dyn Error>> {
    let results = rules.scan_file(file_path.as_ref(), 5)?;

    let mut matches = Vec::new();

    for m in results.iter() {
        matches.push(m.identifier.to_string());
    }

    Ok(matches)
}

// Fallbacks when YARA is not enabled: provide no-op implementations so the
// project can build and run without libyara.
#[cfg(not(feature = "yara"))]
#[derive(Debug)]
pub struct DummyRules;

#[cfg(not(feature = "yara"))]
pub fn load_rules(_path: impl AsRef<Path>) -> Result<DummyRules, Box<dyn Error>> {
    // No YARA support available; return a dummy ruleset.
    Ok(DummyRules)
}

#[cfg(not(feature = "yara"))]
pub fn scan_file(_rules: &DummyRules, _file_path: impl AsRef<Path>) -> Result<Vec<String>, Box<dyn Error>> {
    // No matches when YARA is not available.
    Ok(Vec::new())
}