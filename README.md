# My Whimsical Antivirus

Cross-platform antivirus scanner with file signature matching, YARA rule support, quarantine, and Windows Event Log analysis. File scanning is handled by a Rust binary for performance, YARA rules are kept fresh by a Go updater service, and Windows Event Log analysis runs through Python. The Python layer owns orchestration, decisions, and quarantine throughout.

**Quick Start**

- Install Python 3.8+ (Windows/Mac/Linux).
- Build the Rust binary from the project root: `cargo build`
- Optionally start the Go rule updater before scanning: `go run src/main.go` (runs on port 8080 and pulls the latest YARA rules automatically before each scan)
- Run scans with `antivirus.py` as shown below.

**Commands**

- Scan a directory (recursive):

```powershell
python antivirus.py .
```

- Scan and auto-quarantine matched files:

```powershell
python antivirus.py . --quarantine
```

- Process the stored scan log (human-readable):

```powershell
python antivirus.py --process-log
```

- Scan Windows Event Logs (requires Windows; security log access may need admin):

```powershell
python antivirus.py --windows-logs --hours 24
```

- Force the pure-Python scanner even if the Rust binary is present:

```powershell
python antivirus.py . --no-rust
```

- Point to a Go rule updater running on a non-default address:

```powershell
python antivirus.py . --go-server http://localhost:9090
```

**Files and Logs**

- Signature database: `signatures.json` (SHA256 -> name). Add entries to detect files by hash.
- YARA rules: `rules/` directory. The Go updater writes timestamped `.yar` files here; the Rust binary picks them up at scan time.
- Scan log: `logs/scan.log` -- JSON-lines with file and event scan entries from both the Rust binary and the Python event scanner.
- Quarantine directory: `quarantine/` -- matched files are moved here and set read-only.

**Architecture**

- `antivirus.py` -- orchestrator. Calls the Rust binary for file scanning, hits the Go updater before each scan, handles Windows Event Logs directly, and applies the decision and quarantine layer on all results.
- `decision_engine.py` -- scoring and decision logic. Reads `logs/scan.log` and works with entries from both the Rust binary and the Python scanner transparently.
- `src/main.go` -- Go HTTP server. Exposes `/update` to download and hash-check the latest YARA rules from the Yara-Rules repository.
- `src/main.rs` / `src/scanner.rs` / `src/signatures.rs` / `src/yara_scan.rs` -- Rust scanner. Walks the filesystem, computes SHA256 hashes, matches against `signatures.json` and YARA rules, and writes results to `logs/scan.log`.
- `scripts/confetti_big.py` -- standalone confetti renderer, spawned automatically when a 24-hour clean scan is detected.

**Notes and Permissions**

- Accessing the Windows Security log requires Administrator privileges. If the script prints "Security log requires administrator privileges", re-run the command in an elevated PowerShell session.
- If the Rust binary is not built yet, `antivirus.py` falls back to the pure-Python `FileScanner` automatically with no change to the command.
- If the Go updater is not running, the scanner continues with whatever YARA rules are already present in `rules/`. It does not fail.
- The scanner intentionally skips common build and virtual environment directories (`.git`, `target`, `.cargo`, `node_modules`, `venv`).

**Troubleshooting**

- If `Get-WinEvent` fails with `UnauthorizedAccessException`, run PowerShell as Administrator and re-run the scan.
- If file scanning is slow, run on a specific target path to exclude large directories, or run `cargo build --release` and use the release binary for better throughput.
- If the Go updater cannot reach the Yara-Rules repository, check network access and retry; existing cached rules remain usable.

**Development**

Key classes and modules:

- `FileScanner` -- recursive file hashing and signature matching (Python fallback).
- `WindowsEventScanner` -- queries Security, System, Application, and PowerShell Event Logs for suspicious activity.
- `DecisionEngine` -- maps scores to decisions (ALLOW / WARN USER / AUTO QUARANTINE). Handles log entries from both the Rust binary and the Python scanner.
- `Quarantine` -- moves files to `quarantine/` and sets them read-only.
- Rust `scan_directory` -- fast filesystem walker using `walkdir`, SHA256 via `sha2`, YARA via the `yara` feature flag.
- Go `downloadFile` -- fetches, hash-checks, and saves updated YARA rule files.

**Contributing**

- Add new signatures to `signatures.json` as `{ "name": "Signature: Example", "sha256": "..." }`.
- Add YARA rules directly to `rules/` or let the Go updater manage them.
- Open a PR with tests or sample logs for evaluation.

**License**

MIT. Use responsibly.

**There's an easy-to-find easter egg for ya all. Enjoy the whimsy!**