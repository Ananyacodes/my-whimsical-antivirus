# My Whimsical Antivirus

Small cross-platform antivirus scanner (Python) with file signature matching, quarantine, and Windows Event Log analysis.

**Quick Start**

- Install Python 3.8+ (Windows/Mac/Linux).
- From the project root run scans with the included script.

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

- Demo mode (simulates threats and writes them to `logs/scan.log`):

```powershell
python antivirus.py --demo
```

Files and Logs

- Signature database: `signatures.json` (SHA256 -> name). Add entries to detect files by hash.
- Scan log: `logs/scan.log` — JSON-lines with file and event scan entries.
- Quarantine directory: `quarantine/` — matched files are moved here and set read-only.

Notes & Permissions

- Accessing the Windows Security log requires Administrator privileges. If the script prints "Security log requires administrator privileges", re-run the command in an elevated PowerShell session.
- The script intentionally skips common build and virtual environment directories; update `.gitignore` if you need to include additional paths.

Troubleshooting

- If `Get-WinEvent` fails with `UnauthorizedAccessException`, run PowerShell as Administrator and re-run the scan.
- If file scanning is slow, run on a target path that excludes large directories, or increase system resources.

Development

- The Python scanner is `antivirus.py`. Key classes:
  - `FileScanner` — recursive file hashing and signature matching.
  - `WindowsEventScanner` — queries Windows Event Logs for suspicious activity.
  - `DecisionEngine` — maps scores to decisions (ALLOW/WARN/AUTO QUARANTINE).
  - `Quarantine` — moves files to `quarantine/` and sets them read-only.

Contributing

- Add new signatures to `signatures.json` as `{ "name": "Signature: Example", "sha256": "..." }`.
- Open a PR with tests or sample logs for evaluation.

License

This project inherits the repository license (if any). Use responsibly.
