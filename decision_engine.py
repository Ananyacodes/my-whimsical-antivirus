import json

def score_entry(entry):
    sig = entry.get("signature")

    if sig is None:
        return 0

    if "Signature" in sig:
        return 100
    elif "YARA" in sig:
        return 70
    else:
        return 40

def decide(score):
    if score >= 80:
        return "AUTO QUARANTINE"
    elif 40 <= score < 80:
        return "WARN USER"
    else:
        return "ALLOW"

def process_log(file_path="logs/scan.log"):
    try:
        with open(file_path, "r") as f:
            for line in f:
                entry = json.loads(line)

                score = score_entry(entry)
                decision = decide(score)

                filename = entry.get('filename')
                triggered = entry.get('signature')

                print(f"\nFile: {filename}")
                print(f"Score: {score}")
                print(f"Decision: {decision}")
                print(f"Triggered: {triggered}")
    except FileNotFoundError:
        print(f"Log file not found: {file_path}")