"""
Password Security Auditor
Author: Patricia Naamala
Description: Analyzes passwords for strength, detects patterns attackers exploit,
             estimates crack time, checks against common breach lists,
             and generates cryptographically secure passwords.
             Built with Python standard library only.
"""

import re
import math
import secrets
import string
import hashlib
import urllib.request
import urllib.error
from datetime import datetime


# ──────────────────────────────────────────────
# Common Password Database (Top 200 most breached)
# ──────────────────────────────────────────────

COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "1234567",
    "1234567890", "qwerty", "abc123", "111111", "password1", "iloveyou",
    "admin", "letmein", "welcome", "monkey", "dragon", "master", "login",
    "passw0rd", "superman", "batman", "trustno1", "sunshine", "princess",
    "football", "shadow", "michael", "jessica", "password123", "qwerty123",
    "1q2w3e4r", "654321", "987654321", "pass", "test", "hello", "asdfgh",
    "zxcvbn", "987654", "qazwsx", "123321", "666666", "121212", "000000",
    "1111", "888888", "1234", "555555", "raspberry", "starwars", "donald",
    "charlie", "aa123456", "donald", "pokemon", "qwertyuiop", "mypassword",
    "soccer", "hockey", "baseball", "basketball", "andrew", "hunter",
    "george", "computer", "michelle", "corvette", "daniel", "harley",
    "ranger", "access", "matrix", "butter", "angel", "summer", "robert",
    "thomas", "123abc", "buster", "tigger", "hockey", "killer", "cheese",
    "pepper", "jordan", "jennifer", "taylor", "security", "pass123",
    "africa", "nairobi", "kenya2024", "safaricom", "mpesa", "equity",
}

# Keyboard walk patterns
KEYBOARD_WALKS = [
    "qwerty", "asdfgh", "zxcvbn", "qazwsx", "1qaz2wsx", "qweasdzxc",
    "1q2w3e", "1q2w3e4r", "zaq1xsw2", "qweqwe", "asdasd", "zxczxc",
]

# Common substitution patterns (leet speak)
LEET_MAP = str.maketrans("@4310!|83z5", "aaeioilbez5")


# ──────────────────────────────────────────────
# Entropy & Crack Time Estimation
# ──────────────────────────────────────────────

def calculate_entropy(password: str) -> float:
    """Calculate Shannon entropy of password in bits."""
    charset_size = 0
    if re.search(r'[a-z]', password): charset_size += 26
    if re.search(r'[A-Z]', password): charset_size += 26
    if re.search(r'\d', password):    charset_size += 10
    if re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password): charset_size += 32
    if charset_size == 0:             charset_size = 1
    return len(password) * math.log2(charset_size)


def estimate_crack_time(entropy: float) -> dict:
    """Estimate time to crack at various attack speeds."""
    # Guesses per second for different attack scenarios
    scenarios = {
        "Online attack (100/s)":         100,
        "Offline slow hash (10K/s)":      10_000,
        "Offline fast hash (1B/s)":       1_000_000_000,
        "Distributed GPU (100B/s)":       100_000_000_000,
    }
    results = {}
    total_guesses = 2 ** entropy

    for scenario, speed in scenarios.items():
        seconds = total_guesses / speed / 2  # average case
        results[scenario] = _format_time(seconds)

    return results


def _format_time(seconds: float) -> str:
    """Convert seconds to human-readable time."""
    if seconds < 1:           return "Instant"
    if seconds < 60:          return f"{seconds:.0f} seconds"
    if seconds < 3600:        return f"{seconds/60:.0f} minutes"
    if seconds < 86400:       return f"{seconds/3600:.0f} hours"
    if seconds < 2592000:     return f"{seconds/86400:.0f} days"
    if seconds < 31536000:    return f"{seconds/2592000:.0f} months"
    if seconds < 3153600000:  return f"{seconds/31536000:.0f} years"
    return "Centuries+"


# ──────────────────────────────────────────────
# Pattern Detection
# ──────────────────────────────────────────────

def detect_patterns(password: str) -> list:
    """Detect weak patterns attackers specifically target."""
    issues = []
    p = password.lower()

    # Common password check
    if p in COMMON_PASSWORDS:
        issues.append(("CRITICAL", "This exact password is in known breach databases"))

    # Leet speak normalization check
    normalized = p.translate(LEET_MAP)
    if normalized in COMMON_PASSWORDS and normalized != p:
        issues.append(("HIGH", f"Leet-speak variation of common password ('{normalized}')"))

    # Keyboard walk
    for walk in KEYBOARD_WALKS:
        if walk in p:
            issues.append(("HIGH", f"Contains keyboard walk pattern: '{walk}'"))
            break

    # Repeated characters
    if re.search(r'(.)\1{2,}', password):
        issues.append(("HIGH", "Contains 3+ repeated characters (e.g. 'aaa', '111')"))

    # Sequential numbers
    for seq in ["0123", "1234", "2345", "3456", "4567", "5678", "6789", "9876", "8765"]:
        if seq in p:
            issues.append(("MEDIUM", f"Contains sequential numbers: '{seq}'"))
            break

    # Sequential letters
    for seq in ["abcd", "efgh", "ijkl", "mnop", "qrst", "uvwx", "zyxw"]:
        if seq in p:
            issues.append(("MEDIUM", f"Contains sequential letters: '{seq}'"))
            break

    # Year patterns
    if re.search(r'(19|20)\d{2}', password):
        year = re.search(r'(19|20)\d{2}', password).group()
        issues.append(("MEDIUM", f"Contains a year ({year}) — predictable and commonly tried"))

    # Name + number pattern
    if re.search(r'^[a-zA-Z]+\d+$', password):
        issues.append(("MEDIUM", "Simple name+number pattern — one of the first things attackers try"))

    # Single word
    if re.search(r'^[a-zA-Z]+$', password) and len(password) < 12:
        issues.append(("HIGH", "Single word with no numbers or symbols — vulnerable to dictionary attack"))

    # Too short
    if len(password) < 8:
        issues.append(("CRITICAL", f"Password is only {len(password)} characters — minimum recommended is 12"))
    elif len(password) < 12:
        issues.append(("MEDIUM", f"Password is {len(password)} characters — 12+ strongly recommended"))

    # No uppercase
    if not re.search(r'[A-Z]', password):
        issues.append(("LOW", "No uppercase letters — reduces search space"))

    # No digits
    if not re.search(r'\d', password):
        issues.append(("LOW", "No numbers — reduces search space"))

    # No symbols
    if not re.search(r'[^a-zA-Z0-9]', password):
        issues.append(("LOW", "No special characters — reduces search space significantly"))

    return issues


# ──────────────────────────────────────────────
# HIBP Check (Have I Been Pwned)
# ──────────────────────────────────────────────

def check_hibp(password: str) -> tuple:
    """
    Check if password appears in Have I Been Pwned database.
    Uses k-anonymity — only first 5 chars of SHA1 hash sent to API.
    Your full password is NEVER transmitted.
    """
    try:
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]

        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        req = urllib.request.Request(url, headers={"User-Agent": "PasswordAuditor/1.0"})
        with urllib.request.urlopen(req, timeout=5) as response:
            hashes = response.read().decode()

        for line in hashes.splitlines():
            h, count = line.split(":")
            if h == suffix:
                return True, int(count)
        return False, 0
    except Exception:
        return None, 0  # API unavailable


# ──────────────────────────────────────────────
# Strength Scorer
# ──────────────────────────────────────────────

def score_password(password: str) -> tuple:
    """Return a score 0-100 and label."""
    entropy = calculate_entropy(password)
    patterns = detect_patterns(password)

    score = min(entropy * 1.5, 100)

    # Deduct for patterns
    deductions = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 5}
    for severity, _ in patterns:
        score -= deductions.get(severity, 0)

    score = max(0, min(100, score))

    if score >= 80:   label = "STRONG"
    elif score >= 60: label = "MODERATE"
    elif score >= 40: label = "WEAK"
    else:             label = "VERY WEAK"

    return round(score), label


def score_bar(score: int) -> str:
    """Visual score bar."""
    filled = int(score / 5)
    empty = 20 - filled
    return f"[{'█' * filled}{'░' * empty}] {score}/100"


# ──────────────────────────────────────────────
# Password Generator
# ──────────────────────────────────────────────

def generate_password(length: int = 16, mode: str = "mixed") -> str:
    """Generate a cryptographically secure password."""
    if mode == "memorable":
        # Word-based passphrase
        words = [
            "tiger", "cloud", "river", "stone", "flame", "swift", "noble",
            "bright", "storm", "lunar", "coral", "amber", "frost", "cedar",
            "solar", "pixel", "cyber", "forge", "vault", "prism", "nexus"
        ]
        chosen = [secrets.choice(words) for _ in range(4)]
        chosen[secrets.randbelow(4)] = chosen[secrets.randbelow(4)].capitalize()
        separator = secrets.choice(["-", "_", ".", "!"])
        number = secrets.randbelow(9000) + 1000
        return f"{separator.join(chosen)}{number}"

    elif mode == "pin":
        return "".join(secrets.choice(string.digits) for _ in range(length))

    else:  # mixed (default)
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
        while True:
            pwd = "".join(secrets.choice(alphabet) for _ in range(length))
            # Ensure all character types present
            if (re.search(r'[a-z]', pwd) and re.search(r'[A-Z]', pwd) and
                    re.search(r'\d', pwd) and re.search(r'[^a-zA-Z0-9]', pwd)):
                return pwd


# ──────────────────────────────────────────────
# Report Generator
# ──────────────────────────────────────────────

def audit_password(password: str, check_online: bool = True):
    """Run full audit and print report."""
    entropy = calculate_entropy(password)
    crack_times = estimate_crack_time(entropy)
    patterns = detect_patterns(password)
    score, label = score_password(password)

    print("\n╔══════════════════════════════════════════════════════════╗")
    print("║            PASSWORD SECURITY AUDITOR — REPORT            ║")
    print("╚══════════════════════════════════════════════════════════╝\n")

    # Mask password for display
    masked = password[0] + "*" * (len(password) - 2) + password[-1] if len(password) > 2 else "***"
    print(f"  Password    : {masked}  (length: {len(password)})")
    print(f"  Entropy     : {entropy:.1f} bits")
    print(f"  Strength    : {score_bar(score)}  [{label}]")

    # HIBP check
    if check_online:
        print(f"\n  Checking breach databases (HIBP)...", end=" ")
        breached, count = check_hibp(password)
        if breached is None:
            print("API unavailable — skipped")
        elif breached:
            print(f"\n   BREACHED — found {count:,} times in known data breaches!")
        else:
            print(" Not found in known breaches")

    # Crack time
    print("\n──────────────────────────────────────────────────────────")
    print("  ESTIMATED CRACK TIME")
    print("──────────────────────────────────────────────────────────")
    for scenario, t in crack_times.items():
        print(f"  {scenario:<35} {t}")

    # Pattern issues
    print("\n──────────────────────────────────────────────────────────")
    print("  SECURITY ISSUES DETECTED")
    print("──────────────────────────────────────────────────────────")
    if not patterns:
        print("  No major issues detected.")
    else:
        icons = {"CRITICAL": "⛔", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}
        for severity, issue in patterns:
            print(f"  {icons[severity]} [{severity}] {issue}")

    # Suggestions
    print("\n──────────────────────────────────────────────────────────")
    print("  SUGGESTED SECURE ALTERNATIVES")
    print("──────────────────────────────────────────────────────────")
    print(f"  Mixed (16 chars) : {generate_password(16, 'mixed')}")
    print(f"  Memorable phrase : {generate_password(mode='memorable')}")
    print(f"  Strong (20 chars): {generate_password(20, 'mixed')}")

    print("\n══════════════════════════════════════════════════════════\n")


# ──────────────────────────────────────────────
# Bulk Audit (for security teams)
# ──────────────────────────────────────────────

def bulk_audit(passwords: list):
    """Audit a list of passwords and print a summary table."""
    print("\n╔══════════════════════════════════════════════════════════╗")
    print("║               BULK PASSWORD AUDIT SUMMARY                ║")
    print("╚══════════════════════════════════════════════════════════╝\n")
    print(f"  {'#':<4} {'MASKED':<20} {'SCORE':<8} {'LABEL':<12} {'ENTROPY':<10} {'TOP ISSUE'}")
    print("  " + "─" * 75)

    for i, pwd in enumerate(passwords, 1):
        score, label = score_password(pwd)
        entropy = calculate_entropy(pwd)
        patterns = detect_patterns(pwd)
        top_issue = patterns[0][1][:40] if patterns else "None"
        masked = pwd[0] + "*" * (len(pwd) - 2) + pwd[-1] if len(pwd) > 2 else "***"
        print(f"  {i:<4} {masked:<20} {score:<8} {label:<12} {entropy:<10.1f} {top_issue}")

    weak = sum(1 for p in passwords if score_password(p)[1] in ("VERY WEAK", "WEAK"))
    print(f"\n  Total: {len(passwords)} passwords | Weak/Very Weak: {weak} ({weak/len(passwords)*100:.0f}%)\n")
    print("══════════════════════════════════════════════════════════\n")


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────

def main():
    print("""
╔══════════════════════════════════════════════╗
║         Password Security Auditor            ║
║           by Patricia Naamala                ║
╚══════════════════════════════════════════════╝
""")

    # Demo — audit a range of passwords
    print("  ── DEMO: Auditing sample passwords ──\n")
    demo_passwords = [
        "password123",
        "P@ssw0rd!",
        "Tr0ub4dor&3",
        "iloveyou",
        "X7#mK9$qL2@nP5!v",
    ]

    bulk_audit(demo_passwords)

    # Full audit on a couple
    for pwd in ["password123", "X7#mK9$qL2@nP5!v"]:
        audit_password(pwd, check_online=False)

    # Interactive
    print("  ── INTERACTIVE MODE ──\n")
    print("  Options:")
    print("  [1] Audit a password")
    print("  [2] Generate a secure password")
    print("  [3] Exit\n")

    choice = input("  Choose: ").strip()

    if choice == "1":
        pwd = input("  Enter password to audit: ")
        check = input("  Check against breach database? (y/n): ").lower() == "y"
        audit_password(pwd, check_online=check)
    elif choice == "2":
        print("\n  Generated passwords:")
        print(f"  Mixed (16)  : {generate_password(16, 'mixed')}")
        print(f"  Memorable   : {generate_password(mode='memorable')}")
        print(f"  Strong (20) : {generate_password(20, 'mixed')}")
        print()
    else:
        print("\n  Stay secure! \n")


if __name__ == "__main__":
    main()
