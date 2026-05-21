Password auditor  

Password Security Auditor
A Python tool that performs deep security analysis on passwords — detecting weak patterns, estimating crack times, checking breach databases, and generating cryptographically secure alternatives. Built with zero external dependencies.

 Background
Weak and reused passwords remain the #1 cause of account breaches. This tool was built to demonstrate practical knowledge of password security, cryptographic hashing, and attack methodologies — skills directly applicable to security auditing and identity management roles.

Features

Strength scoring — 0–100 score based on entropy + pattern analysis
Entropy calculation — measures true randomness in bits
Crack time estimation — estimates time to crack across 4 attack scenarios (online, offline slow/fast, GPU cluster)
Pattern detection — catches 10+ weak patterns including:

Common/breached passwords (200+ database)
Leet speak variations (p@ssw0rd → password)
Keyboard walks (qwerty, 1q2w3e4r)
Sequential numbers/letters, repeated characters
Year patterns (Kenya2024), name+number combos


Have I Been Pwned integration — checks if password appears in real breach data using k-anonymity (your password is never sent to the API)
Secure password generator — 3 modes: mixed, memorable passphrase, PIN
Bulk audit mode — audit multiple passwords at once (for security teams)
Zero dependencies — pure Python standard library


 Usage
Requirements
bashPython 3.8+
No pip installs needed
Internet connection (optional — for HIBP breach check)
Run the auditor
bashpython auditor.py

 Example Output
  Password    : p***3  (length: 11)
  Entropy     : 18.4 bits
  Strength    : [███░░░░░░░░░░░░░░░░░] 22/100  [VERY WEAK]

  Checking breach databases (HIBP)...  BREACHED — found 2,347,891 times!

  ESTIMATED CRACK TIME
  Online attack (100/s)              3 minutes
  Offline slow hash (10K/s)          Instant
  Offline fast hash (1B/s)           Instant
  Distributed GPU (100B/s)           Instant

  SECURITY ISSUES DETECTED
   [CRITICAL] This exact password is in known breach databases
   [HIGH]     Single word with no symbols — vulnerable to dictionary attack
   [MEDIUM]   Contains a year (2023) — predictable and commonly tried

  SUGGESTED SECURE ALTERNATIVES
  Mixed (16 chars) : R#7mK2@xL9$qP4!n
  Memorable phrase : frost-cyber-lunar-noble!4821
  Strong (20 chars): W$3kM#9pL@2nX7!qR5&v

 Key Concepts Demonstrated
ConceptImplementationCryptographic HashingSHA-1 via hashlib for HIBP k-anonymity checkInformation TheoryShannon entropy calculation for true password strengthSecure Randomnesssecrets module for cryptographically secure generationAttack MethodologyCrack time modeled on real GPU/botnet attack speedsPattern RecognitionRegex + dictionary matching for 10+ weak patternsAPI IntegrationHIBP REST API with privacy-preserving k-anonymitySecurity AuditingBulk analysis mode for evaluating multiple credentials

Privacy Note
The Have I Been Pwned check uses k-anonymity:

Only the first 5 characters of your password's SHA-1 hash are sent to the API
Your actual password never leaves your machine
This is the same method used by Firefox Monitor and 1Password


Disclaimer
This tool is for educational and authorized security auditing only. Do not use it to audit passwords you do not own or have permission to test.

 Author
Patricia Naamala
Cybersecurity Student — USIU-Africa
LinkedIn | GitHub
