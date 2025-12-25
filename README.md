
<img width="600" height="600" alt="hashcatNexusLogo" src="https://github.com/user-attachments/assets/8bf90ff0-8cbd-4986-ba1c-3c768284ee9a" />

**Intelligent password cracking optimization tool for Hashcat**

HashcatNexus is a sophisticated wrapper that automates and optimizes hashcat-based password cracking attacks. It provides vendor-specific wordlist generation, rule selection, multi-phase attack orchestration, and real-time progress tracking.

### ⚠️ LEGAL NOTICE

**AUTHORIZED USE ONLY.** This tool is for security research, penetration testing, and password recovery on systems you own or have explicit written authorization to test. Unauthorized access is illegal under CFAA (18 U.S.C. § 1030), GDPR, Computer Misuse Act 1990, and equivalent laws worldwide. Users assume all legal responsibility.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Modes](#usage-modes)
  - [Interactive Wizard](#interactive-wizard)
  - [Command-Line Mode](#command-line-mode)
  - [Analysis Mode](#analysis-mode)
- [Command-Line Options](#command-line-options)
- [Vendor Support](#vendor-support)
- [Attack Strategies](#attack-strategies)
- [Rule System](#rule-system)
- [Examples](#examples)
- [Resource Management](#resource-management)
- [Legal Disclaimer](#legal-disclaimer)

---

## Features

- **Automatic Hash Detection** - Identifies 20+ hash types (MD5, NTLM, SHA256, WPA-PBKDF2, bcrypt, sha512crypt, etc.)
- **Vendor-Specific Optimization** - Generates realistic passwords for 14+ router vendors (Cisco, Netgear, Aruba, Ubiquiti, etc.)
- **Intelligent Rule Selection** - Auto-selects optimal rules based on hash type and system resources
- **Multi-Phase Attacks** - Orchestrates wordlist, hybrid (wordlist+mask), and brute force attacks
- **GPU/CPU Auto-Detection** - Detects and optimizes for Metal (Apple Silicon), CUDA, and OpenCL
- **Memory Profiles** - Adapts to system resources (Low/Medium/High/Extreme RAM configurations)
- **Session Management** - Resume interrupted attacks with `--session` flag
- **Real-Time Progress** - Displays cracked passwords and remaining hashes during execution
- **Attack Estimation** - Predicts time, speed, and success probability before execution

---

## Installation

### Prerequisites

- Python 3.7+
- Hashcat 6.0+
- Internet connection (for downloading rules/wordlists)

### Setup

```bash
# Clone the repository
git clone https://github.com/lukeswitz/hashcat-nexus.git
cd hashcat-nexus

# Install Python dependencies
pip3 install -r requirements.txt

# Run the tool
python3 HCNexus.py
```

**Dependencies:**
- `requests` - For downloading rules and wordlists from remote sources

HashcatNexus automatically creates `~/.hashcat_nexus/` for cached rules, wordlists, and vendor-generated dictionaries.

---

## Quick Start

### Basic Usage

```bash
# Interactive wizard (recommended for first-time users)
python3 HCNexus.py

# Direct attack on WPA handshake with Cisco vendor optimization
python3 HCNexus.py handshake.hc22000 -v cisco -p high -o cracked.txt

# Analyze hash file without executing
python3 HCNexus.py --analyze hashes.txt

# Auto-select optimal rules and execute
python3 HCNexus.py ntlm_hashes.txt -m 1000 --auto --strategy balanced
```

---

## Usage Modes

### Interactive Wizard

The wizard walks through all configuration steps with guided prompts:

```bash
python3 HCNexus.py
```

**15-Step Workflow:**

1. **Device Detection** - Scans for GPU/CPU capabilities
2. **Hash File Input** - Specify target hash file
3. **Hash Analysis** - Auto-detects hash type and mode
4. **Vendor Selection** (WPA only) - Choose 1+ vendors from 14 options
5. **Memory Profile** - Select based on available RAM
6. **Wordlist Configuration** - Scan system for existing wordlists
7. **Wordlist Selection** - Pick from found files or custom path
8. **Vendor Wordlist Generation** - Creates vendor-specific passwords
9. **Rule Calculation** - Tool auto-selects optimal rules
10. **Attack Estimation** - Shows speed, time, success probability
11. **Brute Force Masks** (WPA only) - Enable mask-based attacks
12. **Output Configuration** - Specify output file and session name
13. **Command Generation** - Builds final hashcat command
14. **Script Saving** - Option to save as executable bash script
15. **Execution** - Run attack immediately or save for later

### Command-Line Mode

Skip the wizard for automated or scripted attacks:

```bash
python3 HCNexus.py [hash_file] [options]
```

**Example:**

```bash
python3 HCNexus.py cisco_capture.hc22000 \
  -m 22000 \
  -v cisco,netgear \
  -p high \
  -o /tmp/cracked.txt \
  -s wpa_attack_jan2025 \
  -b
```

### Analysis Mode

Analyze hashes without executing an attack:

```bash
python3 HCNexus.py --analyze hashes.txt
```

**Output (JSON):**

```json
{
  "total_hashes": 1520,
  "detected_type": "WPA-PBKDF2-PMKID+EAPOL",
  "hash_mode": 22000,
  "unique_salts": 0,
  "estimated_complexity": "Very High",
  "recommended_approach": "WPA/WPA2: Use vendor-specific rules + wordlists + brute force with masks",
  "analysis_timestamp": "2025-01-22T14:30:22.123456"
}
```

---

## Command-Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `hash_file` | Path to hash file | `hashes.txt` |
| `-m, --hash-type` | Hashcat mode (auto-detected if omitted) | `-m 1000` |
| `-w, --wordlist` | Path to wordlist | `-w /usr/share/wordlists/rockyou.txt` |
| `-v, --vendor` | WPA vendor(s), comma-separated | `-v cisco,netgear,tp-link` |
| `-p, --profile` | Memory profile: `low`, `medium`, `high`, `extreme` | `-p high` |
| `-o, --output` | Output file for cracked passwords | `-o cracked.txt` |
| `-s, --session` | Session name for resuming | `-s wpa_attack_jan2025` |
| `-b, --brute` | Enable brute force masks (WPA only) | `-b` |
| `--analyze` | Analyze hash file only (no execution) | `--analyze` |
| `--auto` | Auto-select optimal rules | `--auto` |
| `--strategy` | Attack strategy: `quick`, `balanced`, `comprehensive`, `maximum` | `--strategy comprehensive` |
| `--list-rules` | List available rules with performance metrics | `--list-rules` |
| `--list-wordlists` | List available wordlists | `--list-wordlists` |
| `--download-rule` | Download specific rule | `--download-rule OneRuleToRuleThemAll` |
| `--download-wordlist` | Download specific wordlist | `--download-wordlist rockyou` |
| `--download-all-rules` | Download all top-tier rules | `--download-all-rules` |

---

## Vendor Support

HashcatNexus generates realistic vendor-specific passwords for **14 router vendors**:

| Vendor | Pattern Example | Description |
|--------|----------------|-------------|
| **Technicolor** | `circle4298empty` | Adjective + 4 digits + noun (Cox/Xfinity) |
| **Spectrum** | `sharpedge123` | Adjective + noun + digits |
| **Cisco** | `Cisco@2024`, `WLC@2024` | Corporate patterns with years |
| **Aruba** | `Aruba@123`, `AP2024` | Enterprise-focused with model prefixes |
| **Ruckus** | `Ruckus!123`, `Unleashed2024` | Z-series models and Unleashed systems |
| **Ubiquiti** | `ubnt@2024`, `UniFi123` | Default "ubnt" patterns + UniFi series |
| **Meraki** | `Meraki@123`, `MX2024` | Cisco Meraki dashboard patterns |
| **Netgear** | `happyunicorn123` | Adjective + noun + 3 digits (most predictable) |
| **TP-Link** | `12345678`, `Archer2024` | 8-digit numbers + model patterns |
| **ASUS** | `RT-AX2024`, `ZenWiFi!` | RT model numbers + AiMesh |
| **D-Link** | `DIR-2024`, `DLINK@123` | DIR model patterns |
| **Linksys** | `EA@2024`, `Velop!2024` | EA/Velop mesh systems |
| **MikroTik** | `RouterOS@123`, `RB@2024` | RouterOS + RB model patterns |
| **Generic** | `Company@2024`, `P@ssw0rd` | Fallback for unknown vendors |

**Wordlist Generation:**

When you select a vendor, HashcatNexus automatically generates **50,000-100,000 realistic passwords** based on known patterns, including capitalization and special character variations.

Generated wordlists are saved to: `~/.hashcat_nexus/wordlists/{vendor}_passwords.txt`

---

## Attack Strategies

HashcatNexus supports **4 attack strategies** (use with `--strategy` flag):

### 1. Quick
- **Rules:** Unicorn64, best64 (WPA); clem_small, Unicorn64 (slow hashes)
- **Use Case:** Fast initial reconnaissance, time-constrained attacks
- **Est. Time:** 15-30 minutes

### 2. Balanced (Default)
- **Rules:** kaonashi, best64, OneRuleToRuleThemAll, Unicorn250
- **Use Case:** Best balance of time and coverage
- **Est. Time:** 2-4 hours

### 3. Comprehensive
- **Rules:** OneRuleToRuleThemAll, Dive, d3ad0ne, Unicorn1000
- **Use Case:** Thorough attacks with extended time
- **Est. Time:** 8-12 hours

### 4. Maximum
- **Rules:** OneRuleToRuleThemAll, Dive, d3ad0ne, InsidePro-PasswordsPro
- **Use Case:** Exhaustive attacks with unlimited time
- **Est. Time:** 24+ hours

---

## Rule System

HashcatNexus includes **15+ high-performance rules** with performance metrics:

| Rule | Performance | Speed | Coverage | Memory | Best For |
|------|------------|-------|----------|--------|----------|
| **OneRuleToRuleThemAll** | 9.4/10 | 4.63 MH/s | 3.1 | Low | All hash types |
| **Unicorn64** | 9.4/10 | 4.70 MH/s | 3.0 | Low | Fast, high-value |
| **best64** | 9.2/10 | 4.85 MH/s | 2.8 | Low | Quick wins |
| **kaonashi** | 8.8/10 | 4.55 MH/s | 3.2 | Low | Balanced coverage |
| **hashpwn_1500** | 8.6/10 | 4.45 MH/s | 3.0 | Medium | WPA/WPA2 |
| **SlowHashes** | 6.5/10 | 0.85 MH/s | 3.5 | Low | bcrypt, sha512crypt |
| **InsidePro-PasswordsPro** | 8.2/10 | 0.95 MH/s | 4.0 | High | Comprehensive slow |

### Auto-Selection Logic

Rules are automatically selected based on:

1. **Hash Type** - WPA gets hashpwn_1500, leetspeak; NTLM gets Dive, Hob064; bcrypt gets SlowHashes
2. **Memory Profile** - Low removes memory-intensive rules (generated2, InsidePro)
3. **Vendor** - Cisco/Netgear/TP-Link trigger vendor-specific wordlist generation
4. **Strategy** - Quick uses 2 rules, Balanced uses 4, Comprehensive uses 4, Maximum uses 4

### Manual Rule Management

```bash
# List all available rules
python3 HCNexus.py --list-rules

# Download specific rule
python3 HCNexus.py --download-rule OneRuleToRuleThemAll

# Download all top-tier rules
python3 HCNexus.py --download-all-rules
```

---

## Multi-Phase Attack System

HashcatNexus orchestrates **3 attack phases** when brute force is enabled:

### Phase 1: Wordlist + Rules
- **Method:** Dictionary attack with selected rules
- **Example:** `hashcat -m 22000 -a 0 hashes.txt rockyou.txt -r OneRuleToRuleThemAll.rule`

### Phase 1.5: Hybrid Attack (New in v3.0)
- **Method:** Wordlist + mask patterns (based on NetSPI & Rapid7 2025 research)
- **Masks:** `?d?d` (password + 2 digits), `?d?d?d?d` (year), `?s` (special char), `?d?d?s` (combo)
- **Example:** `hashcat -m 22000 -a 6 hashes.txt rockyou.txt ?d?d?d?d`
- **Benefit:** 29%+ improvement in crack rate

### Phase 2: Pure Brute Force
- **Method:** Mask-only patterns for remaining uncracked hashes
- **Masks:** `?l?l?l?l?l?l?d?d` (6 lowercase + 2 digits), `?l?l?l?l?l?l?l?l` (8 lowercase)
- **Example:** `hashcat -m 22000 -a 3 hashes.txt ?l?l?l?l?l?l?d?d`

Each phase checks progress and offers resume options via sessions.

---

## Examples

### Example 1: Crack NTLM Hashes from Domain Controller

```bash
python3 HCNexus.py ntlm_hashes.txt
# Interactive wizard prompts:
# - Enter mode: 1000 (or auto-detected)
# - Memory profile: 3 (High)
# - Select rockyou.txt
# - Tool auto-selects: OneRuleToRuleThemAll, best64, Dive, Hob064
# - Execute: y
```

### Example 2: Target Cisco Router WPA Handshake

```bash
python3 HCNexus.py cisco_capture.hc22000 \
  -v cisco \
  -p medium \
  -o /tmp/cisco_cracked.txt \
  -s cisco_jan2025 \
  -b
```

**What happens:**
1. Auto-detects WPA-PBKDF2-PMKID+EAPOL (mode 22000)
2. Generates Cisco-specific wordlist (100,000 passwords)
3. Selects rules: OneRuleToRuleThemAll, best64, hashpwn_1500, Unicorn64
4. Runs Phase 1 (wordlist + rules)
5. Runs Phase 1.5 (hybrid with `?d?d?d?d` masks)
6. Runs Phase 2 (brute force masks)
7. Results saved to `/tmp/cisco_cracked.txt` as `SSID:PASSWORD`

### Example 3: Multi-Vendor WPA Attack

```bash
python3 HCNexus.py handshake.hc22000 -v netgear,tp-link,asus -p high --auto
```

**What happens:**
- Generates 3 vendor-specific wordlists (150,000+ total passwords)
- Auto-selects balanced rules for WPA
- Executes immediately without prompts

### Example 4: Save Attack Script for Later

```bash
python3 HCNexus.py hashes.txt
# Complete wizard steps
# Save as script: y
# Script saved as: attack_20250122_143022.sh
# Execute now: n

# Later:
./attack_20250122_143022.sh
```

### Example 5: Analyze bcrypt Hashes

```bash
python3 HCNexus.py --analyze bcrypt_hashes.txt
```

**Output:**

```json
{
  "detected_type": "bcrypt",
  "hash_mode": 3200,
  "estimated_complexity": "Very High (likely bcrypt/sha512crypt)",
  "recommended_approach": "Slow hash: Use optimized rulesets (SlowHashes) + focused wordlists"
}
```

### Example 6: Quick Test with Specific Strategy

```bash
python3 HCNexus.py ntlm_hashes.txt --auto --strategy quick -o results.txt
```

**What happens:**
- Uses "quick" strategy (Unicorn64, best64)
- Auto-selects rules without prompts
- Executes immediately
- Results saved to `results.txt`

---

## Resource Management

### Memory Profiles

HashcatNexus adapts to system resources with **4 memory profiles**:

| Profile | RAM | Workload (`-w`) | Optimization (`-O`) | Max Password Length |
|---------|-----|----------------|---------------------|---------------------|
| **Low** | < 4GB | 1 | Disabled | 8 characters |
| **Medium** | 4-8GB | 2 | Enabled | 12 characters |
| **High** | 8-16GB | 3 | Enabled | 14 characters |
| **Extreme** | > 16GB | 4 | Enabled | 16 characters |

### Device Detection

HashcatNexus auto-detects:

- **Metal** (Apple Silicon) - `-D 2` (GPU)
- **CUDA** (NVIDIA) - `-D 2` (GPU)
- **OpenCL** (AMD/Intel GPU) - `-D 2` (GPU)
- **CPU** - `-D 1` (CPU fallback)

GPU memory allocation is displayed during device detection.

### Attack Estimation

Before execution, HashcatNexus estimates:

- **Speed** - Based on hash type baselines (MD5: 15 MH/s, NTLM: 8 MH/s, WPA: 250 H/s, bcrypt: 10 H/s)
- **Total Candidates** - Wordlist size × rule count
- **Estimated Time** - Candidates ÷ speed
- **Success Probability** - Based on wordlist quality and hash type

**Example Output:**

```
Attack Estimation:
- Estimated speed: 12,456,000 H/s
- Total candidates: 1,234,567,890
- Estimated time: 2.5 hours
- Success probability: 67.2%
- Recommendation: Good coverage expected
```

---

## Session Management

Resume interrupted attacks with session names:

```bash
# Start attack with session
python3 HCNexus.py hashes.txt -s my_attack_jan2025

# Later, resume from checkpoint
hashcat --session my_attack_jan2025 --restore
```

HashcatNexus automatically includes `--session` flag in generated commands when specified.

---

## Wordlist Management

### List Available Wordlists

```bash
python3 HCNexus.py --list-wordlists
```

**Output:**

```
AVAILABLE WORDLISTS
Name                          Size       Passwords       Method     Status
rockyou                        134MB      14,341,564      direct     Downloaded
rockyou2024                    92GB       9,948,575,739   manual     Available
weakpass_3                     7GB        3,700,000,000   direct     Available
Top12Million-probable-v2       105MB      12,000,000      direct     Downloaded
```

### Download Wordlists

```bash
# Download specific wordlist
python3 HCNexus.py --download-wordlist rockyou

# Interactive wizard offers to download missing wordlists
python3 HCNexus.py
# Wizard checks for: rockyou.txt, Top12Thousand-probable-v2.txt, darkweb2017-top10000.txt
# Prompt: Download missing wordlists? (y/N)
```

### Common Wordlist Locations

HashcatNexus scans:

1. `/usr/share/wordlists` (Kali Linux default)
2. `~/wordlists`
3. `~/.hashcat_nexus` (HashcatNexus default)
4. Custom paths (user-specified)

---

## Output Formats

### WPA/WPA2

```
SSID:PASSWORD
RouterNetwork:Cisco@2024
GuestWifi:netgear5891bear
```

### Other Hash Types

```
password123
Welcome2024
P@ssw0rd
```

Or with hash:password format:

```
5f4dcc3b5aa765d61d8327deb882cf99:password
8846f7eaee8fb117ad06bdd830b7586c:password123
```

---

## Troubleshooting

### Issue: "ModuleNotFoundError: No module named 'requests'"

**Solution:** Install Python dependencies:

```bash
# Install requirements
pip3 install -r requirements.txt

# Or install directly
pip3 install requests
```

### Issue: "Hashcat not found"

**Solution:** Ensure hashcat is installed and in PATH:

```bash
# Test hashcat
hashcat --version

# Install on Kali Linux
sudo apt install hashcat

# macOS with Homebrew
brew install hashcat
```

### Issue: "No GPU detected"

**Solution:** HashcatNexus falls back to CPU. For GPU support:

- **NVIDIA:** Install CUDA drivers
- **AMD:** Install OpenCL drivers
- **Apple Silicon:** Metal is built-in (macOS 11+)

### Issue: "Rule not found"

**Solution:** Download missing rules:

```bash
python3 HCNexus.py --download-all-rules
```

### Issue: "Wordlist not found"

**Solution:** Specify wordlist path or download:

```bash
python3 HCNexus.py --download-wordlist rockyou
```

---

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-vendor`)
3. Commit changes (`git commit -am 'Add Fortinet vendor support'`)
4. Push to branch (`git push origin feature/new-vendor`)
5. Open a Pull Request

---

## License

MIT License - See [LICENSE](LICENSE) for details.

---

## Acknowledgments

- **Hashcat Team** - Core cracking engine
- **NetSPI & Rapid7** - Hybrid attack research (2025)
- **Rule Authors** - OneRuleToRuleThemAll, Kaonashi, Dive, InsidePro, and other contributors
- **Wordlist Curators** - rockyou, weakpass, and other password datasets

---

## Legal Disclaimer

### Authorized Use Only

HashcatNexus is provided exclusively for:
- Penetration testing on systems you own
- Security audits with explicit written authorization
- Password recovery for your own accounts/systems
- Educational research in authorized environments

### Prohibited Activities

Unauthorized access to computer systems violates:
- Computer Fraud and Abuse Act (CFAA) - 18 U.S.C. § 1030 (US)
- Computer Misuse Act 1990 (UK)
- GDPR Articles 32-34 (EU)
- Budapest Convention on Cybercrime
- Equivalent laws in your jurisdiction

**Do not:**
- Attack networks without documented authorization
- Access wireless networks you do not own
- Bypass authentication on unauthorized systems
- Use this tool for malicious or illegal purposes

### Limitation of Liability

THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. THE AUTHORS:
- Disclaim all warranties including merchantability and fitness for purpose
- Accept no liability for damages, data loss, or legal consequences
- Provide no guarantee of functionality or security
- Are not responsible for user actions or compliance failures

### Your Responsibilities

By using this software, you agree that:
- You are solely responsible for lawful use in your jurisdiction
- You will obtain proper authorization before testing any system
- You will comply with all applicable laws and regulations
- You understand legal risks of unauthorized access
- You indemnify the authors against claims from your use

### No Endorsement of Illegal Activity

This tool does not encourage or endorse unauthorized access. It is developed exclusively for legitimate security professionals operating within legal boundaries.

---

**BY USING THIS SOFTWARE, YOU ACCEPT THESE TERMS AND FULL RESPONSIBILITY FOR YOUR ACTIONS.**

---

**HashcatNexus** - Making password cracking smarter, not harder.
