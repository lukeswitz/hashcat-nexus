#!/usr/bin/env python3
"""
HASHCAT NEXUS v3.0 - Next-Generation Password Cracking Optimizer
Auto-detects hash types, vendor-specific schemas, and builds optimal attacks

# Interactive mode
python3 hashcat_nexus.py

# Command line mode
python3 hashcat_nexus.py hashes.txt -m 22000 -v cisco -p high

# Analyze only
python3 hashcat_nexus.py --analyze hashes.txt

# Quick launcher
./hashcat-nexus.sh
./hashcat-nexus.sh --update
./hashcat-nexus.sh --analyze handshake.pcap
"""

import os
import sys
import re
import json
import hashlib
import subprocess
import argparse
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
import requests
from dataclasses import dataclass
import math

@dataclass
class HashInfo:
    """Auto-detected hash information"""
    mode: int
    name: str
    pattern: str
    length: Tuple[int, int]
    example: str
    vendor_specific: bool = False
    wpa_type: str = ""

@dataclass
class AttackProfile:
    """Optimized attack configuration"""
    rules: List[str]
    wordlists: List[str]
    masks: List[str]
    optimizations: Dict[str, Any]
    estimated_time: str
    success_probability: float
    memory_profile: str  # 'low', 'medium', 'high'


class HashcatNexus:
    def __init__(self):
        self.rules_dir = Path("~/.hashcat_nexus").expanduser()
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        self.wordlists_dir = self.rules_dir / "wordlists"
        self.wordlists_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file = self.rules_dir / "rule_cache.json"
        self.benchmark_file = self.rules_dir / "benchmark.json"

        # Verify hashcat is installed
        self._verify_hashcat_installation()

        # Initialize wordlist database
        self.wordlist_db = self._initialize_wordlist_database()

        # Enhanced hash detection database
        self.hash_patterns = self._load_hash_patterns()

        # WPA vendor database with descriptions
        self.wpa_vendors = self._load_wpa_vendors()

        # Rule performance database
        self.rule_db = self._initialize_rule_database()

        # Memory profiles
        self.memory_profiles = {
            'low': {'w': '1', 'O': False, 'max_len': '8'},
            'medium': {'w': '2', 'O': True, 'max_len': '12'},
            'high': {'w': '3', 'O': True, 'max_len': '14'},
            'extreme': {'w': '4', 'O': True, 'max_len': '16'}
        }

    def _verify_hashcat_installation(self):
        """Verify hashcat is installed and accessible"""
        try:
            result = subprocess.run(['hashcat', '--version'],
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                version = result.stdout.strip().split('\n')[0] if result.stdout else "Unknown"
                print(f"✓ Hashcat detected: {version}")
            else:
                print("⚠️  Hashcat found but version check failed")
        except FileNotFoundError:
            print("\n" + "=" * 80)
            print("ERROR: Hashcat not found!")
            print("=" * 80)
            print("\nPlease install hashcat:")
            print("  macOS:   brew install hashcat")
            print("  Ubuntu:  sudo apt install hashcat")
            print("  Arch:    sudo pacman -S hashcat")
            print("  Manual:  https://hashcat.net/hashcat/")
            print("=" * 80)
            sys.exit(1)
        except Exception as e:
            print(f"⚠️  Could not verify hashcat installation: {e}")

    def _load_hash_patterns(self) -> Dict[int, HashInfo]:
        """Load comprehensive hash type patterns"""
        patterns = {
            0: HashInfo(0, "MD5", r'^[a-f0-9]{32}$', (32, 32), "5f4dcc3b5aa765d61d8327deb882cf99"),
            1000: HashInfo(1000, "NTLM", r'^[a-f0-9]{32}$', (32, 32), "8846f7eaee8fb117ad06bdd830b7586c"),
            1400: HashInfo(1400, "SHA256", r'^[a-f0-9]{64}$', (64, 64), "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"),
            22000: HashInfo(22000, "WPA-PBKDF2-PMKID+EAPOL", r'^WPA\*01\*02\*03\*', (0, 0), "", True, "generic"),
            22001: HashInfo(22001, "WPA-PMKID-PMK", r'^WPA\*01\*', (0, 0), "", True, "generic"),
            2500: HashInfo(2500, "WPA-EAPOL-PBKDF2", r'^\$WPAPSK\$\$', (0, 0), "", True, "generic"),
            3200: HashInfo(3200, "bcrypt", r'^\$2[aby]\$\d+\$[./A-Za-z0-9]{53}$', (60, 60), "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"),
            500: HashInfo(500, "md5crypt", r'^\$1\$[./A-Za-z0-9]{8}\$[./A-Za-z0-9]{22}$', (34, 34), "$1$salt$hash"),
            1800: HashInfo(1800, "sha512crypt", r'^\$6\$[./A-Za-z0-9]{16}\$[./A-Za-z0-9]{86}$', (106, 106), "$6$salt$hash"),
        }
        return patterns

    def _load_wpa_vendors(self) -> Dict[str, Dict]:
        """Load WPA vendor-specific password patterns"""
        return {
            'technicolor': {
                'masks': ['circle4298empty', 'chore4982become', 'apple1234orange'],
                'rules': ['router_specific'],
                'wordlists': ['technicolor_passwords.txt'],
                'common_patterns': ['[a-z]{5,6}[0-9]{4}[a-z]{5,6}'],
                'description': 'Cox/Xfinity routers - word+digits+word pattern'
            },
            'spectrum': {
                'masks': ['sharpedge123', 'keenmind456', 'clearlogic789'],
                'rules': ['router_specific'],
                'wordlists': ['spectrum_passwords.txt'],
                'common_patterns': ['[a-z]{4,6}[a-z]{4,6}[0-9]{3}'],
                'description': 'Spectrum routers - adjective+noun+digits'
            },
            'cisco': {
                'masks': ['Cisco123', 'cisco@2023', 'C1sc0123!', 'WLC@2024'],
                'rules': ['cisco.rule', 'vendor_cisco.rule'],
                'wordlists': ['cisco_passwords.txt'],
                'common_patterns': ['[Cc]isco[0-9]{4}', '[Cc][0-9]{8}', 'WLC[0-9]{6}'],
                'description': 'Cisco enterprise APs & WLCs - corporate patterns'
            },
            'aruba': {
                'masks': ['Aruba@123', 'aruba2024', 'A1ruba!2024'],
                'rules': ['aruba.rule', 'vendor_aruba.rule'],
                'wordlists': ['aruba_passwords.txt'],
                'common_patterns': ['[Aa]ruba[0-9]{4}', 'AP[0-9]{6}', 'mobility[0-9]{4}'],
                'description': 'Aruba enterprise WiFi - mobility/AP patterns'
            },
            'ruckus': {
                'masks': ['Ruckus!123', 'ruckus2024', 'R1ckus@2024'],
                'rules': ['ruckus.rule', 'vendor_ruckus.rule'],
                'wordlists': ['ruckus_passwords.txt'],
                'common_patterns': ['[Rr]uckus[0-9]{4}', 'Z[0-9]{8}', 'unleashed[0-9]{4}'],
                'description': 'Ruckus/CommScope APs - Unleashed systems'
            },
            'ubiquiti': {
                'masks': ['ubnt@2024', 'Ub1qu1t1!', 'UBNT2024'],
                'rules': ['ubiquiti.rule', 'vendor_ubiquiti.rule'],
                'wordlists': ['ubiquiti_passwords.txt'],
                'common_patterns': ['ubnt[0-9]{4}', 'UBNT[0-9]{6}', '[Aa]ir[0-9]{6}'],
                'description': 'Ubiquiti UniFi/AirMax - default ubnt patterns'
            },
            'meraki': {
                'masks': ['Meraki@123', 'm3raki2024', 'CiscoMeraki!'],
                'rules': ['meraki.rule', 'vendor_meraki.rule'],
                'wordlists': ['meraki_passwords.txt'],
                'common_patterns': ['[Mm]eraki[0-9]{4}', 'MX[0-9]{8}', 'dashboard[0-9]{4}'],
                'description': 'Cisco Meraki cloud-managed - dashboard patterns'
            },
            'netgear': {
                'masks': ['password123', 'netgear@2024', 'N3tg3ar!', 'Nighthawk2024'],
                'rules': ['netgear.rule', 'vendor_netgear.rule'],
                'wordlists': ['netgear_passwords.txt'],
                'common_patterns': ['[Nn]etgear[0-9]{4}', '[A-Za-z]{4,}[A-Za-z]{4,}[0-9]{3,4}'],
                'description': 'Netgear routers - adjective+noun+3digits pattern'
            },
            'tp-link': {
                'masks': ['12345678', 'tplink2024', 'Archer@123', 'TP@2024'],
                'rules': ['tplink.rule', 'vendor_tplink.rule'],
                'wordlists': ['tplink_passwords.txt'],
                'common_patterns': ['[0-9]{8}', '[Tt][Pp][0-9]{4,6}'],
                'description': 'TP-Link routers - often 8-digit numeric defaults'
            },
            'asus': {
                'masks': ['asus2024', 'ASUS@123', 'RT-AX2024', 'ZenWiFi!'],
                'rules': ['asus.rule', 'vendor_asus.rule'],
                'wordlists': ['asus_passwords.txt'],
                'common_patterns': ['[Aa]sus[0-9]{4}', 'RT-[A-Z]{2}[0-9]{4}'],
                'description': 'ASUS routers - RT/AiMesh model patterns'
            },
            'd-link': {
                'masks': ['dlink2024', 'DLINK@123', 'DIR-2024', 'D@link!'],
                'rules': ['dlink.rule', 'vendor_dlink.rule'],
                'wordlists': ['dlink_passwords.txt'],
                'common_patterns': ['[Dd]link[0-9]{4}', 'DIR-[0-9]{3,5}'],
                'description': 'D-Link routers - DIR model patterns'
            },
            'linksys': {
                'masks': ['linksys2024', 'Linksys@123', 'EA@2024', 'Velop!2024'],
                'rules': ['linksys.rule', 'vendor_linksys.rule'],
                'wordlists': ['linksys_passwords.txt'],
                'common_patterns': ['[Ll]inksys[0-9]{4}', 'EA[0-9]{4}'],
                'description': 'Linksys routers - EA/Velop mesh systems'
            },
            'mikrotik': {
                'masks': ['mikrotik2024', 'MikroTik@123', 'RouterOS!', 'RB@2024'],
                'rules': ['mikrotik.rule', 'vendor_mikrotik.rule'],
                'wordlists': ['mikrotik_passwords.txt'],
                'common_patterns': ['[Mm]ikrotik[0-9]{4}', 'RB[0-9]{3,5}'],
                'description': 'MikroTik RouterOS - RB model patterns'
            },
            'generic': {
                'masks': ['Company@2024', 'Welcome123!', 'P@ssw0rd', 'Admin@123'],
                'rules': ['best64.rule', 'OneRuleToRuleThemAll.rule'],
                'wordlists': ['rockyou.txt'],
                'common_patterns': ['[A-Z][a-z]+[0-9]{2,4}', '[0-9]{8}', '[A-Za-z]+@[0-9]{4}'],
                'description': 'Generic/Unknown - standard password patterns'
            }
        }

    def _initialize_rule_database(self) -> Dict:
        """Initialize with modern, high-performance rules"""
        rule_sources = {
            # Core high-performance rules
            'OneRuleToRuleThemAll': {
                'url': 'https://raw.githubusercontent.com/NotSoSecure/password_cracking_rules/master/OneRuleToRuleThemAll.rule',
                'performance': 9.4,
                'speed': '4.63 MH/s',
                'coverage': 3.1,
                'memory_footprint': 'low',
                'hash_types': [0, 1000, 1400, 22000, 2500],
                'description': 'All-round champion rule'
            },
            'OneRuleToRuleThemStill': {
                'url': 'https://raw.githubusercontent.com/NotSoSecure/password_cracking_rules/master/OneRuleToRuleThemStill.rule',
                'performance': 8.9,
                'speed': '4.52 MH/s',
                'coverage': 2.8,
                'memory_footprint': 'low',
                'hash_types': [0, 1000, 1400],
                'description': 'Updated version with better coverage'
            },
            'hashpwn_1500': {
                'url': 'https://raw.githubusercontent.com/hashpwn/rules/main/hashpwn_1500.rule',
                'performance': 8.8,
                'speed': '4.50 MH/s',
                'coverage': 2.9,
                'memory_footprint': 'low',
                'hash_types': [22000, 2500, 1000],
                'description': 'Top 1500 rules from hashpwn - excellent for WPA'
            },
            'hashpwn_3000': {
                'url': 'https://raw.githubusercontent.com/hashpwn/rules/main/hashpwn_3000.rule',
                'performance': 8.6,
                'speed': '4.45 MH/s',
                'coverage': 3.0,
                'memory_footprint': 'medium',
                'hash_types': [22000, 2500],
                'description': 'Top 3000 rules for comprehensive WPA coverage'
            },
            'Unicorn64': {
                'url': 'https://raw.githubusercontent.com/Unic0rn28/hashcat-rules/main/unicorn%20rules/Unicorn64.rule',
                'performance': 8.7,
                'speed': '4.48 MH/s',
                'coverage': 2.8,
                'memory_footprint': 'low',
                'hash_types': [22000, 2500],
                'description': 'Top 64 rules from massive hash analysis'
            },
            'Unicorn250': {
                'url': 'https://raw.githubusercontent.com/Unic0rn28/hashcat-rules/main/unicorn%20rules/Unicorn250.rule',
                'performance': 8.5,
                'speed': '4.42 MH/s',
                'coverage': 2.9,
                'memory_footprint': 'low',
                'hash_types': [22000, 2500],
                'description': 'Top 250 rules - balanced approach'
            },
            # Vendor-specific rules
            'router_specific': {
                'url': 'https://raw.githubusercontent.com/initstring/passphrase-wordlist/master/hashcat-rules/passphrase-rule2.rule',
                'performance': 7.5,
                'speed': '2.80 MH/s',
                'coverage': 4.5,
                'memory_footprint': 'high',
                'hash_types': [22000, 2500],
                'description': 'Passphrase rules for long router passwords'
            },
            'Dive': {
                'url': 'https://raw.githubusercontent.com/hashcat/hashcat/master/rules/dive.rule',
                'performance': 8.2,
                'speed': '4.35 MH/s',
                'coverage': 2.9,
                'memory_footprint': 'low',
                'hash_types': [0, 1000, 1400],
                'description': 'Deep rule set for comprehensive attacks'
            },
            'hob064': {
                'url': 'https://raw.githubusercontent.com/praetorian-inc/Hob0Rules/master/hob064.rule',
                'performance': 8.0,
                'speed': '4.30 MH/s',
                'coverage': 2.7,
                'memory_footprint': 'low',
                'hash_types': [0, 1000, 1400],
                'description': '64 best rules optimized for speed'
            },
            'InsidePro-PasswordsPro': {
                'url': 'https://raw.githubusercontent.com/hashcat/hashcat/master/rules/InsidePro-PasswordsPro.rule',
                'performance': 7.8,
                'speed': '4.25 MH/s',
                'coverage': 2.5,
                'memory_footprint': 'medium',
                'hash_types': [500, 1800, 3200],
                'description': 'Best for Unix password hashes'
            },
            'generated2': {
                'url': 'https://raw.githubusercontent.com/hashcat/hashcat/master/rules/generated2.rule',
                'performance': 7.5,
                'speed': '4.20 MH/s',
                'coverage': 2.8,
                'memory_footprint': 'high',
                'hash_types': [0, 1000, 1400, 22000],
                'description': 'Generated rules for modern passwords'
            },
            'leetspeak': {
                'url': 'https://raw.githubusercontent.com/hashcat/hashcat/master/rules/leetspeak.rule',
                'performance': 7.0,
                'speed': '4.15 MH/s',
                'coverage': 2.2,
                'memory_footprint': 'low',
                'hash_types': [22000, 2500],
                'description': 'Leet speak transformations for WPA'
            },
            # WPA-specific rules
            'WPA-optimized': {
                'url': 'https://raw.githubusercontent.com/samirettali/password-cracking-rules/master/best64.rule',
                'performance': 8.4,
                'speed': '4.75 MH/s',
                'coverage': 2.5,
                'memory_footprint': 'low',
                'hash_types': [22000, 22001, 2500],
                'description': 'Optimized for WPA handshake cracking'
            },
            'vendor_cisco': {
                'url': 'https://raw.githubusercontent.com/initstring/word2rule/master/cisco.rule',
                'performance': 8.1,
                'speed': '4.40 MH/s',
                'coverage': 2.9,
                'memory_footprint': 'medium',
                'hash_types': [22000],
                'description': 'Cisco-specific password patterns'
            },
            'vendor_aruba': {
                'url': 'https://raw.githubusercontent.com/initstring/word2rule/master/aruba.rule',
                'performance': 7.9,
                'speed': '4.35 MH/s',
                'coverage': 2.7,
                'memory_footprint': 'medium',
                'hash_types': [22000],
                'description': 'Aruba-specific password patterns'
            },
            'SlowHashes': {
                'url': 'https://raw.githubusercontent.com/hashcat/hashcat/master/rules/SlowHashes.rule',
                'performance': 6.5,
                'speed': '0.85 MH/s',
                'coverage': 3.5,
                'memory_footprint': 'low',
                'hash_types': [3200, 1800],
                'description': 'Optimized for slow hashes (bcrypt, sha512crypt)'
            },
            # Top rules - Unicorn1000
            'Unicorn1000': {
                'url': 'https://raw.githubusercontent.com/Unic0rn28/hashcat-rules/main/unicorn%20rules/Unicorn1k.rule',
                'performance': 9.0,
                'speed': '4.58 MH/s',
                'coverage': 3.4,
                'memory_footprint': 'medium',
                'hash_types': [0, 1000, 1400, 22000],
                'description': 'Top 1000 rules - extended coverage'
            },
            'd3ad0ne': {
                'url': 'https://raw.githubusercontent.com/praetorian-inc/Hob0Rules/master/d3adhob0.rule',
                'performance': 8.9,
                'speed': '4.55 MH/s',
                'coverage': 3.0,
                'memory_footprint': 'medium',
                'hash_types': [0, 1000, 1400],
                'description': 'Praetorian optimized comprehensive rules'
            },
            'clem9669_large': {
                'url': 'https://raw.githubusercontent.com/clem9669/hashcat-rule/master/clem9669_large.rule',
                'performance': 8.8,
                'speed': '4.50 MH/s',
                'coverage': 2.9,
                'memory_footprint': 'medium',
                'hash_types': [0, 1000, 1400],
                'description': 'Optimized for fast hashes MD5/NTLM'
            },
            'clem9669_medium': {
                'url': 'https://raw.githubusercontent.com/clem9669/hashcat-rule/master/clem9669_medium.rule',
                'performance': 8.7,
                'speed': '4.45 MH/s',
                'coverage': 2.7,
                'memory_footprint': 'low',
                'hash_types': [0, 1000, 1400, 3200],
                'description': 'Balanced rule coverage'
            },
            'clem9669_small': {
                'url': 'https://raw.githubusercontent.com/clem9669/hashcat-rule/master/clem9669_small.rule',
                'performance': 8.5,
                'speed': '1.20 MH/s',
                'coverage': 2.5,
                'memory_footprint': 'low',
                'hash_types': [3200, 1800],
                'description': 'Optimized for slow hashes bcrypt/scrypt'
            },
            'nsa-v2-dive': {
                'url': 'https://raw.githubusercontent.com/NSAKEY/nsa-rules/master/_NSAKEY.v2.dive.rule',
                'performance': 8.4,
                'speed': '4.40 MH/s',
                'coverage': 2.8,
                'memory_footprint': 'medium',
                'hash_types': [0, 1000, 1400],
                'description': 'NSA optimized dive rules'
            },
            'kaonashi': {
                'url': 'https://raw.githubusercontent.com/kaonashi-passwords/Kaonashi/master/rules/kaonashi.rule',
                'performance': 8.8,
                'speed': '3.80 MH/s',
                'coverage': 3.1,
                'memory_footprint': 'medium',
                'hash_types': [22000, 2500],
                'description': 'WPA/WPA2 optimized rules'
            },
            'best64': {
                'url': 'https://raw.githubusercontent.com/samirettali/password-cracking-rules/master/best64.rule',
                'performance': 8.5,
                'speed': '4.60 MH/s',
                'coverage': 2.6,
                'memory_footprint': 'low',
                'hash_types': [0, 1000, 1400, 22000, 2500],
                'description': 'Hashcat best 64 rules'
            },
        }
        return rule_sources

    def auto_detect_hash(self, hash_sample: str) -> Optional[HashInfo]:
        """Intelligently detect hash type from sample"""
        # Check for WPA formats first
        if hash_sample.startswith("WPA*") or "WPA*" in hash_sample:
            return HashInfo(22000, "WPA-PBKDF2-PMKID+EAPOL", "", (0, 0), "", True, "generic")

        if hash_sample.startswith("$WPAPSK$"):
            return HashInfo(2500, "WPA-EAPOL-PBKDF2", "", (0, 0), "", True, "generic")

        # Try hashcat's identify first
        try:
            result = subprocess.run(['hashcat', '--identify', hash_sample],
                                  capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if line.startswith(hash_sample):
                        parts = line.split()
                        if len(parts) >= 2:
                            mode = parts[1].strip('[]')
                            for hash_info in self.hash_patterns.values():
                                if str(hash_info.mode) == mode:
                                    return hash_info
        except Exception:
            pass

        # Fallback to pattern matching
        hash_length = len(hash_sample)

        for hash_info in self.hash_patterns.values():
            if hash_info.pattern:
                if re.match(hash_info.pattern, hash_sample):
                    return hash_info

            # Length-based fallback
            if hash_info.length[0] <= hash_length <= hash_info.length[1]:
                return hash_info

        return None

    def analyze_hash_file(self, hash_file: Path) -> Dict:
        """Analyze hash file for attack strategy"""
        hashes = []
        try:
            with open(hash_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        hashes.append(line)

            if not hashes:
                return {"error": "No hashes found in file"}

            # Analyze first hash
            sample_hash = hashes[0]
            hash_info = self.auto_detect_hash(sample_hash)

            analysis = {
                "total_hashes": len(hashes),
                "sample_hash": sample_hash[:50] + "..." if len(sample_hash) > 50 else sample_hash,
                "detected_type": hash_info.name if hash_info else "Unknown",
                "hash_mode": hash_info.mode if hash_info else None,
                "unique_salts": self._count_unique_salts(hashes) if hash_info and hash_info.mode in [500, 1800, 3200] else 0,
                "estimated_complexity": self._estimate_complexity(hashes),
                "recommended_approach": self._get_recommended_approach(hash_info, len(hashes)),
                "analysis_timestamp": datetime.now().isoformat()
            }

            return analysis
        except Exception as e:
            return {"error": f"Analysis failed: {str(e)}"}

    def _count_unique_salts(self, hashes: List[str]) -> int:
        """Count unique salts for salted hashes"""
        salts = set()
        for h in hashes:
            # Extract salt from common formats
            if h.startswith('$1$'):  # md5crypt
                parts = h.split('$')
                if len(parts) >= 3:
                    salts.add(parts[2])
            elif h.startswith('$6$'):  # sha512crypt
                parts = h.split('$')
                if len(parts) >= 3:
                    salts.add(parts[2])
            elif h.startswith('$2'):  # bcrypt
                parts = h.split('$')
                if len(parts) >= 4:
                    salts.add('$'.join(parts[:4]))
        return len(salts)

    def _estimate_complexity(self, hashes: List[str]) -> str:
        """Estimate password complexity based on hash patterns"""
        # Simple heuristic based on hash length
        avg_len = sum(len(h) for h in hashes) / len(hashes)

        if avg_len > 100:
            return "Very High (likely bcrypt/sha512crypt)"
        elif avg_len > 60:
            return "High (likely salted SHA)"
        elif avg_len > 50:
            return "Medium-High"
        elif avg_len > 30:
            return "Medium"
        else:
            return "Low (likely fast hashes)"

    def _get_recommended_approach(self, hash_info: Optional[HashInfo], hash_count: int) -> str:
        """Get recommended attack approach based on hash type and count"""
        if not hash_info:
            return "Unknown hash type - try brute force with masks"

        if hash_info.mode == 22000 or hash_info.mode == 2500:
            return "WPA/WPA2: Use vendor-specific rules + wordlists + brute force with masks"
        elif hash_info.mode == 3200 or hash_info.mode == 1800:
            return "Slow hash: Use optimized rulesets (SlowHashes) + focused wordlists"
        elif hash_count > 10000:
            return "Large dataset: Use fast rules (best64, Hob064) with combinator attacks"
        else:
            return "Standard: Comprehensive rules (OneRuleToRuleThemAll) + hybrid attacks"

    def download_rule(self, rule_name: str) -> Optional[Path]:
        """Download and cache rules with validation"""
        rule_info = self.rule_db.get(rule_name)
        if not rule_info:
            print(f"Rule {rule_name} not found in database")
            return None

        rule_path = self.rules_dir / f"{rule_name}.rule"

        # Check cache
        if rule_path.exists():
            # Verify file integrity
            file_size = rule_path.stat().st_size
            if file_size > 100:  # Minimum reasonable size
                return rule_path

        print(f"Downloading rule: {rule_name}...")
        try:
            response = requests.get(rule_info['url'], timeout=15)
            response.raise_for_status()

            # Save rule
            rule_path.write_text(response.text)

            # Verify rule syntax
            lines = response.text.strip().split('\n')
            rule_count = sum(1 for line in lines if line.strip() and not line.startswith('#'))

            print(f"✓ Downloaded {rule_name}: {rule_count} rules")
            return rule_path
        except Exception as e:
            print(f"✗ Failed to download {rule_name}: {e}")

            # Try fallback locations
            fallback_urls = [
                f"https://raw.githubusercontent.com/hashcat/hashcat/master/rules/{rule_name}.rule",
                f"https://raw.githubusercontent.com/NotSoSecure/password_cracking_rules/master/{rule_name}.rule",
                f"https://raw.githubusercontent.com/Stealthsploit/rule-set/master/{rule_name}.rule"
            ]

            for url in fallback_urls:
                try:
                    response = requests.get(url, timeout=10)
                    if response.status_code == 200:
                        rule_path.write_text(response.text)
                        print(f"✓ Downloaded from fallback: {rule_name}")
                        return rule_path
                except:
                    continue

            return None

    def _initialize_wordlist_database(self) -> Dict:
        """Initialize comprehensive public wordlist database"""
        return {
            # Top-tier mega wordlists
            'rockyou': {
                'url': 'https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt',
                'size': '134MB',
                'passwords': 14_341_564,
                'method': 'direct',
                'description': 'Classic 2009 breach - baseline wordlist',
                'recommended_for': ['general', 'fast_hash']
            },
            'rockyou2021': {
                'url': 'https://weakpass.com/wordlist/1943',
                'size': '92GB',
                'passwords': 8_459_060_239,
                'method': 'manual',
                'note': 'Download from weakpass.com',
                'description': '8.4 billion passwords from breaches',
                'recommended_for': ['comprehensive', 'large_scale']
            },
            'rockyou2024': {
                'url': None,
                'size': '92GB',
                'passwords': 9_948_575_739,
                'method': 'manual',
                'note': 'Download from weakpass.com or torrent',
                'description': 'Largest compilation - 9.9B passwords (July 2024)',
                'recommended_for': ['comprehensive', 'maximum_coverage']
            },

            # Weakpass collections (best performance)
            'weakpass_3': {
                'url': 'https://download.weakpass.com/wordlists/1851/weakpass_3.txt.gz',
                'size': '7GB',
                'passwords': 3_700_000_000,
                'method': 'direct',
                'description': 'Weakpass v3 - high crack rate',
                'recommended_for': ['ntlm', 'md5', 'general']
            },
            'weakpass_3a': {
                'url': 'https://weakpass.com/wordlist/1948',
                'size': '85GB',
                'passwords': 7_200_000_000,
                'method': 'manual',
                'note': 'Download from weakpass.com',
                'description': 'Weakpass v3a - extended collection',
                'recommended_for': ['comprehensive']
            },
            'AllInOne': {
                'url': 'https://weakpass.com/all-in-one',
                'size': 'varies',
                'passwords': 0,
                'method': 'manual',
                'note': 'Combined mega-wordlist from weakpass.com',
                'description': 'All weakpass wordlists combined',
                'recommended_for': ['maximum_coverage']
            },

            # Probable wordlists (statistically optimized)
            'Top2Billion-probable-v2': {
                'url': 'https://weakpass.com/wordlist/1858',
                'size': '17GB',
                'passwords': 2_000_000_000,
                'method': 'manual',
                'note': 'Download from weakpass.com',
                'description': 'Top 2B passwords by probability',
                'recommended_for': ['general', 'ntlm', 'fast_hash']
            },
            'Top304Thousand-probable-v2': {
                'url': 'https://github.com/berzerk0/Probable-Wordlists/raw/master/Real-Passwords/Top304Thousand-probable-v2.txt',
                'size': '2.5MB',
                'passwords': 304_000,
                'method': 'direct',
                'description': 'Top 304K passwords sorted by probability',
                'recommended_for': ['wpa', 'quick_test']
            },
            'Top12Thousand-probable-v2': {
                'url': 'https://github.com/berzerk0/Probable-Wordlists/raw/master/Real-Passwords/Top12Thousand-probable-v2.txt',
                'size': '103KB',
                'passwords': 12_000,
                'method': 'direct',
                'description': 'Top 12K passwords sorted by probability (150+ appearances)',
                'recommended_for': ['quick_test', 'general']
            },
            'Top204Thousand-WPA-probable-v2': {
                'url': 'https://github.com/berzerk0/Probable-Wordlists/raw/master/Real-Passwords/WPA-Length/Top204Thousand-WPA-probable-v2.txt',
                'size': '1.8MB',
                'passwords': 204_000,
                'method': 'direct',
                'description': 'Top 204K WPA-length passwords (8-40 chars) sorted by probability',
                'recommended_for': ['wpa', 'balanced']
            },

            # CrackStation
            'crackstation_human': {
                'url': 'https://crackstation.net/files/crackstation-human-only.txt.gz',
                'size': '4.2GB',
                'passwords': 64_000_000,
                'method': 'direct',
                'description': 'Human-readable passwords only',
                'recommended_for': ['general', 'ntlm']
            },
            'crackstation_full': {
                'url': 'https://crackstation.net/files/crackstation.txt.gz',
                'size': '15GB',
                'passwords': 1_493_677_782,
                'method': 'direct',
                'description': 'Complete CrackStation - 1.4B passwords',
                'recommended_for': ['comprehensive']
            },

            # Kaonashi (frequency sorted)
            'kaonashi': {
                'url': None,
                'size': '2.35GB',
                'passwords': 0,
                'method': 'mega',
                'note': 'https://github.com/kaonashi-passwords/Kaonashi',
                'description': 'Frequency-sorted real breaches',
                'recommended_for': ['wpa', 'efficient']
            },

            # HashKiller found lists
            'hk_hlm_founds': {
                'url': 'https://weakpass.com/wordlist/1256',
                'size': 'varies',
                'passwords': 0,
                'method': 'manual',
                'note': 'HashKiller found passwords',
                'description': 'Passwords cracked by HashKiller community',
                'recommended_for': ['modern', 'recent_cracks']
            },

            # SecLists
            'seclists': {
                'url': 'https://github.com/danielmiessler/SecLists/archive/master.zip',
                'size': '655MB',
                'passwords': 0,
                'method': 'direct',
                'description': 'SecLists password collection (multiple files)',
                'recommended_for': ['pentesting', 'varied']
            },
            'darkweb2017-top10000': {
                'url': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/darkweb2017-top10000.txt',
                'size': '80KB',
                'passwords': 10_000,
                'method': 'direct',
                'description': 'Top 10K dark web passwords',
                'recommended_for': ['quick_test', 'common']
            },

            # Passphrase wordlists
            'passphrase_wordlist': {
                'url': 'https://github.com/initstring/passphrase-wordlist/releases',
                'size': '1.2GB',
                'passwords': 20_000_000,
                'method': 'manual',
                'note': 'Check releases page for download',
                'description': '20M passphrases for long passwords',
                'recommended_for': ['long_passwords', 'passphrases']
            },

            # Wordlust (base wordlist for mutations)
            'wordlust': {
                'url': 'https://github.com/frizb/Wordlust',
                'size': '50GB',
                'passwords': 0,
                'method': 'manual',
                'note': 'Check GitHub releases',
                'description': 'Base wordlist optimized for mutations',
                'recommended_for': ['with_rules', 'ntlm']
            },
        }

    def download_wordlist(self, wordlist_name: str) -> Optional[Path]:
        """Download wordlist with method-specific handling"""
        if not hasattr(self, 'wordlist_db'):
            self.wordlist_db = self._initialize_wordlist_database()

        if wordlist_name not in self.wordlist_db:
            print(f"Unknown wordlist: {wordlist_name}")
            print("Run --list-wordlists to see available wordlists")
            return None

        info = self.wordlist_db[wordlist_name]
        wordlist_path = self.wordlists_dir / f"{wordlist_name}.txt"

        if wordlist_path.exists():
            print(f"✓ {wordlist_name} already exists at {wordlist_path}")
            return wordlist_path

        if info['method'] == 'manual':
            print(f"⚠ {wordlist_name} requires manual download")
            print(f"  Size: {info['size']}")
            print(f"  Note: {info.get('note', 'Too large for auto-download')}")
            return None

        if info['method'] == 'mega':
            print(f"⚠ {wordlist_name} requires MEGA download")
            print(f"  See: {info.get('note')}")
            return None

        if info['method'] == 'direct':
            print(f"Downloading {wordlist_name} ({info['size']})...")
            print(f"  From: {info['url']}")
            try:
                response = requests.get(info['url'], stream=True, timeout=120)
                response.raise_for_status()

                if info['url'].endswith('.gz'):
                    import gzip
                    print("  Decompressing gzip...")
                    with gzip.open(response.raw, 'rt', encoding='utf-8', errors='ignore') as f:
                        wordlist_path.write_text(f.read())
                elif info['url'].endswith('.zip'):
                    import zipfile
                    import io
                    print("  Extracting zip...")
                    with zipfile.ZipFile(io.BytesIO(response.content)) as z:
                        z.extractall(self.wordlists_dir)
                else:
                    wordlist_path.write_bytes(response.content)

                print(f"✓ Downloaded {wordlist_name} to {wordlist_path}")
                return wordlist_path
            except Exception as e:
                print(f"✗ Failed to download {wordlist_name}: {e}")
                return None

        return None

    def generate_vendor_wordlist(self, vendor: str, size: int = 50000) -> Optional[Path]:
        """Generate vendor-specific wordlist for routers with realistic patterns"""
        wordlist_path = self.wordlists_dir / f"{vendor}_passwords.txt"

        if wordlist_path.exists():
            print(f"✓ Wordlist already exists: {wordlist_path}")
            return wordlist_path

        print(f"Generating {vendor} wordlist ({size:,} passwords)...")

        vendor_info = self.wpa_vendors.get(vendor)
        if not vendor_info:
            print(f"⚠️  Unknown vendor: {vendor}")
            return None

        words = set()

        # Add common vendor-specific patterns from research
        if vendor == 'netgear':
            # Netgear uses adjective+noun+digits pattern
            adjectives = ['happy', 'bright', 'quick', 'smart', 'fast', 'strong', 'brave', 'clever',
                          'fancy', 'gentle', 'golden', 'hidden', 'jolly', 'kindly', 'lively', 'magic',
                          'noble', 'quiet', 'rapid', 'silent', 'tender', 'vivid', 'witty', 'melodic']
            nouns = ['unicorn', 'dragon', 'tiger', 'eagle', 'lion', 'wolf', 'bear', 'fox',
                     'hawk', 'raven', 'phoenix', 'griffin', 'pegasus', 'dolphin', 'panther']

            for adj in adjectives[:15]:
                for noun in nouns[:15]:
                    # Netgear patterns: adjective+noun+3digits
                    for i in range(100, 1000, 10):
                        words.add(f"{adj}{noun}{i}")
                        # Capitalize variations
                        words.add(f"{adj.capitalize()}{noun.capitalize()}{i}")
                        # Sometimes with special characters
                        words.add(f"{adj}{noun}@{i}")
                        words.add(f"{adj}{noun}!")
                        if len(words) >= size:
                            break
                    if len(words) >= size:
                        break
                if len(words) >= size:
                    break

        elif vendor == 'tp-link':
            # TP-Link often uses 8-digit numbers and common patterns
            for i in range(10000000, 10000000 + min(size, 1000000)):
                words.add(str(i))
                if len(words) >= size:
                    break

            # Common TP-Link patterns
            common_tplink = ['12345678', '11111111', '00000000', '88888888', '87654321',
                             'password', 'admin', 'admin123', 'welcome', '123456']
            words.update(common_tplink)

            # Model numbers often used in passwords
            for model in ['archer', 'tl', 'wr', 'td']:
                for i in range(700, 900, 10):
                    words.add(f"{model}{i}")
                    words.add(f"{model}{i}!")
                    if len(words) >= size:
                        break

        elif vendor in ['cisco', 'linksys']:
            # Corporate style: Word + Year or Word@Year
            base_words = ['cisco', 'linksys', 'network', 'admin', 'router', 'wireless', 'switch']
            for word in base_words:
                for year in range(2018, 2026):
                    words.add(f"{word}{year}")
                    words.add(f"{word.capitalize()}{year}")
                    words.add(f"{word}@{year}")
                    words.add(f"{word.upper()}{year}")
                    words.add(f"{word}!{year}")

                # Add Cisco-specific patterns
                if vendor == 'cisco':
                    for i in range(1000, 2000, 10):
                        words.add(f"Cisco{i}")
                        words.add(f"CISCO{i}")
                        words.add(f"cisco{i}")
                        if len(words) >= size:
                            break

        elif vendor in ['asus', 'd-link']:
            # Model + digits patterns
            models = ['RT', 'AC', 'AX', 'DIR', 'DSL', 'ASUS', 'DLink']
            for model in models:
                for i in range(1000, 5000, 100):
                    words.add(f"{model}{i}")
                    words.add(f"{model}-{i}")
                    words.add(f"{model.lower()}{i}")
                    if len(words) >= size:
                        break

        elif vendor == 'technicolor':
            # Technicolor routers (Cox/Xfinity) use 5-6 letter word + 4 digits + 5-6 letter word
            words_list1 = ['circle', 'chore', 'beach', 'apple', 'grape', 'lemon', 'mango']
            words_list2 = ['empty', 'become', 'before', 'behind', 'beside', 'between']

            for w1 in words_list1:
                for i in range(1000, 10000, 100):
                    for w2 in words_list2:
                        words.add(f"{w1}{i}{w2}")
                        if len(words) >= size:
                            break
                    if len(words) >= size:
                        break
                if len(words) >= size:
                    break

        elif vendor == 'spectrum':
            # Spectrum routers use adjective+noun+3digits similar to Netgear
            adjectives = ['sharp', 'keen', 'acute', 'clear', 'fine', 'quick', 'smart']
            nouns = ['blade', 'edge', 'point', 'focus', 'mind', 'logic', 'think']

            for adj in adjectives:
                for noun in nouns:
                    for i in range(100, 1000, 10):
                        words.add(f"{adj}{noun}{i}")
                        if len(words) >= size:
                            break
                    if len(words) >= size:
                        break
                if len(words) >= size:
                    break

        # Generic patterns for all vendors (fallback)
        if len(words) < size:
            common_words = ['password', 'admin', 'wireless', 'network', 'internet', 'router']
            for word in common_words:
                for i in range(1, 1000, 5):
                    words.add(f"{word}{i}")
                    words.add(f"{word.capitalize()}{i}")
                    words.add(f"{word}@{i}")
                    words.add(f"{word}!{i}")
                    if len(words) >= size:
                        break
                if len(words) >= size:
                    break

        # Write wordlist
        with open(wordlist_path, 'w', encoding='utf-8') as f:
            for word in sorted(words)[:size]:
                f.write(f"{word}\n")

        actual_size = min(len(words), size)
        print(f"✓ Generated {actual_size:,} passwords: {wordlist_path}")
        return wordlist_path

    def setup_wordlists(self) -> Path:
        """Interactive wordlist setup - ask for location and offer downloads"""
        print("\n" + "=" * 80)
        print("WORDLIST CONFIGURATION")
        print("=" * 80)

        # Ask for wordlist directory
        print("\nWhere are your wordlists stored?")
        print("Common locations:")
        print("  1) /usr/share/wordlists (Kali Linux default)")
        print("  2) ~/wordlists (User home directory)")
        print(f"  3) {self.wordlists_dir} (HashcatNexus default)")
        print("  4) ~/Documents/wordlists (Documents folder)")
        print("  5) Custom path")

        choice = input("\nChoice (1-5, default: 1): ").strip()

        if choice == '2':
            wordlist_base = Path.home() / "wordlists"
        elif choice == '3':
            wordlist_base = self.wordlists_dir
        elif choice == '4':
            wordlist_base = Path.home() / "Documents" / "wordlists"
        elif choice == '5':
            custom = input("Enter custom path: ").strip()
            wordlist_base = Path(custom).expanduser()
        else:
            wordlist_base = Path("/usr/share/wordlists")

        # Create if doesn't exist
        if not wordlist_base.exists():
            create = input(f"\n{wordlist_base} doesn't exist. Create it? (Y/n): ").strip().lower()
            if create != 'n':
                wordlist_base.mkdir(parents=True, exist_ok=True)
                print(f"✓ Created {wordlist_base}")

        # Helper function to format file sizes
        def format_size(size_bytes):
            """Format file size in human-readable format"""
            if size_bytes < 1024:
                return f"{size_bytes} B"
            elif size_bytes < 1024 * 1024:
                return f"{size_bytes / 1024:.1f} KB"
            elif size_bytes < 1024 * 1024 * 1024:
                return f"{size_bytes / (1024 * 1024):.1f} MB"
            else:
                return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"

        # Scan for existing wordlists
        print(f"\nScanning {wordlist_base} for wordlists...")
        found_wordlists = []

        if wordlist_base.exists():
            for ext in ['*.txt', '*.lst', '*.dict']:
                found_wordlists.extend(wordlist_base.rglob(ext))

            if found_wordlists:
                print(f"\n✓ Found {len(found_wordlists)} wordlists:")
                for wl in found_wordlists[:10]:  # Show first 10
                    size = wl.stat().st_size
                    print(f"  • {wl.name} ({format_size(size)})")
                if len(found_wordlists) > 10:
                    print(f"  ... and {len(found_wordlists) - 10} more")
            else:
                print("⚠️  No wordlists found")

        # Check for common wordlists
        print("\nChecking for common wordlists...")
        common_wordlists = {
            'rockyou.txt': 'Classic 14M password list (baseline)',
            'Top12Thousand-probable-v2.txt': 'Top 12K by probability',
            'Top204Thousand-WPA-probable-v2.txt': 'Top 204K WPA-length (8-40 chars)',
            'Top304Thousand-probable-v2.txt': 'Top 304K by probability',
            'darkweb2017-top10000.txt': 'Top 10K dark web passwords',
        }

        missing = []
        for wl_name, desc in common_wordlists.items():
            wl_path = wordlist_base / wl_name
            if wl_path.exists():
                print(f"  ✓ {wl_name} - {desc}")
            else:
                print(f"  ✗ {wl_name} - {desc}")
                missing.append(wl_name)

        # Offer to download missing wordlists
        if missing:
            download = input(f"\n💾 Download missing wordlists? (y/N): ").strip().lower()
            if download == 'y':
                self._download_common_wordlists(wordlist_base, missing)

        return wordlist_base

    def _download_common_wordlists(self, base_path: Path, wordlists: List[str]):
        """Download common public wordlists"""
        download_urls = {
            'rockyou.txt': 'https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt',
            'darkweb2017-top10000.txt': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/darkweb2017_top-10000.txt',
            'Top12Thousand-probable-v2.txt': 'https://raw.githubusercontent.com/berzerk0/Probable-Wordlists/master/Real-Passwords/Top12Thousand-probable-v2.txt',
            'Top204Thousand-WPA-probable-v2.txt': 'https://raw.githubusercontent.com/berzerk0/Probable-Wordlists/master/Real-Passwords/WPA-Length/Top204Thousand-WPA-probable-v2.txt',
            'Top304Thousand-probable-v2.txt': 'https://raw.githubusercontent.com/berzerk0/Probable-Wordlists/master/Real-Passwords/Top304Thousand-probable-v2.txt',
            '10k-most-common.txt': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt',
        }

        for wl in wordlists:
            if wl not in download_urls:
                continue

            print(f"\n📥 Downloading {wl}...")
            try:
                response = requests.get(download_urls[wl], stream=True, timeout=120)
                response.raise_for_status()

                output_path = base_path / wl

                # Handle gzipped files
                if wl.endswith('.gz'):
                    import gzip
                    with gzip.open(response.raw, 'rt', encoding='utf-8', errors='ignore') as f:
                        output_path = base_path / wl.replace('.gz', '')
                        output_path.write_text(f.read())
                else:
                    output_path.write_bytes(response.content)

                size = output_path.stat().st_size / (1024 * 1024)
                print(f"✓ Downloaded {wl} ({size:.1f} MB)")
            except Exception as e:
                print(f"✗ Failed to download {wl}: {e}")

    def suggest_wordlist(self, wordlist_base: Path, hash_mode: int, vendor=None) -> List[Path]:
        def format_size(size_bytes):
            """Format file size in human-readable format"""
            if size_bytes < 1024:
                return f"{size_bytes} B"
            elif size_bytes < 1024 * 1024:
                return f"{size_bytes / 1024:.1f} KB"
            elif size_bytes < 1024 * 1024 * 1024:
                return f"{size_bytes / (1024 * 1024):.1f} MB"
            else:
                return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"

        print("\n" + "=" * 80)
        print("WORDLIST SELECTION")
        print("=" * 80)

        print("\nScanning for wordlists...")
        available = {}
        if wordlist_base.exists():
            for wl in wordlist_base.glob('*.txt'):
                try:
                    size = wl.stat().st_size
                    rel_path = wl.relative_to(wordlist_base)
                    display_name = str(rel_path)
                    available[display_name] = {'path': wl, 'size': size}
                except Exception:
                    continue

            for wl in wordlist_base.glob('*.lst'):
                try:
                    size = wl.stat().st_size
                    rel_path = wl.relative_to(wordlist_base)
                    display_name = str(rel_path)
                    available[display_name] = {'path': wl, 'size': size}
                except Exception:
                    continue

        print(f"Found {len(available)} wordlists\n")

        if not available:
            return []

        recommendations = []

        if hash_mode in [22000, 2500]:
            print("🎯 WPA/WPA2 Recommendations:")

            vendors_to_check = vendor if isinstance(vendor, list) else [vendor] if vendor else []
            for v in vendors_to_check:
                if v and v != 'generic':
                    vendor_wl_name = f"{v}_passwords.txt"
                    for wl_key in available.keys():
                        if vendor_wl_name in wl_key:
                            size_str = format_size(available[wl_key]['size'])
                            recommendations.append((wl_key, f"{v.title()} ({size_str})"))
                            break

            for target in ['Top304Thousand-probable-v2.txt', 'Top12Million-probable-v2.txt',
                           'darkweb2017-top10000.txt']:
                for wl_key in available.keys():
                    if target.lower() in wl_key.lower():
                        size_str = format_size(available[wl_key]['size'])
                        recommendations.append((wl_key, f"WPA-optimized ({size_str})"))
                        break

            for wl_key in available.keys():
                if 'rockyou.txt' in wl_key.lower() and wl_key not in [r[0] for r in recommendations]:
                    size_str = format_size(available[wl_key]['size'])
                    recommendations.append((wl_key, f"Comprehensive ({size_str})"))
                    break

        else:
            print(f"🎯 Hash Mode {hash_mode} Recommendations:")

            for wl_key in available.keys():
                if 'rockyou.txt' in wl_key.lower():
                    size_str = format_size(available[wl_key]['size'])
                    recommendations.append((wl_key, f"Standard ({size_str})"))
                    break

            for wl_key in available.keys():
                if 'darkweb2017-top10000.txt' in wl_key.lower():
                    size_str = format_size(available[wl_key]['size'])
                    recommendations.append((wl_key, f"Quick test ({size_str})"))
                    break

        if recommendations:
            for i, (wl_name, desc) in enumerate(recommendations, 1):
                print(f"  {i}) {wl_name} - {desc}")

            print(f"\n  {len(recommendations) + 1}) Select multiple from all wordlists")
            print(f"  {len(recommendations) + 2}) Custom path")

            choice = input(f"\nSelect (1-{len(recommendations) + 2}, default: 1): ").strip()

            if not choice or choice == '1':
                return [available[recommendations[0][0]]['path']]
            elif choice.isdigit() and 1 <= int(choice) <= len(recommendations):
                return [available[recommendations[int(choice) - 1][0]]['path']]
            elif choice == str(len(recommendations) + 1):
                all_wl = sorted(available.items(), key=lambda x: x[1]['size'], reverse=True)
                print("\nAll wordlists:")
                for i, (name, info) in enumerate(all_wl, 1):
                    size_str = format_size(info['size'])
                    print(f"  {i}) {name} ({size_str})")

                multi = input(f"\nEnter numbers (1-{len(all_wl)}, comma-separated): ").strip()
                selected = []
                try:
                    for idx in [int(x.strip()) - 1 for x in multi.split(',')]:
                        if 0 <= idx < len(all_wl):
                            selected.append(all_wl[idx][1]['path'])
                except:
                    pass
                return selected if selected else [all_wl[0][1]['path']]
            elif choice == str(len(recommendations) + 2):
                custom = input("Path: ").strip()
                custom_path = Path(custom).expanduser()
                return [custom_path] if custom_path.exists() else [available[recommendations[0][0]]['path']]
            else:
                return [available[recommendations[0][0]]['path']]

        else:
            all_wl = sorted(available.items(), key=lambda x: x[1]['size'], reverse=True)
            print("All wordlists:")
            for i, (name, info) in enumerate(all_wl, 1):
                size_str = format_size(info['size'])
                print(f"  {i}) {name} ({size_str})")

            print(f"\n  {len(all_wl) + 1}) Custom path")

            sel = input(f"\nSelect (numbers comma-separated, default: 1): ").strip()

            if not sel or sel == '1':
                return [all_wl[0][1]['path']]
            elif ',' in sel:
                selected = []
                try:
                    for idx in [int(x.strip()) - 1 for x in sel.split(',')]:
                        if 0 <= idx < len(all_wl):
                            selected.append(all_wl[idx][1]['path'])
                except:
                    pass
                return selected if selected else [all_wl[0][1]['path']]
            elif sel == str(len(all_wl) + 1):
                custom = input("Path: ").strip()
                custom_path = Path(custom).expanduser()
                return [custom_path] if custom_path.exists() else [all_wl[0][1]['path']]
            elif sel.isdigit() and 1 <= int(sel) <= len(all_wl):
                return [all_wl[int(sel) - 1][1]['path']]
            else:
                return [all_wl[0][1]['path']]

    def list_all_rules(self):
        """List all available rules with status"""
        print("\n" + "=" * 100)
        print("AVAILABLE RULES")
        print("=" * 100)
        print(f"{'Name':<30} {'Perf':<6} {'Speed':<12} {'Cov':<5} {'Mem':<8} {'Hash Types':<20} {'Status'}")
        print("-" * 100)

        rules_sorted = sorted(self.rule_db.items(),
                              key=lambda x: x[1].get('performance', 0),
                              reverse=True)

        for name, info in rules_sorted:
            rule_path = self.rules_dir / f"{name}.rule"
            status = "✓ Downloaded" if rule_path.exists() else "Available"

            hash_types_str = ','.join(str(h) for h in info.get('hash_types', [])[:3])
            if len(info.get('hash_types', [])) > 3:
                hash_types_str += '...'

            print(f"{name:<30} "
                  f"{info.get('performance', 0):<6.1f} "
                  f"{info.get('speed', 'N/A'):<12} "
                  f"{info.get('coverage', 0):<5.1f} "
                  f"{info.get('memory_footprint', 'N/A'):<8} "
                  f"{hash_types_str:<20} "
                  f"{status}")

        print("\nLegend:")
        print("  Perf = Performance rating (0-10)")
        print("  Speed = Average cracking speed")
        print("  Cov = Coverage multiplier")
        print("  Mem = Memory footprint (low/medium/high)")

    def list_all_wordlists(self):
        """List all available wordlists with download status"""
        if not hasattr(self, 'wordlist_db'):
            self.wordlist_db = self._initialize_wordlist_database()

        print("\n" + "=" * 100)
        print("AVAILABLE WORDLISTS")
        print("=" * 100)
        print(f"{'Name':<20} {'Size':<10} {'Passwords':<15} {'Method':<10} {'Status':<15}")
        print("-" * 100)

        for name, info in self.wordlist_db.items():
            wordlist_path = self.wordlists_dir / f"{name}.txt"
            status = "✓ Downloaded" if wordlist_path.exists() else info['method'].title()
            passwords = f"{info.get('passwords', 0):,}" if info.get('passwords') else 'Varies'

            print(f"{name:<20} {info['size']:<10} {passwords:<15} {info['method']:<10} {status:<15}")
            if info.get('note') and not wordlist_path.exists():
                print(f"  → {info['note']}")

        print("\nDownload Methods:")
        print("  direct = Auto-downloadable")
        print("  manual = Too large, manual download required")
        print("  mega = Requires MEGA download client")

    def verify_and_customize_rules(self, rules: List[str], hash_mode: int) -> List[str]:
        """Allow user to verify and customize rule selection"""
        MAX_RULES = 4

        print("\n" + "=" * 80)
        print("RULE VERIFICATION & CUSTOMIZATION")
        print("=" * 80)

        if len(rules) > 0:
            print(f"\n✓ Auto-selected {len(rules)} optimized rules for hash mode {hash_mode}:")
            print()

            for i, rule_name in enumerate(rules, 1):
                rule_info = self.rule_db.get(rule_name, {})
                status = "✓ Downloaded" if (self.rules_dir / f"{rule_name}.rule").exists() else "⚠ Not downloaded"
                perf = rule_info.get('performance', 0)
                desc = rule_info.get('description', 'No description')
                print(f"  {i}. {rule_name:<30} [Perf: {perf:.1f}] {status}")
                print(f"     → {desc}")
        else:
            print("\n⚠ No rules auto-selected")

        print("\nOptions:")
        print("  1) Use these rules (recommended)")
        print("  2) Customize rule selection")
        print("  3) Skip rules entirely (straight wordlist)")

        choice = input("\nChoice (1-3, default: 1): ").strip()

        if choice == '2':
            # Customize rules submenu
            print("\nCustomize rules:")
            print("  1) Select from all available rules")
            print("  2) Add more rules to current selection")
            print("  3) Remove rules from current selection")

            custom_choice = input("\nChoice (1-3): ").strip()

            if custom_choice == '1':
                # Start fresh with manual selection
                rules = []
                print("\nAll available rules (sorted by performance):")
                sorted_rules = sorted(self.rule_db.items(),
                                    key=lambda x: x[1].get('performance', 0),
                                    reverse=True)
                for i, (rule_name, rule_info) in enumerate(sorted_rules[:30], 1):
                    print(f"  {i}. {rule_name:<30} [Perf: {rule_info.get('performance', 0):.1f}]")

                manual_choices = input(f"\nEnter up to {MAX_RULES} numbers (comma-separated, or 'none'): ").strip().lower()
                if manual_choices != 'none' and manual_choices:
                    try:
                        for idx in [int(x.strip()) - 1 for x in manual_choices.split(',')]:
                            if 0 <= idx < len(sorted_rules) and len(rules) < MAX_RULES:
                                rules.append(sorted_rules[idx][0])
                        print(f"\n✓ Selected: {', '.join(rules)}")
                    except:
                        print("⚠ Invalid input, reverting to recommended rules")
                        rules = self.get_optimal_rules(hash_mode)

            elif custom_choice == '2':
                # Add rules to current selection
                available = [r for r in self.rule_db.keys() if r not in rules]
                sorted_available = sorted(available,
                                        key=lambda x: self.rule_db[x].get('performance', 0),
                                        reverse=True)[:20]

                print("\nAvailable additional rules:")
                for i, rule_name in enumerate(sorted_available, 1):
                    rule_info = self.rule_db[rule_name]
                    print(f"  {i}. {rule_name:<30} [Perf: {rule_info.get('performance', 0):.1f}]")

                spaces_left = MAX_RULES - len(rules)
                if spaces_left > 0:
                    add_choices = input(f"\nEnter numbers to add (max {spaces_left} more): ").strip()
                    if add_choices:
                        try:
                            for idx in [int(x.strip()) - 1 for x in add_choices.split(',')]:
                                if 0 <= idx < len(sorted_available) and len(rules) < MAX_RULES:
                                    rules.append(sorted_available[idx])
                            print(f"\n✓ Updated selection: {', '.join(rules)}")
                        except:
                            print("⚠ Invalid input, keeping original rules")
                else:
                    print(f"⚠ Already at max {MAX_RULES} rules")

            elif custom_choice == '3':
                # Remove rules from current selection
                if len(rules) > 0:
                    print("\nCurrent rules:")
                    for i, rule_name in enumerate(rules, 1):
                        print(f"  {i}. {rule_name}")

                    remove_choices = input("\nEnter numbers to remove (comma-separated): ").strip()
                    if remove_choices:
                        try:
                            to_remove = [int(x.strip()) - 1 for x in remove_choices.split(',')]
                            rules = [r for i, r in enumerate(rules) if i not in to_remove]
                            print(f"\n✓ Updated selection: {', '.join(rules) if rules else 'None'}")
                        except:
                            print("⚠ Invalid input, keeping all rules")
                else:
                    print("\n⚠ No rules to remove")

        elif choice == '3':
            rules = []
            print("\n✓ Skipping all rules - straight wordlist attack")

        if len(rules) == 0:
            print("\n💡 Running without rules - testing exact wordlist matches only")
        
        print(f"\n✓ Final rule selection ({len(rules)}/{MAX_RULES}): {', '.join(rules) if rules else 'None (straight wordlist)'}")
        return rules

    def get_optimal_rules(self, hash_mode: int, vendor=None,
                          memory_profile: str = 'medium') -> List[str]:
        """Get optimal rules based on hash type, vendor(s), and memory constraints"""
        MAX_RULES = 4
        rules = []

        # Hash-type specific rules (prioritized by performance)
        if hash_mode == 22000 or hash_mode == 2500:  # WPA
            # Top 4 WPA rules prioritized by performance and WPA optimization
            rules = ['OneRuleToRuleThemAll', 'best64', 'hashpwn_1500', 'Unicorn64']

            # Handle vendor wordlist generation
            if vendor:
                vendors_to_check = vendor if isinstance(vendor, list) else [vendor]
                for v in vendors_to_check:
                    if v in self.wpa_vendors:
                        # Add specific wordlist generation for common router vendors
                        if v in ['netgear', 'tp-link', 'cisco', 'linksys']:
                            # These vendors have known password patterns
                            self.generate_vendor_wordlist(v, 100000)

        elif hash_mode == 3200 or hash_mode == 1800:  # Slow hashes (bcrypt, sha512crypt)
            rules = ['OneRuleToRuleThemAll', 'best64', 'SlowHashes', 'InsidePro-PasswordsPro']
        elif hash_mode == 1000:  # NTLM
            rules = ['OneRuleToRuleThemAll', 'best64', 'Dive', 'Hob064']
        elif hash_mode == 0:  # MD5
            rules = ['OneRuleToRuleThemAll', 'best64', 'OneRuleToRuleThemStill', 'Dive']
        else:  # Default for other hash types
            rules = ['OneRuleToRuleThemAll', 'best64', 'Dive', 'kaonashi']

        # Memory optimization - replace memory-intensive rules
        if memory_profile == 'low':
            # Replace memory-intensive rules with lighter alternatives
            replacements = {
                'generated2': 'kaonashi',
                'InsidePro-PasswordsPro': 'best64',
                'router_specific': 'Unicorn64'
            }
            rules = [replacements.get(r, r) for r in rules]

        # Deduplicate while preserving order and limit to MAX_RULES
        seen = set()
        unique_rules = []
        for r in rules:
            if r not in seen and len(unique_rules) < MAX_RULES:
                seen.add(r)
                unique_rules.append(r)

        return unique_rules[:MAX_RULES]

    def estimate_attack_time(self, hash_mode: int, wordlist_size: int,
                        rule_count: int, memory_profile: str) -> Dict:
        """Estimate attack time based on parameters"""
        # Base speeds (H/s) for different hash types
        base_speeds = {
            0: 15000000,    # MD5 (15 MH/s)
            1000: 8000000,  # NTLM (8 MH/s)
            1400: 5000000,  # SHA256 (5 MH/s)
            22000: 250,     # WPA-PBKDF2 (250 H/s)
            2500: 300,      # WPA-EAPOL (300 H/s)
            3200: 10,       # bcrypt (10 H/s)
            1800: 100,      # sha512crypt (100 H/s)
            500: 5000       # md5crypt (5 KH/s)
        }

        base_speed = base_speeds.get(hash_mode, 1000)

        # Adjust for memory profile
        memory_multiplier = {
            'low': 0.5,
            'medium': 0.8,
            'high': 1.0,
            'extreme': 1.2
        }.get(memory_profile, 0.8)

        # Adjust for rule count (rules slow down processing slightly)
        # No rules = no slowdown (multiplier = 1.0)
        if rule_count == 0:
            rule_multiplier = 1.0
        else:
            rule_multiplier = max(0.1, 1.0 / (1 + rule_count * 0.1))

        # Effective speed
        effective_speed = base_speed * memory_multiplier * rule_multiplier

        # Total candidates: straight wordlist if no rules, otherwise wordlist × rules
        if rule_count == 0:
            total_candidates = wordlist_size
        else:
            total_candidates = wordlist_size * rule_count

        # Time in seconds
        if total_candidates > 0 and effective_speed > 0:
            time_seconds = total_candidates / effective_speed
        else:
            time_seconds = 0

        # Format output
        if time_seconds < 60:
            time_str = f"{time_seconds:.1f} seconds"
        elif time_seconds < 3600:
            time_str = f"{time_seconds/60:.1f} minutes"
        elif time_seconds < 86400:
            time_str = f"{time_seconds/3600:.1f} hours"
        else:
            time_str = f"{time_seconds/86400:.1f} days"

        # Success probability estimation
        if rule_count == 0:
            # Straight wordlist - lower probability
            probability = min(0.95, 0.25 + (wordlist_size / 1000000 * 0.15))
        else:
            probability = min(0.95, 0.3 + (rule_count * 0.05) + (wordlist_size / 1000000 * 0.2))

        return {
            "estimated_speed": f"{effective_speed:,.0f} H/s",
            "total_candidates": f"{total_candidates:,}",
            "estimated_time": time_str,
            "success_probability": f"{probability:.1%}",
            "recommendation": "Add rules for better coverage" if rule_count == 0 or probability < 0.5 else "Good coverage expected"
        }

    def detect_available_devices(self) -> Dict[str, Any]:
        """Detect all available hashcat devices (CPU, GPU, etc)"""
        try:
            result = subprocess.run(['hashcat', '-I'],
                                    capture_output=True, text=True, timeout=10)
            output = result.stdout + result.stderr

            devices = {
                'has_cpu': False,
                'has_gpu': False,
                'has_metal': False,
                'has_opencl': False,
                'device_types': [],
                'gpu_memory': 0,
                'device_count': 0
            }

            # Check for Metal
            if 'Metal Info:' in output:
                devices['has_metal'] = True
                devices['device_types'].append('Metal')

            # Check for OpenCL GPU
            if 'OpenCL Platform' in output and 'GPU' in output:
                devices['has_gpu'] = True
                devices['has_opencl'] = True
                if 'Metal' not in devices['device_types']:
                    devices['device_types'].append('OpenCL GPU')

            # Check for CUDA
            if 'CUDA' in output:
                devices['has_gpu'] = True
                devices['device_types'].append('CUDA')

            # Extract GPU memory
            memory_match = re.search(r'Memory\.Total\.\.\.\.\: (\d+) MB', output)
            if memory_match:
                devices['gpu_memory'] = int(memory_match.group(1))

            # Count devices
            device_count = output.count('Backend Device ID')
            devices['device_count'] = device_count

            # Assume CPU is available on all systems
            devices['has_cpu'] = True
            if 'CPU' not in devices['device_types']:
                devices['device_types'].insert(0, 'CPU')

            return devices

        except Exception as e:
            print(f"⚠️  Error detecting devices: {e}")
            return {
                'has_cpu': True,
                'has_gpu': False,
                'has_metal': False,
                'has_opencl': False,
                'device_types': ['CPU'],
                'gpu_memory': 0,
                'device_count': 1
            }

    def get_device_flags(self, hash_mode: int, use_gpu: bool = True) -> str:
        """Get optimal device selection flags for macOS"""
        devices = self.detect_available_devices()

        print("\n🖥️  Available Devices:")
        for device_type in devices['device_types']:
            print(f"  ✓ {device_type}")

        if devices['gpu_memory'] > 0:
            print(f"  💾 GPU Memory: {devices['gpu_memory']} MB")

        # Apple Silicon: Metal is the only reliable API
        # Don't use CPU (-D 1) as it causes "No devices found/left" on M1/M2/M3
        if 'Metal' in devices['device_types']:
            print("\n⚙️  Using: GPU (Metal) - Apple Silicon detected")
            return "-D 2"  # Metal API
        elif devices['has_gpu'] and use_gpu:
            print("\n⚙️  Using: GPU")
            return "-D 2"
        else:
            print("\n⚙️  Using: CPU only")
            return "-D 1"

    def build_attack_command(self, hash_file: str, hash_mode: int,
                            wordlists: List[str], rules: List[str],
                            vendor: str = None, memory_profile: str = 'medium',
                            output_file: str = None, session: str = None,
                            enable_brute: bool = False) -> str:

        cmd_parts = ["hashcat", "-m", str(hash_mode)]

        devices = self.detect_available_devices()
        if 'Metal' in devices['device_types']:
            cmd_parts.extend(["-D", "2"])
        elif devices['has_gpu']:
            cmd_parts.extend(["-D", "2"])
        else:
            cmd_parts.extend(["-D", "1"])

        cmd_parts.extend(["--status", "--status-timer", "30", "-a", "0"])
        cmd_parts.append(hash_file)

        if vendor and vendor != 'generic' and hash_mode in [22000, 2500]:
            vendor_list = vendor if isinstance(vendor, list) else [vendor]
            for v in vendor_list:
                vendor_wl = self.wordlists_dir / f"{v}_passwords.txt"
                if vendor_wl.exists():
                    cmd_parts.append(str(vendor_wl))

        cmd_parts.extend(wordlists)

        if rules:
            for rule_name in rules:
                rule_path = self.download_rule(rule_name)
                if rule_path:
                    cmd_parts.extend(["-r", str(rule_path)])

        profile = self.memory_profiles[memory_profile]
        cmd_parts.extend(["-w", profile['w']])

        if session:
            cmd_parts.extend(["--session", session])
        else:
            cmd_parts.append("--restore-disable")

        if output_file:
            output_path = Path(output_file).resolve()
            if hash_mode in [22000, 2500, 22001]:
                cmd_parts.extend(["-o", str(output_path), "--outfile-format", "3"])
            else:
                cmd_parts.extend(["-o", str(output_path), "--outfile-format", "2,7"])
        else:
            cmd_parts.append("--potfile-disable")

        return " ".join(cmd_parts)

    def generate_wpa2_masks(self, vendor: str = None) -> List[str]:
        """Generate optimized mask attack patterns for WPA2"""
        base_masks = [
            '?l?l?l?l?l?l?l?l',           # 8 lowercase (common minimum)
            '?l?l?l?l?l?l?l?l?l?l',       # 10 lowercase
            '?u?l?l?l?l?l?l?l',           # Capitalized 8-char
            '?u?l?l?l?l?l?l?l?d?d',       # Capitalized + 2 digits
            '?l?l?l?l?d?d?d?d',           # 4 lower + 4 digits
            '?d?d?d?d?d?d?d?d',           # 8 digits (common for simple passwords)
            '?l?l?l?l?l?d?d?d',           # 5 lower + 3 digits
        ]

        # Add vendor-specific masks if vendor provided
        if vendor and vendor in self.wpa_vendors:
            vendor_patterns = self.wpa_vendors[vendor].get('common_patterns', [])
            # Convert regex patterns to hashcat masks (simplified)
            for pattern in vendor_patterns[:3]:  # Limit to top 3 vendor patterns
                if '[a-z]{5,6}[0-9]{4}[a-z]{5,6}' in pattern:
                    base_masks.insert(0, '?l?l?l?l?l?d?d?d?d?l?l?l?l?l')
                elif '[a-z]{4,6}[a-z]{4,6}[0-9]{3}' in pattern:
                    base_masks.insert(0, '?l?l?l?l?l?l?l?l?l?l?d?d?d')

        return base_masks[:5]  # Return top 5 masks to avoid excessive runtime

    def generate_hybrid_masks(self) -> List[str]:
        """Generate hybrid attack masks (wordlist + mask patterns) - 2025 Best Practices"""
        # Category 4: Best 2025 Hybrid Attack Patterns
        # Based on NetSPI & Rapid7 research - these patterns crack 29%+ of passwords
        hybrid_masks = [
            '?d?d',              # Wordlist + 2 digits (e.g., password24)
            '?d?d?d?d',          # Wordlist + 4 digits/year (e.g., password2024)
            '?s',                # Wordlist + special char (e.g., password!)
            '?d?d?s',            # Wordlist + 2 digits + special (e.g., password24!)
        ]

        return hybrid_masks

    def build_hybrid_command(self, hash_file: str, hash_mode: int,
                            wordlists: List[str], hybrid_masks: List[str],
                            vendor: str = None, memory_profile: str = 'medium',
                            output_file: str = None, session: str = None) -> str:
        """Build hybrid attack command (wordlist + mask patterns)"""
        cmd_parts = ["hashcat", "-m", str(hash_mode)]

        # Device detection
        devices = self.detect_available_devices()
        if 'Metal' in devices['device_types'] or devices['has_gpu']:
            cmd_parts.extend(["-D", "2"])
        else:
            cmd_parts.extend(["-D", "1"])

        # Attack mode 6 = hybrid wordlist + mask (append)
        cmd_parts.extend(["--status", "--status-timer", "30", "-a", "6"])
        cmd_parts.append(hash_file)

        # Add wordlists
        if vendor and vendor != 'generic' and hash_mode in [22000, 2500]:
            vendor_wl = self.wordlists_dir / f"{vendor}_passwords.txt"
            if vendor_wl.exists():
                cmd_parts.append(str(vendor_wl))

        cmd_parts.extend(wordlists)

        # Add first hybrid mask (we'll run multiple passes)
        if hybrid_masks:
            cmd_parts.append(hybrid_masks[0])

        # Memory profile
        profile = self.memory_profiles[memory_profile]
        cmd_parts.extend(["-w", profile['w']])

        if session:
            cmd_parts.extend(["--session", session])
        else:
            cmd_parts.append("--restore-disable")

        if output_file:
            # For WPA/WPA2, use format 3 to include ESSID:password
            # For other hashes, use format 2 (password only)
            if hash_mode in [22000, 2500, 22001]:
                cmd_parts.extend(["-o", output_file, "--outfile-format", "3"])
            else:
                cmd_parts.extend(["-o", output_file, "--outfile-format", "2"])
        else:
            cmd_parts.append("--potfile-disable")

        return " ".join(cmd_parts)

    def check_remaining_hashes(self, hash_file: str, output_file: str = None) -> Dict[str, Any]:
        """Check how many hashes remain uncracked"""
        try:
            # Use hashcat --show to see cracked hashes (hardcoded for WPA2)
            hash_mode = 22000
            cmd = ['hashcat', '--show', '-m', str(hash_mode), hash_file]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            cracked_lines = [line for line in result.stdout.strip().split('\n') if line and ':' in line]
            cracked = len(cracked_lines)

            # Count total hashes in file
            with open(hash_file, 'r') as f:
                total = len([line for line in f if line.strip()])

            remaining = total - cracked

            # Also collect cracked passwords from output file (fallback)
            cracked_passwords = []
            if output_file and Path(output_file).exists():
                with open(output_file, 'r') as f:
                    cracked_passwords = [line.strip() for line in f if line.strip()]

            return {
                'total': total,
                'cracked': cracked,
                'remaining': remaining,
                'progress_pct': (cracked / total * 100) if total > 0 else 0,
                'cracked_passwords': cracked_passwords,
                'cracked_details': cracked_lines
            }
        except Exception as e:
            return {
                'error': str(e),
                'total': 0,
                'cracked': 0,
                'remaining': 0,
                'progress_pct': 0,
                'cracked_passwords': [],
                'cracked_details': []
            }

    def build_bruteforce_command(self, hash_file: str, hash_mode: int,
                                  masks: List[str], vendor: str = None,
                                  memory_profile: str = 'medium',
                                  output_file: str = None,
                                  session: str = None) -> str:
        """Build mask attack (brute force) command for remaining hashes"""
        cmd_parts = ["hashcat", "-m", str(hash_mode)]

        # Device selection
        devices = self.detect_available_devices()
        if 'Metal' in devices['device_types'] or devices['has_gpu']:
            cmd_parts.extend(["-D", "2"])
        else:
            cmd_parts.extend(["-D", "1"])

        cmd_parts.extend(["--status", "--status-timer", "30"])

        # Attack mode 3 = mask attack (brute force)
        cmd_parts.extend(["-a", "3"])
        cmd_parts.append(hash_file)

        # Add first mask (we'll run multiple passes)
        if masks:
            cmd_parts.append(masks[0])

        # Increment mode for variable length passwords
        cmd_parts.extend(["--increment", "--increment-min", "8"])

        profile = self.memory_profiles[memory_profile]
        cmd_parts.extend(["-w", profile['w']])

        if session:
            cmd_parts.extend(["--session", f"{session}_brute"])

        if output_file:
            # For WPA/WPA2, use format 3 to include ESSID:password
            # For other hashes, use format 2 (password only)
            if hash_mode in [22000, 2500, 22001]:
                cmd_parts.extend(["-o", output_file, "--outfile-format", "3"])
            else:
                cmd_parts.extend(["-o", output_file, "--outfile-format", "2"])

        return " ".join(cmd_parts)

    def execute_multiphase_attack(self, hash_file: str, hash_mode: int,
                                  wordlists: List[str], rules: List[str],
                                  vendor: str = None, memory_profile: str = 'medium',
                                  output_file: str = None, session: str = None,
                                  enable_brute: bool = False):
        """Execute multi-phase attack: wordlist+rules first, then brute force on remaining"""

        print("\n" + "═" * 80)
        print("⚡ MULTI-PHASE ATTACK EXECUTION")
        print("═" * 80)

        # Phase 1: Wordlist + Rules Attack (skip if no rules/wordlists or already completed)
        skip_phase1 = not rules or (rules == [])

        if not skip_phase1:
            print("\n📋 PHASE 1: Wordlist + Rules Attack")
            print("─" * 80)

            phase1_cmd = self.build_attack_command(
                hash_file=hash_file,
                hash_mode=hash_mode,
                wordlists=wordlists,
                rules=rules,
                vendor=vendor,
                memory_profile=memory_profile,
                output_file=output_file,
                session=f"{session}_phase1" if session else None,
                enable_brute=False
            )

            print(f"\n✓ Phase 1 command:\n{phase1_cmd}\n")

            execute = input("▶️  Execute Phase 1 now? (Y/n): ").strip().lower()
            if execute != 'n':
                print("\n" + "═" * 80)
                print("⚡ EXECUTING PHASE 1")
                print("═" * 80)
                print("\n💡 Press Ctrl+C anytime to stop and see progress\n")

                try:
                    subprocess.run(phase1_cmd, shell=True)
                except KeyboardInterrupt:
                    print("\n\n" + "═" * 80)
                    print("⚠️  ATTACK INTERRUPTED BY USER (Ctrl+C)")
                    print("═" * 80)
                    print("\n💡 Checking progress before exit...\n")

                    # Show resume command immediately
                    if session:
                        print(f"📌 To resume this attack later:")
                        print(f"   hashcat --session {session}_phase1 --restore\n")
        else:
            print("\n📋 Skipping Phase 1 (Wordlist + Rules) - already completed")

        # Check results
        print("\n" + "═" * 80)
        print("📊 PHASE 1 RESULTS")
        print("═" * 80)

        status = self.check_remaining_hashes(hash_file, output_file)
        if 'error' not in status:
            print(f"\n✓ Cracked: {status['cracked']}/{status['total']} ({status['progress_pct']:.1f}%)")
            print(f"⏳ Remaining: {status['remaining']} hashes")

            # Show ALL cracked passwords
            if status['cracked'] > 0 and status['cracked_details']:
                print(f"\n🔓 CRACKED PASSWORDS ({len(status['cracked_details'])} total):")
                print("─" * 80)
                for i, detail in enumerate(status['cracked_details'], 1):
                    # Extract just SSID:password from hashcat --show output
                    parts = detail.split(':')
                    if len(parts) >= 3:
                        ssid = parts[-2]
                        password = parts[-1]
                        print(f"   {i:3}. {ssid:30} → {password}")
                print("─" * 80)

            if output_file:
                print(f"\n💾 Full results saved to: {output_file}")

            # Show resume info if session was used
            if session and status['remaining'] > 0:
                print(f"\n💡 To resume this attack later, use:")
                print(f"   hashcat --session {session}_phase1 --restore")

            # Phase 1.5: Hybrid Attack (wordlist + mask patterns)
            if status['remaining'] > 0 and hash_mode in [22000, 2500]:
                print("\n" + "═" * 80)
                print("📋 PHASE 1.5: Hybrid Attack (Wordlist + Mask - 2025 Best Patterns)")
                print("─" * 80)
                print("Based on NetSPI & Rapid7 research - these patterns crack 29%+ of passwords")

                hybrid_masks = self.generate_hybrid_masks()
                print(f"\n✓ Generated {len(hybrid_masks)} hybrid attack patterns:")
                for i, mask in enumerate(hybrid_masks, 1):
                    examples = {
                        '?d?d': 'password24',
                        '?d?d?d?d': 'password2024',
                        '?s': 'password!',
                        '?d?d?s': 'password24!'
                    }
                    example = examples.get(mask, '')
                    print(f"   {i}. {mask:15} (e.g., {example})")

                hybrid_cmd = self.build_hybrid_command(
                    hash_file=hash_file,
                    hash_mode=hash_mode,
                    wordlists=wordlists,
                    hybrid_masks=hybrid_masks,
                    vendor=vendor,
                    memory_profile=memory_profile,
                    output_file=output_file,
                    session=f"{session}_hybrid" if session else None
                )

                print(f"\n✓ Hybrid attack command prepared")
                print(f"   Remaining {status['remaining']} hashes will be targeted\n")

                execute_hybrid = input("▶️  Execute Hybrid Attack? (Y/n): ").strip().lower()
                if execute_hybrid != 'n':
                    print("\n" + "═" * 80)
                    print("⚡ EXECUTING HYBRID ATTACK")
                    print("═" * 80)
                    print("\n💡 Press Ctrl+C anytime to stop and see progress\n")

                    try:
                        # Run hybrid attack for each mask pattern
                        for i, mask in enumerate(hybrid_masks, 1):
                            print(f"\n🎯 Trying hybrid pattern {i}/{len(hybrid_masks)}: {mask}")
                            mask_cmd = hybrid_cmd.replace(hybrid_masks[0], mask)
                            subprocess.run(mask_cmd, shell=True)

                            # Check if all cracked
                            current_status = self.check_remaining_hashes(hash_file, output_file)
                            if current_status['remaining'] == 0:
                                print("\n🎉 All hashes cracked!")
                                break
                            else:
                                print(f"   Still remaining: {current_status['remaining']} hashes")
                    except KeyboardInterrupt:
                        print("\n\n" + "═" * 80)
                        print("⚠️  HYBRID ATTACK INTERRUPTED BY USER (Ctrl+C)")
                        print("═" * 80)
                        print("\n💡 Checking progress before continuing...\n")

                        if session:
                            print(f"📌 To resume Hybrid attack:")
                            print(f"   hashcat --session {session}_hybrid --restore\n")

                    # Update status after hybrid attack
                    status = self.check_remaining_hashes(hash_file, output_file)
                    print(f"\n✓ After Hybrid Attack: {status['cracked']}/{status['total']} cracked")
                    print(f"⏳ Remaining: {status['remaining']} hashes")

            # Phase 2: Brute Force (if enabled and hashes remain)
            if enable_brute and status['remaining'] > 0 and hash_mode in [22000, 2500]:
                print("\n" + "═" * 80)
                print("📋 PHASE 2: Brute Force Mask Attack (Remaining Hashes)")
                print("─" * 80)

                masks = self.generate_wpa2_masks(vendor)
                print(f"\n✓ Generated {len(masks)} optimized masks for WPA2")
                print("  Masks:", ", ".join(masks[:3]), "..." if len(masks) > 3 else "")

                phase2_cmd = self.build_bruteforce_command(
                    hash_file=hash_file,
                    hash_mode=hash_mode,
                    masks=masks,
                    vendor=vendor,
                    memory_profile=memory_profile,
                    output_file=output_file,
                    session=f"{session}_phase2" if session else None
                )

                print(f"\n✓ Phase 2 command:\n{phase2_cmd}\n")
                print(f"⚠️  Warning: Mask attacks can take significant time")
                print(f"   Remaining {status['remaining']} hashes will be targeted\n")

                execute_phase2 = input("▶️  Execute Phase 2 now? (y/N): ").strip().lower()
                if execute_phase2 == 'y':
                    print("\n" + "═" * 80)
                    print("⚡ EXECUTING PHASE 2")
                    print("═" * 80)
                    print("\n💡 Press Ctrl+C anytime to stop and see progress\n")

                    try:
                        # Run mask attack for each mask pattern
                        for i, mask in enumerate(masks, 1):
                            print(f"\n🎯 Trying mask {i}/{len(masks)}: {mask}")
                            mask_cmd = phase2_cmd.replace(masks[0], mask)
                            subprocess.run(mask_cmd, shell=True)

                            # Check if all cracked
                            current_status = self.check_remaining_hashes(hash_file, output_file)
                            if current_status['remaining'] == 0:
                                print("\n🎉 All hashes cracked!")
                                break
                    except KeyboardInterrupt:
                        print("\n\n" + "═" * 80)
                        print("⚠️  PHASE 2 INTERRUPTED BY USER (Ctrl+C)")
                        print("═" * 80)
                        print("\n💡 Checking progress before exit...\n")

                        # Show resume command immediately
                        if session:
                            print(f"📌 To resume Phase 2 brute force:")
                            print(f"   hashcat --session {session}_phase2 --restore\n")

                    # Final results
                    print("\n" + "═" * 80)
                    print("📊 FINAL RESULTS")
                    print("═" * 80)

                    final_status = self.check_remaining_hashes(hash_file, output_file)
                    if 'error' not in final_status:
                        print(f"\n✓ Total cracked: {final_status['cracked']}/{final_status['total']} ({final_status['progress_pct']:.1f}%)")
                        print(f"⏳ Remaining: {final_status['remaining']} hashes")

                        # Show ALL cracked passwords
                        if final_status['cracked'] > 0 and final_status['cracked_details']:
                            print(f"\n🔓 ALL CRACKED PASSWORDS ({len(final_status['cracked_details'])} total):")
                            print("─" * 80)
                            for i, detail in enumerate(final_status['cracked_details'], 1):
                                parts = detail.split(':')
                                if len(parts) >= 3:
                                    ssid = parts[-2]
                                    password = parts[-1]
                                    print(f"   {i:3}. {ssid:30} → {password}")
                            print("─" * 80)

                        if output_file:
                            print(f"\n💾 All results saved to: {output_file}")
                            print(f"📂 View with: cat {output_file}")
                            print(f"📂 Or use: hashcat --show -m 22000 {hash_file}")

                        # Show resume info if work remains
                        if session and final_status['remaining'] > 0:
                            print(f"\n📌 To continue this attack later:")
                            print(f"   hashcat --session {session}_phase2 --restore")
                else:
                    print("\n💡 Phase 2 command saved above. Run manually when ready.")
            elif enable_brute and status['remaining'] == 0:
                print("\n🎉 All hashes cracked in Phase 1! No brute force needed.")
            elif enable_brute:
                print(f"\n⚠️  Brute force only supported for WPA/WPA2 (modes 22000, 2500)")
        else:
            print(f"\n⚠️  Could not check status: {status['error']}")

    def interactive_wizard(self):
        print("\n" + "═" * 80)
        print("HASHCAT NEXUS v3.0 - Next-Generation Password Cracking")
        print("═" * 80)

        print("\n🔍 Detecting available devices...")
        devices = self.detect_available_devices()
        print("\n✓ Available devices:")
        for device in devices['device_types']:
            print(f"  • {device}")
        if devices['gpu_memory'] > 0:
            print(f"  • GPU Memory: {devices['gpu_memory']} MB")

        use_gpu = True
        if devices['has_gpu']:
            gpu_choice = input("\n💡 Use GPU acceleration? (Y/n): ").strip().lower()
            if gpu_choice == 'n':
                use_gpu = False

        while True:
            hash_file = input("\n📁 Enter hash file path: ").strip()
            if Path(hash_file).exists():
                break
            print("❌ File not found. Please try again.")

        print("\n🔍 Analyzing hash file...")
        analysis = self.analyze_hash_file(Path(hash_file))

        if "error" in analysis:
            print(f"⚠️  Analysis failed: {analysis['error']}")
            hash_mode = input("Enter hashcat mode manually (e.g., 1000 for NTLM): ").strip()
            hash_mode = int(hash_mode) if hash_mode.isdigit() else 1000
            detected_type = "Unknown"
        else:
            print(f"✓ Found {analysis['total_hashes']} hashes")
            print(f"✓ Hash type: {analysis['detected_type']} (mode {analysis['hash_mode']})")
            print(f"✓ Recommendation: {analysis['recommended_approach']}")

            if analysis['unique_salts'] > 0:
                print(f"⚠️  Note: {analysis['unique_salts']} unique salts detected")

            hash_mode = analysis['hash_mode']
            detected_type = analysis['detected_type']

        vendor = None
        if hash_mode == 22000 or hash_mode == 2500:
            print("\n📡 WPA/WPA2 Handshake Detected")
            print("Select vendor(s) for optimized attack (comma-separated for multiple):")
            vendors_list = list(self.wpa_vendors.keys())
            for i, vendor_name in enumerate(vendors_list, 1):
                vendor_desc = self.wpa_vendors[vendor_name].get('description', '')
                print(f"  {i:2}) {vendor_name.ljust(15)} - {vendor_desc}")

            while True:
                vendor_choice = input(
                    f"\nVendor(s) (1-{len(vendors_list)}, comma-separated, default: {len(vendors_list)}): ").strip()
                if not vendor_choice:
                    vendor = 'generic'
                    break

                try:
                    choices = [c.strip() for c in vendor_choice.split(',')]
                    selected_vendors = []

                    for choice in choices:
                        if choice.isdigit() and 1 <= int(choice) <= len(vendors_list):
                            selected_vendors.append(vendors_list[int(choice) - 1])
                        else:
                            print(f"❌ Invalid choice: {choice}")
                            selected_vendors = []
                            break

                    if selected_vendors:
                        if len(selected_vendors) == 1:
                            vendor = selected_vendors[0]
                        else:
                            vendor = selected_vendors
                        print(f"✓ Selected: {', '.join(selected_vendors) if isinstance(vendor, list) else vendor}")
                        break
                except:
                    print("❌ Invalid input. Please enter numbers separated by commas.")

        print("\n💾 Select memory profile:")
        print("  1. Low RAM (< 4GB)")
        print("  2. Medium RAM (4-8GB)")
        print("  3. High RAM (8-16GB)")
        print("  4. Extreme RAM (> 16GB)")

        while True:
            mem_choice = input("\nProfile (1-4, default: 2): ").strip()
            profiles = ['low', 'medium', 'high', 'extreme']
            if not mem_choice:
                memory_profile = 'medium'
                break
            elif mem_choice.isdigit() and 1 <= int(mem_choice) <= 4:
                memory_profile = profiles[int(mem_choice) - 1]
                break
            else:
                print("Invalid choice.")

        wordlist_base = self.setup_wordlists()

        if vendor and hash_mode in [22000, 2500] and vendor != 'generic':
            vendors_to_gen = vendor if isinstance(vendor, list) else [vendor]
            print("\n💡 Generating vendor wordlists...")
            for v in vendors_to_gen:
                vendor_wl_path = self.wordlists_dir / f"{v}_passwords.txt"
                if not vendor_wl_path.exists():
                    print(f"  Generating {v}...")
                    self.generate_vendor_wordlist(v, 100000)
                else:
                    print(f"  ✓ {v} exists")

        selected_wordlists = self.suggest_wordlist(wordlist_base, hash_mode, vendor)

        if not selected_wordlists:
            print("⚠️  No wordlists selected")
            return

        wordlist_paths = [str(wl) for wl in selected_wordlists]
        print(f"\n✓ Selected {len(wordlist_paths)} wordlist(s): {', '.join([Path(wl).name for wl in wordlist_paths])}")

        print("\n⚙️  Calculating optimal rules...")
        rules = self.get_optimal_rules(hash_mode, vendor, memory_profile)

        # Allow user to verify and customize rules
        rules = self.verify_and_customize_rules(rules, hash_mode)

        try:
            wordlist_size = sum(1 for _ in open(wordlist_paths[0], 'r', encoding='utf-8', errors='ignore'))
        except:
            wordlist_size = 1000000

        time_estimate = self.estimate_attack_time(hash_mode, wordlist_size, len(rules), memory_profile)

        print("\n📊 Attack Estimation:")
        print(f"  • Estimated speed: {time_estimate['estimated_speed']}")
        print(f"  • Total candidates: {time_estimate['total_candidates']}")
        print(f"  • Estimated time: {time_estimate['estimated_time']}")
        print(f"  • Success probability: {time_estimate['success_probability']}")
        print(f"  • Recommendation: {time_estimate['recommendation']}")

        enable_brute = False
        if hash_mode in [22000, 2500]:
            enable_brute = input("\n🔓 Enable brute force masks? (y/N): ").strip().lower() == 'y'

        output_file = input("\n💾 Output file (optional, for results): ").strip() or None
        session_name = input("\n💿 Session name (optional, for resuming): ").strip() or None

        # Multi-phase attack for brute force enabled
        if enable_brute:
            self.execute_multiphase_attack(
                hash_file=hash_file,
                hash_mode=hash_mode,
                wordlists=wordlist_paths,
                rules=rules,
                vendor=vendor,
                memory_profile=memory_profile,
                output_file=output_file,
                session=session_name,
                enable_brute=True
            )
        else:
            # Standard single-phase attack
            print("\n" + "═" * 80)
            print("🚀 BUILDING OPTIMIZED ATTACK COMMAND")
            print("═" * 80)

            command = self.build_attack_command(
                hash_file=hash_file,
                hash_mode=hash_mode,
                wordlists=wordlist_paths,
                rules=rules,
                vendor=vendor,
                memory_profile=memory_profile,
                output_file=output_file,
                session=session_name,
                enable_brute=False
            )

            print(f"\n✓ Generated optimized command:\n")
            print(command)
            print()

            save_script = input("💡 Save as script? (y/N): ").strip().lower()
            if save_script == 'y':
                script_name = f"attack_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sh"
                with open(script_name, 'w') as f:
                    f.write("#!/bin/bash\n")
                    f.write(f"# Hashcat Nexus generated attack\n")
                    f.write(f"# Timestamp: {datetime.now().isoformat()}\n")
                    f.write(f"# Hash type: {detected_type}\n")
                    f.write(f"# Rules: {', '.join(rules)}\n")
                    f.write(f"# Memory profile: {memory_profile}\n")
                    if vendor:
                        vendors_str = ', '.join(vendor) if isinstance(vendor, list) else vendor
                        f.write(f"# Vendors: {vendors_str}\n")
                    f.write("\n")
                    f.write(f"{command}\n")

                os.chmod(script_name, 0o755)
                print(f"✓ Script saved as {script_name}")

            execute = input("\n▶️  Execute now? (y/N): ").strip().lower()
            if execute == 'y':
                print("\n" + "═" * 80)
                print("⚡ EXECUTING HASHCAT")
                print("═" * 80)
                print("\n💡 Press Ctrl+C anytime to stop and see progress\n")

                try:
                    result = subprocess.run(command, shell=True)

                    if result.returncode == 0:
                        print(f"\n✓ Attack completed successfully")
                    else:
                        print(f"\n⚠️  Attack finished with return code {result.returncode}")
                except KeyboardInterrupt:
                    print("\n\n" + "═" * 80)
                    print("⚠️  ATTACK INTERRUPTED BY USER (Ctrl+C)")
                    print("═" * 80)
                    print("\n💡 Checking progress...\n")

                    if session_name:
                        print(f"📌 To resume this attack later:")
                        print(f"   hashcat --session {session_name} --restore\n")

                # Show results after completion or interruption
                if output_file or session_name:
                    status = self.check_remaining_hashes(hash_file, output_file)
                    if 'error' not in status:
                        print(f"\n📊 Current Progress:")
                        print(f"  ✓ Cracked: {status['cracked']}/{status['total']} ({status['progress_pct']:.1f}%)")
                        print(f"  ⏳ Remaining: {status['remaining']} hashes")

                        if status['cracked'] > 0:
                            # Display results nicely
                            self.display_cracked_results(hash_file, output_file, hash_mode)
                            print(f"💾 Full results saved to: {output_file}")

                        # Offer to continue with hybrid/mask attacks if hashes remain
                        if status['remaining'] > 0 and hash_mode in [22000, 2500]:
                            print("\n" + "═" * 80)
                            print(f"⚠️  {status['remaining']} hashes still remain uncracked")
                            print("═" * 80)
                            continue_attack = input("\n▶️  Continue with Hybrid/Mask attacks? (y/N): ").strip().lower()

                            if continue_attack == 'y':
                                # Run the multi-phase attack with remaining hashes
                                self.execute_multiphase_attack(
                                    hash_file=hash_file,
                                    hash_mode=hash_mode,
                                    wordlists=wordlist_paths,
                                    rules=[],  # Already ran rules/wordlist
                                    vendor=vendor,
                                    memory_profile=memory_profile,
                                    output_file=output_file,
                                    session=session_name,
                                    enable_brute=True
                                )
            else:
                print("\n📋 Command ready to copy/paste")
    
    def display_cracked_results(self, hash_file: str, output_file: str = None, hash_mode: int = None):
        """Display cracked results in a nice format using hashcat --show

        Args:
            hash_file: Path to the hash file
            output_file: Optional output file path
            hash_mode: Hash mode/type (auto-detected if not provided)
        """

        print("\n" + "═" * 80)
        print("CRACKED PASSWORDS")
        print("═" * 80 + "\n")

        try:
            # Auto-detect hash mode if not provided
            if hash_mode is None:
                analysis = self.analyze_hash_file(Path(hash_file))
                hash_mode = analysis.get('detected_mode')
                if hash_mode is None:
                    print("⚠️  Could not auto-detect hash type. Please provide hash_mode parameter.")
                    return

            # Use hashcat --show to get properly formatted results
            cmd = ['hashcat', '--show', '-m', str(hash_mode), hash_file]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            lines = [line.strip() for line in result.stdout.split('\n') if line.strip()]

            if not lines:
                print("  No passwords cracked yet")
                return

            # Parse results based on hash format
            # WPA/WPA2 (22000, 22001): hash:ESSID:password
            # Most other formats: hash:password or hash:salt:password
            if hash_mode in [22000, 22001]:
                # WPA/WPA2 format
                print(f"{'No.':<6} {'SSID':<30} {'Password':<40}")
                print("─" * 80)

                for i, line in enumerate(lines, 1):
                    parts = line.split(':')
                    if len(parts) >= 3:
                        ssid = parts[-2]
                        password = parts[-1]
                        print(f"{i:<6} {ssid:<30} {password:<40}")
                    else:
                        print(f"{i:<6} {line}")
            else:
                # Generic format - display hash and password
                print(f"{'No.':<6} {'Hash/Info':<50} {'Password':<30}")
                print("─" * 80)

                for i, line in enumerate(lines, 1):
                    parts = line.split(':')
                    if len(parts) >= 2:
                        # Last part is password, everything before is hash/salt/info
                        hash_info = ':'.join(parts[:-1])
                        password = parts[-1]
                        # Truncate hash if too long for display
                        if len(hash_info) > 47:
                            hash_info = hash_info[:44] + "..."
                        print(f"{i:<6} {hash_info:<50} {password:<30}")
                    else:
                        print(f"{i:<6} {line}")

            print(f"\n{'─' * 80}")
            print(f"Total: {len(lines)} password(s) cracked")

            if output_file:
                with open(output_file, 'w') as f:
                    for line in lines:
                        f.write(line + '\n')
                print(f"\n💾 Results saved to: {output_file}")

            print(f"📂 View anytime with: hashcat --show -m {hash_mode} {hash_file}\n")

        except subprocess.TimeoutExpired:
            print("⚠️  Timeout while retrieving results")
        except Exception as e:
            print(f"⚠️  Error displaying results: {e}")

            # Fallback: try reading output file directly
            if output_file and Path(output_file).exists():
                print(f"\n💡 Attempting to read from output file: {output_file}\n")
                try:
                    with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = [line.strip() for line in f if line.strip()]
                        for i, line in enumerate(lines, 1):
                            print(f"  {i:3}. {line}")
                        print(f"\nTotal: {len(lines)} password(s)\n")
                except Exception as e2:
                    print(f"⚠️  Could not read output file: {e2}")

def main():
    parser = argparse.ArgumentParser(description='Hashcat Nexus v3.0 - Next-Generation Password Cracking Optimizer')
    parser.add_argument('hash_file', nargs='?', help='Hash file to crack')
    parser.add_argument('-m', '--hash-type', type=int, help='Hashcat mode (auto-detected if not specified)')
    parser.add_argument('-w', '--wordlist', default='/usr/share/wordlists/rockyou.txt', help='Wordlist path')
    parser.add_argument('-v', '--vendor',
                        help='WPA vendor (cisco, aruba, ruckus, ubiquiti, meraki, comma-separated)')
    parser.add_argument('-p', '--profile', choices=['low', 'medium', 'high', 'extreme'],
                        default='medium', help='Memory profile')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-s', '--session', help='Session name')
    parser.add_argument('-b', '--brute', action='store_true', help='Enable brute force masks')
    parser.add_argument('--analyze', action='store_true', help='Analyze hash file only')
    parser.add_argument('--list-rules', action='store_true',
                        help='List all available rules with performance metrics')
    parser.add_argument('--list-wordlists', action='store_true',
                        help='List all available wordlists with download info')
    parser.add_argument('--download-rule', metavar='RULE_NAME',
                        help='Download specific rule by name')
    parser.add_argument('--download-wordlist', metavar='WORDLIST_NAME',
                        help='Download specific wordlist by name')
    parser.add_argument('--download-all-rules', action='store_true',
                        help='Download all top-tier rules')
    parser.add_argument('--auto', action='store_true',
                        help='Auto-select optimal rules based on hash type')
    parser.add_argument('--strategy', choices=['quick', 'balanced', 'comprehensive', 'maximum'],
                        default='balanced', help='Attack strategy for auto mode')

    args = parser.parse_args()

    nexus = HashcatNexus()

    if args.list_rules:
        nexus.list_all_rules()
        return

    if args.list_wordlists:
        nexus.list_all_wordlists()
        return

    if args.download_rule:
        nexus.download_rule(args.download_rule)
        return

    if args.download_wordlist:
        nexus.download_wordlist(args.download_wordlist)
        return

    if args.download_all_rules:
        print("Downloading all top-tier rules...")
        top_rules = [
            'OneRuleToRuleThemAll', 'OneRuleToRuleThemStill', 'Dive',
            'Unicorn64', 'Unicorn250', 'Unicorn1000',
            'd3ad0ne', 'hob064', 'best64', 'kaonashi',
            'clem9669_small', 'clem9669_medium', 'clem9669_large',
            'hashpwn_1500', 'hashpwn_3000', 'leetspeak'
        ]
        for rule_name in top_rules:
            print(f"\n📥 Downloading {rule_name}...")
            nexus.download_rule(rule_name)
        print("\n✓ Download complete!")
        return

    if args.hash_file:
        if args.analyze:
            analysis = nexus.analyze_hash_file(Path(args.hash_file))
            print(json.dumps(analysis, indent=2))
            return

        hash_mode = args.hash_type
        if not hash_mode:
            analysis = nexus.analyze_hash_file(Path(args.hash_file))
            hash_mode = analysis.get('hash_mode', 1000)
            print(f"Auto-detected hash type: {analysis.get('detected_type', 'Unknown')} (mode {hash_mode})")

        vendor = None
        if args.vendor:
            vendor_list = [v.strip().lower() for v in args.vendor.split(',')]
            vendor = vendor_list if len(vendor_list) > 1 else vendor_list[0]

        if args.auto:
            fast_hashes = [0, 1000, 1400, 1700]
            slow_hashes = [3200, 1800, 500, 7400]
            wpa_hashes = [22000, 22001, 2500]

            if args.strategy == 'quick':
                if hash_mode in wpa_hashes:
                    rules = ['Unicorn64', 'best64']
                elif hash_mode in slow_hashes:
                    rules = ['clem9669_small', 'Unicorn64']
                else:
                    rules = ['Unicorn64', 'hob064', 'best64']

            elif args.strategy == 'balanced':
                if hash_mode in wpa_hashes:
                    rules = ['kaonashi', 'best64', 'OneRuleToRuleThemAll', 'Unicorn250', 'hashpwn_1500', 'leetspeak']
                elif hash_mode in slow_hashes:
                    rules = ['clem9669_small', 'Unicorn64', 'best64', 'clem9669_medium']
                else:
                    rules = ['OneRuleToRuleThemAll', 'Unicorn250', 'Dive', 'hob064']

            elif args.strategy == 'comprehensive':
                if hash_mode in slow_hashes:
                    rules = ['clem9669_medium', 'InsidePro-PasswordsPro', 'OneRuleToRuleThemAll', 'Unicorn1000']
                else:
                    rules = ['OneRuleToRuleThemAll', 'Dive', 'd3ad0ne', 'Unicorn1000', 'generated2']

            else:
                if hash_mode in slow_hashes:
                    rules = ['clem9669_large', 'InsidePro-PasswordsPro', 'OneRuleToRuleThemAll', 'Dive',
                             'Unicorn1000']
                else:
                    rules = ['OneRuleToRuleThemAll', 'Dive', 'd3ad0ne', 'Unicorn1000', 'generated2',
                             'InsidePro-PasswordsPro']

            print(f"\n✓ Recommended rules for {args.strategy} strategy:")
            for i, rule in enumerate(rules, 1):
                print(f"  {i}. {rule}")
            
            if len(rules) > 4:
                print(f"\nHashcat supports max 4 chained rules.")
                while True:
                    pick = input(f"Pick up to 4 numbers (comma-separated, or press Enter for top 4): ").strip()
                    if not pick:
                        rules = rules[:4]
                        break
                    try:
                        indices = [int(x.strip()) - 1 for x in pick.split(',')]
                        if 1 <= len(indices) <= 4 and all(0 <= idx < len(rules) for idx in indices):
                            rules = [rules[idx] for idx in indices]
                            break
                        else:
                            print(f"⚠ Pick 1-4 numbers from 1-{len(rules)}")
                    except:
                        print("⚠ Invalid input, try again")
                
                print(f"\n✓ Using: {', '.join(rules)}")
        else:
            rules = nexus.get_optimal_rules(hash_mode, vendor, args.profile)

        if args.brute:
            nexus.execute_multiphase_attack(
                hash_file=args.hash_file,
                hash_mode=hash_mode,
                wordlists=[args.wordlist],
                rules=rules,
                vendor=vendor,
                memory_profile=args.profile,
                output_file=args.output,
                session=args.session,
                enable_brute=True
            )
        else:
            command = nexus.build_attack_command(
                hash_file=args.hash_file,
                hash_mode=hash_mode,
                wordlists=[args.wordlist],
                rules=rules,
                vendor=vendor,
                memory_profile=args.profile,
                output_file=args.output,
                session=args.session,
                enable_brute=False
            )

            print(f"\n✓ Generated optimized command:\n")
            print(command)
            print()

            execute = input("Execute now? (y/N): ").strip().lower()
            if execute == 'y':
                print(f"\n{'═' * 80}")
                print("EXECUTING HASHCAT")
                print(f"{'═' * 80}\n")
                subprocess.run(command, shell=True)
    else:
        nexus.interactive_wizard()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n" + "═" * 80)
        print("👋 HASHCAT NEXUS EXITED")
        print("═" * 80)
        print("\n✨ Thanks for using Hashcat Nexus!")
        print("💡 Your progress is automatically saved to hashcat's potfile")
        print("📂 Check results: hashcat --show <hashfile>\n")
        sys.exit(0)