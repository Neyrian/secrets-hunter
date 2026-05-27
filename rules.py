"""
SecretHunter - Rule Definitions and Detection Engines

This module contains the core analytical logic for SecretHunter. It includes 
regular expression signatures for known credential formats, mathematical 
functions for calculating Shannon Entropy, heuristic filters for minimizing 
false positives, and the primary orchestration function for line-by-line analysis.
"""

import math
import re
from typing import Dict, List, Any

SECRET_PATTERNS: Dict[str, str] = {
    # Cloud Infrastructure & Providers
    "AWS Access Key ID": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "AWS Secret Access Key": r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([^A-Za-z0-9+/])([A-Za-z0-9+/]{40})([^A-Za-z0-9+/])['\"]?",
    "Google Cloud API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Google OAuth Access Token": r"ya29\.[0-9A-Za-z\-_]+",
    "Azure Client Secret": r"[a-zA-Z0-9-_~.]{3,4}~[a-zA-Z0-9-_~.]{31}",
    "Heroku API Key": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    
    # Git & CI/CD Platforms
    "GitHub Personal Access Token": r"ghp_[a-zA-Z0-9]{36}",
    "GitHub OAuth Success Token": r"gho_[a-zA-Z0-9]{36}",
    "GitLab Personal Access Token": r"glpat-[a-zA-Z0-9\-]{20}",
    "BitBucket App Password": r"(?i)bitbucket[_-](client[_-])?(secret|id)[ \t]*[=:][ \t]*['\"]?[A-Za-z0-9a-zA-Z]{32}['\"]?",
    
    # Communication, Messaging & Collaboration APIs
    "Slack Token": r"xox[baprs]-[0-9A-Za-z]{10,48}",
    "Slack Webhook URL": r"https://hooks\.slack\.com/services/T[A-Z0-9_]{8}/B[A-Z0-9_]{8}/[A-Za-z0-9_]{24}",
    "Discord Bot Token": r"[MNNT][A-Za-z0-9]{23}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27}",
    "Telegram Bot Token": r"[0-9]{9,10}:[A-Za-z0-9_-]{35}",
    "Twilio API Key": r"SK[0-9a-fA-F]{32}",
    "SendGrid API Key": r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",
    
    # Payment Gateways & E-Commerce
    "Stripe Standard/Restricted API Key": r"(sk|rk)_live_[0-9a-zA-Z]{24,99}",
    "PayPal Braintree Access Token": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    "Square Access Token": r"sq0atp-[0-9A-Za-z\-_]{22}",
    "Shopify Access Token": r"shpat_[0-9a-fA-F]{32}",
    
    # Cryptography, Keys & Tokens
    "JSON Web Token (JWT)": r"ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "Generic Bearer Token": r"(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}",
    "SSH/Generic Private Key": r"-----BEGIN (RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY-----",
    "Database Connection String": r"(mongodb(?:\+srv)?|postgres|postgresql|mysql|sqlite|redis):\/\/[^:\s]+:[^@\s]+@[^?\s]+",
    "Basic Auth Header Base64": r"Basic\s+[A-Za-z0-9+/]{40,}={0,2}"
}

COMMENT_KEYWORD_REGEX = re.compile(
    r"\b(todo|fixme|remove before production|do not commit|creds|password|pass|pwd|token|secret|key|auth|login|api_key|apikey|dummy|test_token|hardcoded|temp|hack|bypass)\b", 
    re.IGNORECASE
)

def calculate_entropy(text: str) -> float:
    r"""
    Calculates the Shannon Entropy of a string to detect high-randomness patterns.

    The function applies the Shannon Entropy formula:
    $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
    where $P(x_i)$ is the probability of character $x_i$ appearing in the string.

    Args:
        text (str): The target string to evaluate.

    Returns:
        float: The calculated entropy value. Returns 0.0 for empty strings.
    """
    if not text:
        return 0.0
    
    frequencies = {}
    for char in text:
        frequencies[char] = frequencies.get(char, 0) + 1
        
    length = len(text)
    entropy = 0.0
    
    for count in frequencies.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
        
    return entropy

def is_valid_secret_structure(text: str) -> bool:
    """
    Applies abstract mathematical validation to distinguish between high-entropy 
    code/prose and actual cryptographic keys.

    This acts as a heuristic filter to reduce false positives by analyzing 
    character density, whitespace usage, and symbol-to-alphanumeric ratios.

    Args:
        text (str): The high-entropy string to validate.

    Returns:
        bool: True if the string geometrically resembles a valid token, False otherwise.
    """
    cleaned = text.strip()
    length = len(cleaned)
    
    # Cryptographic tokens, hashes, and private keys do not contain spaces.
    if cleaned.count(" ") > 1:
        return False
        
    # A random secret utilizes a high variety of characters relative to its size.
    unique_chars = len(set(cleaned))
    if unique_chars < 6 or (unique_chars / length) < 0.25:
        return False

    # Markup Symbol Filter
    symbol_count = len(re.findall(r"[\-;:,\(\)\{\}\[\]<=!]", cleaned))
    if symbol_count / length > 0.15:
        return False

    return True


def check_regex_signatures(line: str) -> List[Dict[str, Any]]:
    """
    Scans a text line against known patterns for concrete high-fidelity keys.

    Args:
        line (str): The line of code or text to analyze.

    Returns:
        List[Dict[str, Any]]: A list of dictionaries detailing any regex matches.
    """
    matches = []
    for name, pattern in SECRET_PATTERNS.items():
        match = re.search(pattern, line)
        if match:
            matches.append({
                "type": "Regex Match",
                "description": name,
                "value": match.group(0).strip()
            })
    return matches


def check_high_entropy_strings(line: str, entropy_threshold: float = 4.5) -> List[Dict[str, Any]]:
    """
    Extracts quoted assignments and flags strings exhibiting high statistical randomness.

    Args:
        line (str): The line of code or text to analyze.
        entropy_threshold (float, optional): The minimum entropy limit. Defaults to 4.5.

    Returns:
        List[Dict[str, Any]]: A list of dictionaries detailing high-entropy findings.
    """
    matches = []
    quoted_strings = re.findall(r"['\"`](.*?)['\"`]", line)
    
    for string in quoted_strings:
        if len(string) > 6:
            if not is_valid_secret_structure(string):
                continue
            entropy = calculate_entropy(string)
            if entropy > entropy_threshold:
                matches.append({
                    "type": "High Entropy",
                    "description": f"Potential Raw Secret (Entropy: {entropy:.2f})",
                    "value": string
                })
    return matches

def check_developer_comments(line: str) -> List[Dict[str, Any]]:
    """
    Parses code comments to find leftover developer notes using strict regex boundaries.

    Args:
        line (str): The line of code or text to analyze.

    Returns:
        List[Dict[str, Any]]: A list of dictionaries detailing suspicious comment findings.
    """
    matches = []
    
    # Match standard comment styles
    comment_match = re.search(r"(#|//|--)\s*(.*)", line)
    if comment_match:
        comment_text = comment_match.group(2).strip()
        
        keyword_match = COMMENT_KEYWORD_REGEX.search(comment_text)
        if keyword_match:
            matches.append({
                "type": "Suspicious Comment",
                "description": f"Comment flagged via keyword: '{keyword_match.group(1)}'",
                "value": comment_text
            })
                
    return matches


def scan_line(line: str, line_num: int, entropy_threshold: float = 4.5) -> List[Dict[str, Any]]:
    """
    Main orchestration engine that runs a single line through all detection modules.

    This function applies regex, entropy, and comment analysis sequentially. It also 
    handles deduplication (favoring regex over entropy) and respects the inline 
    'secret-hunter:ignore' bypass directive.

    Args:
        line (str): The line of code or text to analyze.
        line_num (int): The line number corresponding to the text being scanned.
        entropy_threshold (float, optional): The minimum entropy limit. Defaults to 4.5.

    Returns:
        List[Dict[str, Any]]: A merged and deduplicated list of all findings on the line.
    """
    if "secret-hunter:ignore" in line.lower():
        return []

    findings = []

    regex_results = check_regex_signatures(line)
    findings.extend(regex_results)

    entropy_results = check_high_entropy_strings(line, entropy_threshold)
    # Deduplicate
    for item in entropy_results:
        if not any(f["value"] in item["value"] for f in findings):
            findings.append(item)

    comment_results = check_developer_comments(line)
    # Deduplicate
    for item in comment_results:
        if not any(f["value"] in item["value"] for f in findings):
            findings.append(item)

    for finding in findings:
        finding["line"] = line_num

    return findings