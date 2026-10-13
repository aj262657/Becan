"""
detection_engine.py - Enterprise Digital Risk Protection (DRP) Threat Intelligence Engine
========================================================================================
Modular detection engine providing multi-vector brand protection forensics:
- Cyrillic / Greek IDN homoglyph deobfuscation and Punycode conversion
- Normalized Levenshtein distance and typosquatting analysis
- 64-bit Perceptual Hashing (pHash) with explicit Hamming distance bit-level forensics
- Developer ecosystem and free webmail anomaly detection
- Mathematical composite risk scoring with full component weighting and trace logic
"""

import re
import unicodedata
from typing import Dict, Any, List, Tuple, Optional
from pathlib import Path

# External libraries with pure-Python resilient fallbacks
try:
    import Levenshtein
    _HAS_LEVENSHTEIN = True
except ImportError:
    _HAS_LEVENSHTEIN = False

try:
    from PIL import Image
    import imagehash
    _HAS_IMAGEHASH = True
except ImportError:
    _HAS_IMAGEHASH = False


# Comprehensive Cyrillic, Greek, and Unicode Homoglyphs mapped to Latin characters
HOMOGLYPH_MAP = {
    # Cyrillic lowercase
    'а': 'a', 'в': 'v', 'г': 'g', 'д': 'd', 'е': 'e', 'ё': 'e',
    'ж': 'zh', 'з': 'z', 'и': 'i', 'й': 'i', 'к': 'k', 'л': 'l',
    'м': 'm', 'н': 'n', 'о': 'o', 'п': 'p', 'р': 'p', 'с': 'c',
    'т': 't', 'у': 'y', 'ф': 'f', 'х': 'x', 'ц': 'ts', 'ч': 'ch',
    'ш': 'sh', 'щ': 'sh', 'ъ': '', 'ы': 'y', 'ь': '', 'э': 'e',
    'ю': 'yu', 'я': 'ya',
    # Cyrillic Ukrainian / Belarusian / Rare
    'і': 'i', 'ї': 'i', 'є': 'e', 'ґ': 'g', 'ј': 'j', 'ѕ': 's',
    'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w',
    # Cyrillic uppercase
    'А': 'A', 'В': 'B', 'Г': 'G', 'Е': 'E', 'Ё': 'E', 'Ж': 'Zh',
    'З': 'Z', 'И': 'I', 'Й': 'I', 'К': 'K', 'Л': 'L', 'М': 'M',
    'Н': 'H', 'О': 'O', 'П': 'P', 'Р': 'P', 'С': 'C', 'Т': 'T',
    'У': 'Y', 'Ф': 'F', 'Х': 'X', 'Ц': 'Ts', 'Ч': 'Ch', 'Ш': 'Sh',
    'Щ': 'Sh', 'Э': 'E', 'Ю': 'Yu', 'Я': 'Ya',
    'І': 'I', 'Ї': 'I', 'Є': 'E', 'Ґ': 'G', 'Ј': 'J',
    # Greek lowercase and uppercase
    'α': 'a', 'β': 'b', 'γ': 'g', 'δ': 'd', 'ε': 'e', 'ζ': 'z',
    'η': 'h', 'θ': 'th', 'ι': 'i', 'κ': 'k', 'λ': 'l', 'μ': 'm',
    'ν': 'n', 'ξ': 'x', 'ο': 'o', 'π': 'p', 'ρ': 'p', 'σ': 's',
    'τ': 't', 'υ': 'u', 'φ': 'f', 'χ': 'x', 'ψ': 'ps', 'ω': 'o',
    'Α': 'A', 'Β': 'B', 'Γ': 'G', 'Δ': 'D', 'Ε': 'E', 'Ζ': 'Z',
    'Η': 'H', 'Θ': 'Th', 'Ι': 'I', 'Κ': 'K', 'Λ': 'L', 'Μ': 'M',
    'Ν': 'N', 'Ξ': 'X', 'Ο': 'O', 'Π': 'P', 'Ρ': 'P', 'Σ': 'S',
    'Τ': 'T', 'Υ': 'Y', 'Φ': 'F', 'Χ': 'X', 'Ψ': 'Ps', 'Ω': 'O',
}

# Common leetspeak substitutions
LEETSPEAK_MAP = {
    '0': 'o',
    '1': 'i',
    '3': 'e',
    '4': 'a',
    '5': 's',
    '7': 't',
    '8': 'b',
    '@': 'a',
    '$': 's',
    '!': 'i',
}

# Scam and high-risk trigger tokens in enterprise financial phishing
SCAM_TOKENS = [
    'support',
    'helpdesk',
    'claim',
    'verify',
    'verification',
    'apk',
    'fast cash',
    'quickloan',
    'quick loan',
    'instant loan',
    'login',
    'auth',
    'secure',
    'security',
    'official',
    'recovery',
    'refund',
    'giveaway',
    'bonus',
    'crypto',
    'wallet',
    'help',
    'care',
    'customer service',
    'hotline',
    'portal',
    'desk',
    'escalation',
    'staking',
    'unfreeze',
    'overdraft',
]

# Free / unverified webmail providers disallowed for official corporate apps
FREE_EMAIL_DOMAINS = {
    'gmail.com',
    'yahoo.com',
    'hotmail.com',
    'outlook.com',
    'proton.me',
    'protonmail.com',
    'aol.com',
    'mail.com',
    'yandex.com',
    'gmx.com',
    'icloud.com',
}


def _pure_levenshtein(s1: str, s2: str) -> int:
    """Pure-python fallback for Levenshtein distance."""
    if len(s1) < len(s2):
        return _pure_levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def get_levenshtein_distance(s1: str, s2: str) -> int:
    """Compute Levenshtein distance using C extension or fallback."""
    if _HAS_LEVENSHTEIN:
        return Levenshtein.distance(s1, s2)
    return _pure_levenshtein(s1, s2)


def get_levenshtein_ratio(s1: str, s2: str) -> float:
    """Compute Levenshtein similarity ratio between 0.0 and 1.0."""
    if not s1 and not s2:
        return 1.0
    if not s1 or not s2:
        return 0.0
    if _HAS_LEVENSHTEIN:
        return Levenshtein.ratio(s1, s2)
    dist = _pure_levenshtein(s1, s2)
    max_len = max(len(s1), len(s2))
    return max(0.0, 1.0 - (dist / max_len))


def compute_punycode(text: str) -> str:
    """Computes RFC 3492 / IDNA Punycode representation for internationalized domains/handles."""
    try:
        clean = text.lstrip('@').split('/')[0].strip()
        encoded = clean.encode('idna').decode('ascii')
        return f"xn--{encoded[4:]}" if encoded.startswith('xn--') else encoded
    except Exception:
        return text


def normalize_text(text: str) -> Tuple[str, bool, List[Dict[str, Any]], str]:
    """
    Normalizes Cyrillic homoglyphs, Greek letters, and leetspeak into Latin chars.
    Returns:
        (normalized_string, has_homoglyphs, detailed_homoglyphs_list, punycode_representation)
    """
    detected_homoglyphs = []
    has_homoglyphs = False
    chars = []

    for idx, char in enumerate(text):
        if char in HOMOGLYPH_MAP:
            mapped = HOMOGLYPH_MAP[char]
            cp = ord(char)
            script = "Cyrillic" if (0x0400 <= cp <= 0x052F) else "Greek" if (0x0370 <= cp <= 0x03FF) else "Unicode Other"
            detected_homoglyphs.append({
                "char": char,
                "replacement": mapped,
                "unicode_hex": f"U+{cp:04X}",
                "latin_hex": f"U+{ord(mapped):04X}",
                "name": unicodedata.name(char, "UNKNOWN"),
                "script": script,
                "position": idx,
                "decimal_codepoint": cp
            })
            chars.append(mapped)
            has_homoglyphs = True
        elif char in LEETSPEAK_MAP:
            mapped = LEETSPEAK_MAP[char]
            chars.append(mapped)
        else:
            chars.append(char)

    normalized = "".join(chars)
    nfkd = unicodedata.normalize('NFKD', normalized)
    normalized = "".join([c for c in nfkd if not unicodedata.combining(c)])
    punycode = compute_punycode(text) if has_homoglyphs else ""

    return normalized, has_homoglyphs, detected_homoglyphs, punycode


def clean_alphanumeric(text: str) -> str:
    """Strip spaces, underscores, hyphens, and symbols for direct brand matching."""
    return re.sub(r'[^a-zA-Z0-9]', '', text).lower()


def is_allowlisted(entity: Dict[str, Any], official_assets: Dict[str, Any]) -> bool:
    """
    Excludes official assets from threat calculation (assigns 0 risk / Clean).
    Checks:
    - Entity explicit 'is_allowlisted' flag
    - Handle in official_handles
    - Package name in official_packages
    - Exact match in official handles / names / domains
    """
    if entity.get("is_allowlisted") is True:
        return True

    handle = (entity.get("handle") or "").strip().lower()
    name = (entity.get("name") or "").strip().lower()
    pkg = (entity.get("package_name") or "").strip().lower()

    official_handles = [h.strip().lower() for h in (official_assets.get("official_handles") or [])]
    official_packages = [p.strip().lower() for p in (official_assets.get("official_packages") or [])]
    official_names = [n.strip().lower() for n in (official_assets.get("brand_aliases") or [])]
    if official_assets.get("brand_name"):
        official_names.append(official_assets["brand_name"].strip().lower())

    if handle and handle in official_handles:
        return True

    if pkg and pkg in official_packages:
        return True

    if name and name in official_names and entity.get("is_official_verified") is True:
        return True

    return False


def calculate_text_similarity(
    discovered_name: str,
    brand_name: str,
    brand_aliases: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Normalizes Cyrillic homoglyphs and leetspeak, computes Levenshtein distance,
    and flags scam tokens ('support', 'helpdesk', 'claim', 'verify', 'apk', etc.).
    """
    if brand_aliases is None:
        brand_aliases = []

    targets = [brand_name] + brand_aliases
    norm_discovered, has_homoglyphs, homoglyphs, punycode = normalize_text(discovered_name)
    clean_discovered = clean_alphanumeric(norm_discovered)
    discovered_lower = discovered_name.lower()
    norm_discovered_lower = norm_discovered.lower()

    # Detect scam tokens in both original and normalized forms
    flagged_tokens = []
    for token in SCAM_TOKENS:
        token_clean = clean_alphanumeric(token)
        if token in discovered_lower or token in norm_discovered_lower or token_clean in clean_discovered:
            if token not in flagged_tokens:
                flagged_tokens.append(token)

    best_ratio = 0.0
    best_dist = 999
    best_target = brand_name
    best_type = "levenshtein"

    for target in targets:
        norm_target, _, _, _ = normalize_text(target)
        clean_target = clean_alphanumeric(norm_target)

        # 1. Direct Levenshtein on alphanumeric cleaned tokens
        ratio = get_levenshtein_ratio(clean_discovered, clean_target)
        dist = get_levenshtein_distance(clean_discovered, clean_target)

        # 2. Check if brand is a contained substring
        is_substring = clean_target in clean_discovered or clean_discovered in clean_target
        if is_substring and len(clean_target) > 3:
            sub_ratio = len(clean_target) / max(len(clean_discovered), 1)
            adjusted_ratio = max(ratio, 0.75 + (0.25 * sub_ratio))
            if adjusted_ratio > best_ratio:
                best_ratio = adjusted_ratio
                best_dist = min(dist, abs(len(clean_discovered) - len(clean_target)))
                best_target = target
                best_type = "substring_match"
        else:
            if ratio > best_ratio:
                best_ratio = ratio
                best_dist = dist
                best_target = target
                best_type = "ratio_match"

    text_score = best_ratio * 100.0

    # Boost score for intentional homoglyph deception
    if has_homoglyphs:
        for target in targets:
            clean_tgt = clean_alphanumeric(target)
            if clean_tgt == clean_discovered or get_levenshtein_distance(clean_tgt, clean_discovered) <= 1:
                text_score = max(text_score, 98.0)
                break
        else:
            text_score = min(100.0, text_score + 25.0)

    # Boost score if scam tokens are combined with the brand name
    if flagged_tokens and any(clean_alphanumeric(t) in clean_discovered for t in targets):
        token_bonus = min(25.0, len(flagged_tokens) * 12.0)
        text_score = min(100.0, text_score + token_bonus)

    text_score = min(100.0, max(0.0, text_score))

    return {
        "text_score": round(text_score, 1),
        "normalized_name": norm_discovered,
        "has_homoglyphs": has_homoglyphs,
        "detected_homoglyphs": homoglyphs,
        "punycode": punycode,
        "flagged_tokens": flagged_tokens,
        "best_target": best_target,
        "levenshtein_distance": best_dist,
        "levenshtein_ratio": round(best_ratio, 3),
        "match_type": best_type,
    }


def compute_phash_forensics(
    discovered_img: Optional[Any],
    official_img: Optional[Any],
    threshold: int = 10
) -> Dict[str, Any]:
    """
    Computes mathematical 64-bit Perceptual Hash forensics:
    - 64-bit Hex strings
    - 64-bit Binary bitstrings
    - Bitwise XOR bitmask of differences
    - Hamming distance d_H
    - Threshold comparison (tau = 10 bits)
    - Calculated match score (0-100)
    """
    default_payload = {
        "score": 0.0,
        "hamming_distance": 64,
        "threshold": threshold,
        "is_match": False,
        "bits_identical": 0,
        "bit_match_ratio": 0.0,
        "discovered_hash_hex": "0000000000000000",
        "official_hash_hex": "0000000000000000",
        "discovered_hash_bin": "0" * 64,
        "official_hash_bin": "0" * 64,
        "xor_diff_bin": "1" * 64,
        "verdict": "NO_IMAGE_EVIDENCE"
    }

    if discovered_img is None or official_img is None or not _HAS_IMAGEHASH:
        return default_payload

    try:
        # Load discovered image
        if isinstance(discovered_img, (str, Path)):
            p1 = Path(discovered_img)
            if not p1.is_file():
                return default_payload
            img1 = Image.open(p1)
        elif isinstance(discovered_img, Image.Image):
            img1 = discovered_img
        else:
            return default_payload

        # Load official image
        if isinstance(official_img, (str, Path)):
            p2 = Path(official_img)
            if not p2.is_file():
                return default_payload
            img2 = Image.open(p2)
        elif isinstance(official_img, Image.Image):
            img2 = official_img
        else:
            return default_payload

        if img1.mode != 'RGB':
            img1 = img1.convert('RGB')
        if img2.mode != 'RGB':
            img2 = img2.convert('RGB')

        hash1 = imagehash.phash(img1)
        hash2 = imagehash.phash(img2)

        dist = int(hash1 - hash2)
        h1_hex = str(hash1).zfill(16)
        h2_hex = str(hash2).zfill(16)

        h1_bin = bin(int(h1_hex, 16))[2:].zfill(64)
        h2_bin = bin(int(h2_hex, 16))[2:].zfill(64)
        xor_diff = "".join(["1" if b1 != b2 else "0" for b1, b2 in zip(h1_bin, h2_bin)])

        bits_ident = 64 - dist
        bit_match_ratio = round(bits_ident / 64.0, 4)

        if dist == 0:
            score = 100.0
            verdict = "EXACT_PIXEL_HASH_DUPLICATION (d_H = 0)"
        elif dist <= 4:
            score = 100.0 - (dist * 2.0)
            verdict = "NEAR_IDENTICAL_REPLICATED_ASSET (d_H <= 4)"
        elif dist <= 10:
            score = 92.0 - ((dist - 4) * 2.5)
            verdict = "HIGH_CONFIDENCE_COPYRIGHT_MATCH (d_H <= 10)"
        elif dist <= 20:
            score = 72.0 - ((dist - 10) * 2.5)
            verdict = "MODERATE_VISUAL_SIMILARITY (d_H <= 20)"
        else:
            score = max(0.0, 42.0 - ((dist - 20) * 1.5))
            verdict = "DISTINCT_VISUAL_ASSET (d_H > 20)"

        is_match = dist <= threshold

        return {
            "score": round(float(score), 1),
            "hamming_distance": dist,
            "threshold": threshold,
            "is_match": is_match,
            "bits_identical": bits_ident,
            "bit_match_ratio": bit_match_ratio,
            "discovered_hash_hex": f"0x{h1_hex.upper()}",
            "official_hash_hex": f"0x{h2_hex.upper()}",
            "discovered_hash_bin": h1_bin,
            "official_hash_bin": h2_bin,
            "xor_diff_bin": xor_diff,
            "verdict": verdict
        }
    except Exception:
        return default_payload


def calculate_logo_similarity(
    discovered_img: Optional[Any],
    official_img: Optional[Any]
) -> float:
    """Returns 0–100 match score using perceptual hash."""
    forensics = compute_phash_forensics(discovered_img, official_img)
    return forensics["score"]


def calculate_metadata_risk(
    entity: Dict[str, Any],
    official_brand: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Flags unverified social accounts and mismatched developer emails
    (e.g., @gmail.com for an official corporate app).
    """
    flags: List[str] = []
    metadata_risk_score = 0.0

    entity_type = entity.get("type", "social_media")
    platform = (entity.get("platform") or "").lower()
    is_verified = entity.get("is_verified", False)
    dev_email = (entity.get("developer_email") or "").strip().lower()
    package_name = (entity.get("package_name") or "").strip().lower()

    official_domain = (official_brand.get("domain") or "revolut.com").lower()
    official_packages = [p.lower() for p in (official_brand.get("official_packages") or [])]

    # 1. Social Account Verification Check
    if entity_type == "social_media" or any(p in platform for p in ["twitter", "x", "instagram", "facebook", "telegram", "tiktok", "linkedin"]):
        if not is_verified:
            flags.append("Unverified Social Media Account (Absence of corporate blue/gold verification badge)")
            metadata_risk_score += 35.0
        else:
            metadata_risk_score = max(0.0, metadata_risk_score - 10.0)

    # 2. Mobile App Developer Email and Package Namespace Check
    if entity_type == "mobile_app" or any(p in platform for p in ["google play", "app store", "apk", "android", "ios"]):
        if dev_email:
            email_domain = dev_email.split("@")[-1] if "@" in dev_email else ""
            if email_domain in FREE_EMAIL_DOMAINS:
                flags.append(f"Mismatched Free Webmail Developer Email: '{dev_email}' (Expected corporate @{official_domain})")
                metadata_risk_score += 55.0
            elif email_domain and email_domain != official_domain and not official_domain.endswith(email_domain):
                flags.append(f"Untrusted Developer Email Domain: '{dev_email}' (Mismatch with corporate domain @{official_domain})")
                metadata_risk_score += 40.0
        else:
            flags.append("Missing Enterprise Developer Contact Information")
            metadata_risk_score += 20.0

        if package_name:
            if official_packages and package_name not in official_packages:
                flags.append(f"Non-Official Package Namespace: '{package_name}'")
                metadata_risk_score += 30.0

    # 3. Third-party APK Mirror / Sideloading Platform Check
    if "apk" in platform or "mirror" in platform or "sideload" in platform:
        flags.append(f"Unsanctioned Sideloading Distribution Channel: '{entity.get('platform')}'")
        metadata_risk_score += 30.0

    # 4. Low Engagement / Low Follower Anomaly
    followers = entity.get("followers", None)
    if followers is not None and followers < 50:
        flags.append(f"Anomalous Engagement Metric ({followers} followers - Indicative of ephemeral threat infra)")
        metadata_risk_score += 15.0

    # 5. Benign indicators
    bio = (entity.get("bio") or entity.get("description") or "").lower()
    if "fan account" in bio or "parody" in bio or "not affiliated" in bio or "fan page" in bio:
        flags.append("Entity Discloses Fan/Parody Disclaimer (Non-malicious intent factor)")
        metadata_risk_score = max(10.0, metadata_risk_score - 25.0)

    category = (entity.get("category") or "").lower()
    if category and any(c in category for c in ["detailing", "automotive", "car", "pet", "aquarium", "plumbing", "hardware"]):
        flags.append(f"Unrelated Commercial Trademark Sector: '{entity.get('category')}'")
        metadata_risk_score = max(5.0, metadata_risk_score - 40.0)

    metadata_risk_score = min(100.0, max(0.0, metadata_risk_score))

    return {
        "metadata_score": round(metadata_risk_score, 1),
        "flags": flags
    }


def compute_composite_risk(
    entity: Dict[str, Any],
    official_brand: Dict[str, Any],
    discovered_logo_path: Optional[str] = None,
    official_logo_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Aggregates threat telemetry into a 0–100 composite risk score with explicit
    mathematical breakdown and severity tiers (Critical, High, Medium, Low, Clean).
    """
    # 1. Allowlist gate
    if is_allowlisted(entity, official_brand):
        return {
            "composite_score": 0.0,
            "severity": "Clean",
            "is_allowlisted": True,
            "text_score": 0.0,
            "logo_score": 0.0,
            "metadata_score": 0.0,
            "reasons": ["Official verified brand asset included on enterprise baseline allowlist."],
            "flags": [],
            "math_breakdown": {
                "formula": "Composite = 0.0 (Allowlisted baseline exemption)",
                "weights": {"w_text": 0.35, "w_logo": 0.35, "w_meta": 0.30},
                "components": {"weighted_text": 0.0, "weighted_logo": 0.0, "weighted_meta": 0.0},
                "base_sum": 0.0,
                "boosters": [],
                "dampeners": [],
                "final_score": 0.0,
            },
            "logo_forensics": {
                "score": 0.0,
                "hamming_distance": 0,
                "threshold": 10,
                "is_match": True,
                "bits_identical": 64,
                "bit_match_ratio": 1.0,
                "discovered_hash_hex": "OFFICIAL_ASSET",
                "official_hash_hex": "OFFICIAL_ASSET",
                "discovered_hash_bin": "0" * 64,
                "official_hash_bin": "0" * 64,
                "xor_diff_bin": "0" * 64,
                "verdict": "AUTHORIZED_OFFICIAL_ASSET"
            },
            "breakdown": {
                "text_similarity": 0.0,
                "logo_similarity": 0.0,
                "metadata_risk": 0.0,
                "has_homoglyphs": False,
                "scam_tokens": []
            }
        }

    # 2. Text Similarity
    discovered_name = entity.get("name") or entity.get("handle") or ""
    brand_name = official_brand.get("brand_name", "")
    brand_aliases = official_brand.get("brand_aliases", [])
    text_res = calculate_text_similarity(discovered_name, brand_name, brand_aliases)

    # 3. Logo Visual Forensics
    logo_path = discovered_logo_path or entity.get("logo_path")
    off_logo = official_logo_path or official_brand.get("logo_path")
    logo_forensics = compute_phash_forensics(logo_path, off_logo)
    logo_score = logo_forensics["score"]

    # 4. Metadata Risk
    meta_res = calculate_metadata_risk(entity, official_brand)

    # 5. Mathematical Composite Calculation
    # Weights: Text 35%, Logo 35%, Metadata 30%
    w_t, w_l, w_m = 0.35, 0.35, 0.30
    weighted_text = round(text_res["text_score"] * w_t, 2)
    weighted_logo = round(logo_score * w_l, 2)
    weighted_meta = round(meta_res["metadata_score"] * w_m, 2)
    base_sum = round(weighted_text + weighted_logo + weighted_meta, 2)

    current_score = base_sum
    boosters = []
    dampeners = []
    reasons: List[str] = []

    # Threat Multipliers & Boosters
    if text_res["has_homoglyphs"]:
        chars_str = ", ".join([f"{h['char']} ({h['unicode_hex']}) -> {h['replacement']}" for h in text_res["detected_homoglyphs"]])
        reasons.append(f"Cyrillic IDN homoglyph visual spoofing detected: {chars_str}")
        if current_score < 88.0:
            delta = round(88.0 - current_score, 1)
            boosters.append({"factor": "Cyrillic Homoglyph Attack Vector (High Deception)", "delta": f"+{delta} pts"})
            current_score = 88.0

    if text_res["flagged_tokens"]:
        tokens_str = ", ".join(f"'{t}'" for t in text_res["flagged_tokens"])
        reasons.append(f"High-risk financial phishing tokens flagged: {tokens_str}")
        if len(text_res["flagged_tokens"]) >= 2 and current_score < 75.0:
            boosters.append({"factor": "Multiple Phishing Lure Tokens", "delta": "+15.0 pts"})
            current_score = min(100.0, current_score + 15.0)

    if logo_score >= 80.0:
        reasons.append(f"Visual asset copyright infringement: Perceptual pHash match is {logo_score}% (d_H = {logo_forensics['hamming_distance']} bits <= 10)")
        if text_res["flagged_tokens"] or text_res["has_homoglyphs"]:
            if current_score < 92.0:
                delta = round(92.0 - current_score, 1)
                boosters.append({"factor": "Replicated Trademark Visual + Phishing Trigger", "delta": f"+{delta} pts"})
                current_score = 92.0

    # Rogue Mobile App with Mismatched Webmail
    if entity.get("type") == "mobile_app" and any("Mismatched Free Webmail" in f for f in meta_res["flags"]):
        reasons.append("Critical Rogue APK: Financial neobank app distributed via unauthorized personal webmail (@gmail.com).")
        if current_score < 85.0:
            delta = round(85.0 - current_score, 1)
            boosters.append({"factor": "Rogue Mobile APK / Untrusted Developer Webmail", "delta": f"+{delta} pts"})
            current_score = 85.0

    for flag in meta_res["flags"]:
        reasons.append(flag)

    # Dampeners for Benign Entities
    category = (entity.get("category") or "").lower()
    is_unrelated = any(c in category for c in ["detailing", "automotive", "car", "pet", "aquarium", "plumbing", "hardware"])
    is_fan = "fan" in (entity.get("handle") or "").lower() or "community" in (entity.get("name") or "").lower()

    if is_unrelated and logo_score <= 35.0 and not text_res["flagged_tokens"]:
        dampeners.append({"factor": "Unrelated Industry & Distinct Logo (Benign Commercial Trademark)", "delta": f"-{round(current_score - 12.0, 1)} pts"})
        current_score = min(current_score, 12.0)
        reasons.append("Low risk: Coincidental brand name overlap in distinct non-financial industry.")
    elif is_fan and not text_res["flagged_tokens"] and logo_score < 70.0:
        dampeners.append({"factor": "Fan/Parody Community Disclosure Without Phishing Lures", "delta": f"-{round(current_score - 32.0, 1)} pts"})
        current_score = min(current_score, 32.0)
        reasons.append("Medium-Low risk: Fan/parody account without malicious phishing triggers.")

    composite_score = round(min(100.0, max(0.0, current_score)), 1)

    # 6. Severity Category
    if composite_score >= 75.0:
        severity = "Critical"
    elif composite_score >= 50.0:
        severity = "High"
    elif composite_score >= 25.0:
        severity = "Medium"
    elif composite_score > 0.0:
        severity = "Low"
    else:
        severity = "Clean"

    return {
        "composite_score": composite_score,
        "severity": severity,
        "is_allowlisted": False,
        "text_score": text_res["text_score"],
        "logo_score": logo_score,
        "metadata_score": meta_res["metadata_score"],
        "reasons": reasons,
        "flags": meta_res["flags"],
        "math_breakdown": {
            "formula": "Composite = min(100.0, max(0.0, (0.35 * S_text) + (0.35 * S_logo) + (0.30 * S_meta) + Boost - Damp))",
            "weights": {"w_text": w_t, "w_logo": w_l, "w_meta": w_m},
            "components": {
                "weighted_text": weighted_text,
                "weighted_logo": weighted_logo,
                "weighted_meta": weighted_meta,
            },
            "base_sum": base_sum,
            "boosters": boosters,
            "dampeners": dampeners,
            "final_score": composite_score,
        },
        "logo_forensics": logo_forensics,
        "breakdown": {
            "text_similarity": text_res["text_score"],
            "logo_similarity": logo_score,
            "metadata_risk": meta_res["metadata_score"],
            "has_homoglyphs": text_res["has_homoglyphs"],
            "detected_homoglyphs": text_res["detected_homoglyphs"],
            "punycode": text_res["punycode"],
            "scam_tokens": text_res["flagged_tokens"],
            "normalized_name": text_res["normalized_name"],
            "levenshtein_distance": text_res["levenshtein_distance"],
            "levenshtein_ratio": text_res["levenshtein_ratio"],
        }
    }


def generate_takedown_notice(
    entity: Dict[str, Any],
    brand_config: Dict[str, Any],
    risk_analysis: Dict[str, Any]
) -> str:
    """
    Generates a formal enterprise-grade DMCA and Trademark Abuse takedown notice packet
    with legal statutory references (17 U.S.C. § 512, Lanham Act 15 U.S.C. § 1125, EU DSA).
    """
    brand_name = brand_config.get("brand_name", "Revolut Ltd")
    domain = brand_config.get("domain", "revolut.com")
    entity_name = entity.get("name", "Unknown")
    handle = entity.get("handle") or "N/A"
    platform = entity.get("platform", "Online Platform")
    url = entity.get("url", "N/A")
    score = risk_analysis.get("composite_score", 0.0)
    severity = risk_analysis.get("severity", "UNKNOWN")
    reasons = risk_analysis.get("reasons", [])
    logo_forensics = risk_analysis.get("logo_forensics", {})
    breakdown = risk_analysis.get("breakdown", {})

    homoglyph_section = ""
    if breakdown.get("has_homoglyphs"):
        h_rows = [f"  * {h['char']} ({h['unicode_hex']}, script: {h['script']}) -> Latin {h['replacement']} ({h['latin_hex']})" for h in breakdown.get("detected_homoglyphs", [])]
        homoglyph_section = f"""
EXHIBIT B: FORENSIC DEOBFUSCATION & IDN HOMOGLYPH EVIDENCE
- Detected Internationalized Domain Name (IDN) / Cyrillic Visual Spoofing:
{chr(10).join(h_rows)}
- Punycode Resolution: {breakdown.get('punycode', 'N/A')}
"""

    phash_section = ""
    if logo_forensics.get("discovered_hash_hex") != "OFFICIAL_ASSET":
        phash_section = f"""
EXHIBIT C: PERCEPTUAL HASH (pHash) VISUAL COPYRIGHT COMPARISON
- Official Trademark Monogram pHash : {logo_forensics.get('official_hash_hex')}
- Infringing Discovered Asset pHash: {logo_forensics.get('discovered_hash_hex')}
- Bitwise Hamming Distance (d_H)     : {logo_forensics.get('hamming_distance')} bits (Statutory threshold <= 10 bits)
- Perceptual Bit Match Ratio        : {logo_forensics.get('bit_match_ratio', 0) * 100:.1f}%
- Forensic Visual Verdict           : {logo_forensics.get('verdict')}
"""

    notice = f"""LEGAL NOTICE & STATUTORY CEASE AND DESIST DEMAND
================================================================================
TO: Abuse Operations, Trust & Safety, and Legal Compliance Department
PLATFORM: {platform}
DATE OF NOTICE: 2026-10-13
NOTICE IDENTIFIER: DRP-REVOLUT-{entity.get('id', 'REF')}-SOC

RE: EXPEDITED NOTICE OF TRADEMARK INFRINGEMENT, DECEPTIVE IMPERSONATION,
    AND FRAUDULENT BRAND TYPOSQUATTING
    
STATUTORY CITATIONS:
- 17 U.S.C. § 512(c)(3) (Digital Millennium Copyright Act - DMCA Notification)
- Lanham Act 15 U.S.C. § 1125(a) & 15 U.S.C. § 1125(d) (Anti-Cybersquatting Consumer Protection Act)
- Regulation (EU) 2022/2065 (Digital Services Act - DSA Notice and Action)
- Directive 2000/31/EC (Electronic Commerce Directive Article 14)

1. IDENTIFICATION OF AUTHORIZED TRADEMARK PROPRIETOR
This communication is submitted by the Global Cyber Threat Intelligence & Brand Protection
Operations Center on behalf of {brand_name} (Corporate Domain: https://{domain}).
{brand_name} is the registered trademark holder and exclusive proprietor of all logos,
mobile applications, corporate names, and digital brand assets associated with 'Revolut'.

2. IDENTIFICATION OF INFRINGING TARGET ASSET
- Infringing Entity Name: {entity_name}
- Identifier / Handle   : {handle}
- Discovered Location   : {url}
- Threat Classification : {severity} Risk (Composite Forensic Threat Score: {score}/100)
- Distribution Channel  : {platform}

3. SUMMARY OF INFRINGING AND ILLEGAL CONDUCT
The referenced account/package unauthorizedly duplicates registered trademarks and visual
assets belonging to {brand_name}. The asset is actively leveraged to deceive consumers,
harvest account credentials, or divert retail banking users through deceptive lures:
{chr(10).join([f'- [!] {r}' for r in reasons])}
{homoglyph_section}{phash_section}
4. STATUTORY DECLARATION & DEMAND FOR IMMEDIATE REMOVAL
In accordance with 17 U.S.C. § 512(c) and EU Regulation 2022/2065 Article 16:
1. The undersigned has a good faith belief that use of the material in the manner
   complained of is not authorized by {brand_name}, its agents, or the law.
2. The information in this notification is accurate, and under penalty of perjury,
   the undersigned confirms authorization to act on behalf of the trademark owner.
3. We hereby demand the IMMEDIATE EXPULSION, SUSPENSION, AND DE-INDEXATION of the
   aforementioned infringing handle/package to prevent financial harm to consumers.

SUBMITTED BY:
Brand Protection & Incident Response SOC
Global Security Directorate | {brand_name}
Corporate Headquarters: 7 Westferry Circus, London, E14 4HD, UK
Official Verification Channel: security@{domain}
================================================================================
"""
    return notice.strip()


def inspect_threat_surface(
    target_input: str,
    brand_name: str = "Revolut",
    brand_domain: str = "revolut.com"
) -> Dict[str, Any]:
    """
    Live Infrastructure & DNS/WHOIS threat surface analyzer:
    - Resolves IP Address and reverse DNS / PTR record.
    - Flags high-risk indicators: Suspicious TLD (.xyz, .top, .tk, etc.),
      Private/Bogon IP leak, or newly registered domain / typosquat heuristic.
    - Probes active MX records to assess credential phishing and mail spoofing posture.
    """
    import socket
    import urllib.parse
    import subprocess

    target_input = (target_input or "").strip()
    if not target_input:
        return {"error": "Empty target domain or URL provided."}

    # Extract clean domain
    parsed = urllib.parse.urlparse(target_input if "://" in target_input else f"http://{target_input}")
    clean_domain = (parsed.hostname or target_input).strip().lower()
    clean_domain = clean_domain.split(":")[0].strip()

    flags: List[str] = []
    indicators: List[Dict[str, str]] = []
    resolved_ip: Optional[str] = None
    ptr_record: Optional[str] = None
    ip_class = "PUBLIC_INTERNET"
    is_private_ip = False

    # 1. IP & Reverse DNS (PTR) Resolution
    try:
        resolved_ip = socket.gethostbyname(clean_domain)
        # Check for Private / Bogon IP Leak
        octets = resolved_ip.split(".")
        if len(octets) == 4 and all(o.isdigit() for o in octets):
            o1, o2 = int(octets[0]), int(octets[1])
            if o1 == 127:
                is_private_ip = True
                ip_class = "LOOPBACK_INTERNAL"
            elif o1 == 10:
                is_private_ip = True
                ip_class = "RFC1918_PRIVATE_CLASS_A"
            elif o1 == 172 and 16 <= o2 <= 31:
                is_private_ip = True
                ip_class = "RFC1918_PRIVATE_CLASS_B"
            elif o1 == 192 and o2 == 168:
                is_private_ip = True
                ip_class = "RFC1918_PRIVATE_CLASS_C"
            elif o1 == 169 and o2 == 254:
                is_private_ip = True
                ip_class = "LINK_LOCAL_APIPA"

        if is_private_ip:
            flags.append(f"Private/Bogon IP Leak: Infrastructure points to non-routable internal address '{resolved_ip}' ({ip_class})")
            indicators.append({"type": "CRITICAL_IP_ANOMALY", "detail": f"Private IP Leak: {resolved_ip} ({ip_class})"})

        # Reverse DNS / PTR
        try:
            ptr_data = socket.gethostbyaddr(resolved_ip)
            ptr_record = ptr_data[0] if ptr_data else "None"
        except Exception:
            ptr_record = "NO_PTR_RECORD_FOUND"

    except Exception as e:
        resolved_ip = "UNRESOLVED_NXDOMAIN"
        ptr_record = "N/A"
        flags.append(f"DNS Resolution Notice: Host could not be resolved ({str(e)})")

    # 2. Suspicious Top-Level Domain (TLD) Analysis
    suspicious_tlds = {
        '.xyz', '.top', '.tk', '.cc', '.ru', '.cn', '.pw', '.work',
        '.click', '.buzz', '.club', '.rest', '.sbs', '.monster',
        '.cfd', '.online', '.site', '.live', '.space', '.bid', '.loan'
    }
    extracted_tld = "." + clean_domain.split(".")[-1] if "." in clean_domain else ""
    if extracted_tld in suspicious_tlds:
        flags.append(f"High-Abuse Top-Level Domain: '{extracted_tld}' exhibits elevated statistical prevalence in phishing infrastructure.")
        indicators.append({"type": "SUSPICIOUS_TLD", "detail": f"High-Abuse TLD '{extracted_tld}'"})

    # 3. Typosquatting & Hyphenated Brand Lure Heuristic
    lure_tokens = [
        'verify', 'auth', 'login', 'kyc', 'support', 'portal', 'claim',
        'security', 'unfreeze', 'recover', 'update', 'app', 'secure',
        'banking', 'wallet', 'online', 'passcode', 'card'
    ]
    brand_norm = brand_name.lower().replace(" ltd", "").replace(" bank", "").strip()
    is_brand_present = brand_norm in clean_domain and clean_domain != brand_domain.lower()
    matched_lures = [l for l in lure_tokens if l in clean_domain]

    if is_brand_present and matched_lures:
        lures_str = ", ".join(f"'-{l}'" for l in matched_lures)
        flags.append(f"Phishing Typosquatting Vector: Combines target brand '{brand_norm}' with credential lures ({lures_str}).")
        indicators.append({"type": "TYPOSQUAT_LURE", "detail": f"Target brand combined with {lures_str}"})

    hyphen_count = clean_domain.count("-")
    if hyphen_count >= 2:
        flags.append(f"Anomalous Hyphenation Density: {hyphen_count} hyphens detected (Common pattern in phishing kit generation).")
        indicators.append({"type": "HIGH_HYPHEN_DENSITY", "detail": f"{hyphen_count} hyphens in domain string"})

    # 4. Active MX Records & Mail Posture
    mx_active = False
    mx_records: List[str] = []
    try:
        proc = subprocess.run(['nslookup', '-type=mx', clean_domain], capture_output=True, text=True, timeout=3)
        lines = [line.strip() for line in proc.stdout.split('\n') if 'mail exchanger' in line.lower() or 'mx' in line.lower()]
        if lines:
            mx_active = True
            mx_records = lines
    except Exception:
        pass

    # Socket fallback if nslookup produced no lines
    if not mx_records:
        for sub in ['mail', 'smtp', 'mx', 'mx1']:
            host = f"{sub}.{clean_domain}"
            try:
                ip = socket.gethostbyname(host)
                mx_active = True
                mx_records.append(f"{host} -> {ip}")
            except Exception:
                pass

    if mx_active:
        if is_brand_present or extracted_tld in suspicious_tlds:
            flags.append("Active MX Mail Server Configured: Infrastructure is provisioned with mail exchange records, enabling outbound phishing and BEC mail spoofing.")
            indicators.append({"type": "ACTIVE_MAIL_SPOOFING_RISK", "detail": f"Active Mail Exchangers ({len(mx_records)} detected)"})
        else:
            indicators.append({"type": "MX_RECORDS_ACTIVE", "detail": f"{len(mx_records)} MX records detected"})
    else:
        indicators.append({"type": "NO_MX_RECORDS", "detail": "No active mail exchange records (Web landing redirect profile)"})

    # 5. Composite Infrastructure Threat Score
    threat_score = 10.0
    if extracted_tld in suspicious_tlds:
        threat_score += 30.0
    if is_brand_present and matched_lures:
        threat_score += 45.0
    if hyphen_count >= 2:
        threat_score += 15.0
    if is_private_ip:
        threat_score += 40.0
    if mx_active and (is_brand_present or extracted_tld in suspicious_tlds):
        threat_score += 20.0
    if resolved_ip == "UNRESOLVED_NXDOMAIN":
        threat_score = max(threat_score - 15.0, 25.0)

    threat_score = round(min(100.0, max(0.0, threat_score)), 1)
    if threat_score >= 75.0:
        severity = "Critical"
    elif threat_score >= 50.0:
        severity = "High"
    elif threat_score >= 25.0:
        severity = "Medium"
    else:
        severity = "Low"

    return {
        "target_input": target_input,
        "clean_domain": clean_domain,
        "resolved_ip": resolved_ip,
        "ip_classification": ip_class,
        "ptr_record": ptr_record,
        "tld": extracted_tld,
        "has_mx": mx_active,
        "mx_records": mx_records,
        "threat_score": threat_score,
        "severity": severity,
        "flags": flags,
        "indicators": indicators,
        "is_brand_typosquat": is_brand_present and bool(matched_lures)
    }


def generate_stix2_bundle(
    entity: Dict[str, Any],
    brand_config: Dict[str, Any],
    risk_analysis: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Generates a fully valid OASIS STIX 2.1 JSON Cyber Threat Intelligence bundle
    containing Indicator, Identity, Attack-Pattern, and Relationship SDOs.
    """
    import uuid
    import datetime

    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    brand_name = brand_config.get("brand_name", "Revolut Ltd")
    domain = brand_config.get("domain", "revolut.com")
    entity_name = entity.get("name", "Unknown Threat")
    handle = entity.get("handle") or "N/A"
    url = entity.get("url")
    severity = risk_analysis.get("severity", "High").lower()
    score = int(risk_analysis.get("composite_score", 85.0))

    # STIX SDO UUIDs
    bundle_id = f"bundle--{uuid.uuid4()}"
    identity_id = f"identity--{uuid.uuid4()}"
    indicator_id = f"indicator--{uuid.uuid4()}"
    attack_pattern_id = f"attack-pattern--{uuid.uuid4()}"
    rel_targets_id = f"relationship--{uuid.uuid4()}"
    rel_indicates_id = f"relationship--{uuid.uuid4()}"

    # Determine STIX 2.1 pattern based on asset type
    if url and "://" in url:
        stix_pattern = f"[url:value = '{url}']"
    elif handle.startswith("@"):
        stix_pattern = f"[user-account:account_login = '{handle}']"
    elif "." in handle:
        stix_pattern = f"[domain-name:value = '{handle}']"
    else:
        stix_pattern = f"[software:name = '{entity_name}']"

    # 1. Identity SDO (Targeted Enterprise)
    identity_sdo = {
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": now,
        "modified": now,
        "name": brand_name,
        "description": f"Targeted enterprise financial institution ({brand_name}).",
        "identity_class": "organization",
        "sectors": ["financial-services", "banking"],
        "contact_information": f"security@{domain}"
    }

    # 2. Indicator SDO (Malicious Phishing / Impersonator Artifact)
    indicator_sdo = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": indicator_id,
        "created": now,
        "modified": now,
        "name": f"Brand Impersonation Vector: {entity_name}",
        "description": f"Fraudulent impersonation asset ({handle}) targeting {brand_name}. Forensic threat score: {score}/100 ({severity.upper()}). Triggers: {'; '.join(risk_analysis.get('reasons', []))}",
        "indicator_types": ["malicious-activity", "phishing"],
        "pattern": stix_pattern,
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": now,
        "confidence": score
    }

    # 3. Attack Pattern SDO (MITRE ATT&CK T1656 / T1566)
    attack_pattern_sdo = {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": attack_pattern_id,
        "created": now,
        "modified": now,
        "name": "Impersonation & Phishing Infrastructure",
        "description": "Adversary mimics authorized brand persona, deobfuscating Cyrillic IDN homoglyphs and cloning visual marks.",
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": "T1656",
                "url": "https://attack.mitre.org/techniques/T1656/"
            },
            {
                "source_name": "mitre-attack",
                "external_id": "T1566",
                "url": "https://attack.mitre.org/techniques/T1566/"
            }
        ]
    }

    # 4. Relationship: Indicator -> Targets -> Identity
    rel_targets = {
        "type": "relationship",
        "spec_version": "2.1",
        "id": rel_targets_id,
        "created": now,
        "modified": now,
        "relationship_type": "targets",
        "source_ref": indicator_id,
        "target_ref": identity_id
    }

    # 5. Relationship: Indicator -> Indicates -> Attack Pattern
    rel_indicates = {
        "type": "relationship",
        "spec_version": "2.1",
        "id": rel_indicates_id,
        "created": now,
        "modified": now,
        "relationship_type": "indicates",
        "source_ref": indicator_id,
        "target_ref": attack_pattern_id
    }

    stix_bundle = {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": "2.1",
        "objects": [
            identity_sdo,
            indicator_sdo,
            attack_pattern_sdo,
            rel_targets,
            rel_indicates
        ]
    }

    return stix_bundle


def entity_matches_search(
    entity: Dict[str, Any],
    brand_config: Dict[str, Any],
    query: str
) -> bool:
    """
    Evaluates whether an entity or its comparison baseline matches an analyst search query.
    Searches across:
    - Candidate name, discovered identifier (handle / ID), target URL, application package identifiers
    - Candidate metadata: bio, developer_email, category, platform
    - Official comparison baseline: brand name, official domain, authorized handles, application package identifiers, aliases
    """
    if not query:
        return True
    q = query.strip().lower()
    if not q:
        return True

    # 1. Discovered candidate fields
    candidate_strings = [
        str(entity.get("name") or ""),
        str(entity.get("handle") or ""),
        str(entity.get("id") or ""),
        str(entity.get("package_name") or ""),
        str(entity.get("url") or ""),
        str(entity.get("bio") or ""),
        str(entity.get("developer_email") or ""),
        str(entity.get("category") or ""),
        str(entity.get("platform") or "")
    ]
    if any(q in s.lower() for s in candidate_strings):
        return True

    # 2. Official baseline comparison fields (entity-specific official_brand or scoped brand_config)
    off_brand = entity.get("official_brand") if isinstance(entity.get("official_brand"), dict) else (brand_config or {})
    baseline_strings = [
        str(entity.get("brand_name") or off_brand.get("brand_name") or ""),
        str(entity.get("domain") or off_brand.get("domain") or "")
    ]
    for alias in (off_brand.get("brand_aliases") or entity.get("brand_aliases") or []):
        baseline_strings.append(str(alias))
    for handle in (off_brand.get("official_handles") or entity.get("official_handles") or []):
        baseline_strings.append(str(handle))
    for pkg in (off_brand.get("official_packages") or entity.get("official_packages") or []):
        baseline_strings.append(str(pkg))

    if any(q in s.lower() for s in baseline_strings):
        return True

    return False

