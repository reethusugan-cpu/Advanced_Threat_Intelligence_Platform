import sys
import os
import re
from datetime import datetime, timezone

# Add project root to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.mongo_handler import collection
from scoring.mitre.technique_mapper import mapper


# =========================================================
# SOURCE RELIABILITY SCORES
# =========================================================
SOURCE_SCORES = {
    "URLHaus": 60,
    "OpenPhish": 55,
    "AlienVault OTX": 50
}

# =========================================================
# IOC TYPE SCORES
# =========================================================
IOC_TYPE_SCORES = {
    "url": 10,
    "domain": 5,
    "hostname": 5,
    "md5": 15,
    "sha256": 15,
    "filehash-md5": 15,
    "filehash-sha256": 15,
    "ipv4": 0,
    "ip": 0
}

# =========================================================
# THREAT KEYWORDS
# =========================================================
THREAT_KEYWORDS = {
    "ransomware": 15,
    "stealer": 12,
    "infostealer": 12,
    "spyware": 10,
    "trojan": 10,
    "phishing": 10,
    "c2": 15,
    "command and control": 15,
    "backdoor": 12,
    "beacon": 10,
    "loader": 10,
    "dropper": 10,
    "worm": 10,
    "botnet": 12,
    "keylogger": 10,
    "miner": 8,
    "cryptominer": 8,
    "rat": 12,
    "exploit": 10,
    "malware": 8
}


# =========================================================
# CONFIDENCE SCORES
# =========================================================
CONFIDENCE_SCORES = {
    "high": 5,
    "medium": 0,
    "low": -10
}

# =========================================================
# AGE DECAY
# =========================================================
def get_age_modifier(date_str):

    if not date_str:
        return 0

    try:

        cleaned = re.sub(r'\.\d+', '', str(date_str)).replace("Z", "")

        for fmt in (
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d"
        ):

            try:

                parsed = datetime.strptime(cleaned, fmt)

                hours = (
                    datetime.now(timezone.utc).replace(tzinfo=None) - parsed
                ).total_seconds() / 3600

                # Dynamic age decay
                if hours < 24:
                    return 10

                elif hours < 72:
                    return 7

                elif hours < 168:
                    return 3

                elif hours < 720:
                    return -5

                return -10

            except:
                pass

    except:
        pass

    return 0


# =========================================================
# PRELIMINARY SCORING ENGINE
# =========================================================
def calculate_preliminary_score(doc):

    score = 0

    source = doc.get("source", "")
    ioc_type = doc.get("ioc_type", "").lower()

    # =====================================================
    # 1. SOURCE RELIABILITY
    # =====================================================
    score += SOURCE_SCORES.get(source, 40)

    # =====================================================
    # 2. IOC TYPE
    # =====================================================
    score += IOC_TYPE_SCORES.get(ioc_type, 0)

    # =====================================================
    # 3. MALWARE FAMILY BONUS
    # =====================================================
    malware_family = str(
        doc.get("malware_family", "")
    ).lower()

    if malware_family and malware_family != "unknown":
        score += 10

    # =====================================================
    # 4. THREAT KEYWORD ANALYSIS
    # =====================================================
    text = (
        f"{doc.get('threat_type', '')} "
        f"{' '.join(doc.get('tags', []))}"
    ).lower()

    for keyword, value in THREAT_KEYWORDS.items():

        if keyword in text:
            score += value

    # =====================================================
    # 5. TAG COUNT BONUS
    # =====================================================
    tags = doc.get("tags", [])

    if tags:

        unique_tags = list(set(tags))

        score += min(10, len(unique_tags) * 2)

    # =====================================================
    # 6. CONFIDENCE BONUS
    # =====================================================
    confidence = str(
        doc.get("confidence", "medium")
    ).lower()

    score += CONFIDENCE_SCORES.get(confidence, 0)

    # =====================================================
    # 7. AGE DECAY
    # =====================================================
    score += get_age_modifier(
        doc.get("first_seen") or doc.get("created")
    )

    # =====================================================
    # 8. STRUCTURAL JITTER
    # Prevent identical scores everywhere
    # =====================================================
    indicator = doc.get("indicator", "")

    if indicator:

        jitter = (len(indicator) % 5) - 2

        score += jitter

    return max(1, min(100, int(round(score))))


# =========================================================
# SEVERITY LABELS
# =========================================================
def get_severity_label(score):

    if score >= 90:
        return "Critical"

    if score >= 70:
        return "High"

    if score >= 40:
        return "Medium"

    return "Low"


# =========================================================
# MITRE TECHNIQUE MAPPING
# =========================================================
def map_mitre_techniques(doc):

    seen = {}

    malware_family = doc.get("malware_family", "unknown")

    # Malware family mapping
    if malware_family != "unknown":

        for t in mapper.map_malware_to_techniques(
            malware_family
        ):
            seen[t["id"]] = t

    # Threat keyword mapping
    text = (
        f"{doc.get('threat_type', '')} "
        f"{' '.join(doc.get('tags', []))}"
    )

    for t in mapper.map_text_to_techniques(text):

        seen[t["id"]] = t

    return list(seen.values())


# =========================================================
# MAIN PROCESSING
# =========================================================
def run_preliminary_scoring():

    pending_docs = list(
        collection.find({
            "preliminary_score": {
                "$exists": False
            }
        })
    )

    if not pending_docs:

        print("No pending indicators to score.")
        return

    print(f"\nProcessing {len(pending_docs)} indicators...\n")

    updated = 0

    for doc in pending_docs:

        prelim_score = calculate_preliminary_score(doc)

        collection.update_one(

            {"_id": doc["_id"]},

            {"$set": {

                "preliminary_score": prelim_score,

                "preliminary_severity":
                    get_severity_label(prelim_score),

                "mitre_techniques":
                    map_mitre_techniques(doc),

                "vt_enriched":
                    doc.get("vt_enriched", False)
            }}
        )

        updated += 1

    print(f"\nUpdated {updated} indicators successfully.")


# =========================================================
# ENTRY POINT
# =========================================================
if __name__ == "__main__":

    run_preliminary_scoring()
