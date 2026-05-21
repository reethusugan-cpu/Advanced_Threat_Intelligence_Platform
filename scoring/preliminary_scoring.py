import sys
import os
import re
from datetime import datetime

# Add project root to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database.mongo_handler import collection
from scoring.mitre.technique_mapper import mapper

SOURCE_SCORES = {
    "OpenPhish": 85,
    "AlienVault": 65
}

IOC_TYPE_SCORES = {
    "url": 10, "file": 10, "md5": 10, "sha256": 10, "FileHash-MD5": 10, "FileHash-SHA256": 10,
    "domain": 5, "hostname": 5,
    "IPv4": 0, "IP": 0
}

THREAT_KEYWORDS = ["ransomware", "stealer", "c2", "command and control", "backdoor", "apt", "phishing", "beacon", "trojan"]

CONFIDENCE_SCORES = {"high": 5, "medium": 0, "low": -15}

def get_age_modifier(date_str):
    if not date_str: return 0
    try:
        date_cleaned = re.sub(r'\.\d+', '', str(date_str).strip()).replace('Z', '')
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
            try:
                parsed_date = datetime.strptime(date_cleaned, fmt)
                hours = max(0, (datetime.utcnow() - parsed_date).total_seconds() / 3600.0)
                if hours < 24: return 10
                if hours < 24 * 7: return 0
                if hours < 24 * 30: return -15
                return -30
            except ValueError:
                pass
    except Exception:
        pass
    return 0

def calculate_preliminary_score(doc):
    score = 0
    
    # 1. Base Source Score
    source = doc.get("source", "")
    if source == "URLHaus":
        score += 90 if doc.get("status", "") in ["active", "online"] else 50
    elif "AlienVault" in source:
        score += 65
    else:
        score += SOURCE_SCORES.get(source, 50)

    # 2. IOC Type Modifiers
    score += IOC_TYPE_SCORES.get(doc.get("ioc_type", ""), 0)

    # 3. Threat Keywords Modifiers
    if doc.get("malware_family", "unknown") != "unknown":
        score += 15
        
    threat_text = f"{doc.get('threat_type', '')} {' '.join(doc.get('tags', []))}".lower()
    if any(kw in threat_text for kw in THREAT_KEYWORDS):
        score += 10

    # 4. Confidence Modifier
    score += CONFIDENCE_SCORES.get(doc.get("confidence", "medium"), 0)

    # 5. Age Decay (Recency)
    score += get_age_modifier(doc.get("first_seen") or doc.get("created"))

    return max(1, min(100, score))

def get_severity_label(score):
    if score >= 90: return "Critical"
    if score >= 70: return "High"
    if score >= 40: return "Medium"
    return "Low"

def map_mitre_techniques(doc):
    seen = {}
    
    malware_family = doc.get("malware_family", "unknown")
    if malware_family != "unknown":
        for t in mapper.map_malware_to_techniques(malware_family):
            seen[t["id"]] = t
            
    text_to_scan = f"{doc.get('threat_type', '')} {' '.join(doc.get('tags', []))}"
    for t in mapper.map_text_to_techniques(text_to_scan):
        seen[t["id"]] = t
        
    return list(seen.values())

def run_preliminary_scoring():
    pending_docs = list(collection.find({"preliminary_score": {"$exists": False}}))
    if not pending_docs:
        print("No pending indicators to score.")
        return 0

    print(f"\nProcessing {len(pending_docs)} pending indicators...")
    for doc in pending_docs:
        prelim_score = calculate_preliminary_score(doc)
        collection.update_one(
            {"_id": doc["_id"]},
            {"$set": {
                "preliminary_score": prelim_score,
                "preliminary_severity": get_severity_label(prelim_score),
                "mitre_techniques": map_mitre_techniques(doc),
                "vt_enriched": doc.get("vt_enriched", False)
            }}
        )

    print(f"Successfully processed and updated {len(pending_docs)} indicators.")
    return len(pending_docs)

if __name__ == "__main__":
    run_preliminary_scoring()
