import sys
import os
import requests
import base64
import time
from dotenv import load_dotenv

# Add project root to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database.mongo_handler import collection

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
headers = {"x-apikey": VT_API_KEY}
MAX_IOCS = 50

def get_vt_url(ioc_type, indicator):
    ioc_type_lower = ioc_type.lower() if ioc_type else ""
    if ioc_type_lower in ["domain", "hostname"]:
        return f"https://www.virustotal.com/api/v3/domains/{indicator}"
    elif ioc_type_lower == "ipv4":
        return f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
    elif ioc_type_lower == "url":
        encoded_url = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
        return f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
    elif ioc_type_lower in ["filehash-md5", "filehash-sha256", "md5", "sha256"]:
        return f"https://www.virustotal.com/api/v3/files/{indicator}"
    return None

def calculate_vt_score(stats, prelim_score):
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    
    if malicious >= 10: return 100
    if malicious >= 5: return 90
    if malicious >= 2: return 75
    if malicious == 1: return 50
    if malicious == 0 and suspicious >= 1: return 40
    
    # ZERO-DAY HANDLING:
    # If VT doesn't flag it as malicious, it doesn't mean it's safe. It could be brand new.
    # If many engines explicitly say it's harmless, then we lower the score.
    if harmless >= 5: 
        return 10
        
    # If VT has no strong opinion (0 malicious, 0 suspicious, low harmless),
    # we shouldn't artificially downgrade the risk. We defer to our local Preliminary Score.
    return prelim_score

def get_severity_label(score):
    if score >= 90: return "Critical"
    if score >= 70: return "High"
    if score >= 40: return "Medium"
    return "Low"

def main():
    documents = collection.find({"vt_enriched": {"$ne": True}}).sort("preliminary_score", -1).limit(MAX_IOCS)
    enriched_count = skipped_count = 0
    print("\n========== VIRUSTOTAL ENRICHMENT ==========\n")

    for doc in documents:
        indicator = doc.get("indicator")
        ioc_type = doc.get("ioc_type")
        if not indicator or not ioc_type:
            skipped_count += 1
            continue

        try:
            vt_url = get_vt_url(ioc_type, indicator)
            if not vt_url:
                print(f"Unsupported IOC type: {ioc_type}")
                skipped_count += 1
                continue

            response = requests.get(vt_url, headers=headers, timeout=15)

            if response.status_code == 200:
                attributes = response.json()["data"]["attributes"]
                stats = attributes.get("last_analysis_stats", {})
                prelim_score = doc.get("preliminary_score", 50)
                vt_score = calculate_vt_score(stats, prelim_score)

                final_score = int(round((prelim_score * 0.4) + (vt_score * 0.6)))
                final_severity = get_severity_label(final_score)

                collection.update_one(
                    {"_id": doc["_id"]},
                    {"$set": {
                        "vt_malicious": stats.get("malicious", 0),
                        "vt_suspicious": stats.get("suspicious", 0),
                        "vt_harmless": stats.get("harmless", 0),
                        "vt_undetected": stats.get("undetected", 0),
                        "vt_reputation": attributes.get("reputation", 0),
                        "vt_tags": attributes.get("tags", []),
                        "vt_enriched": True,
                        "risk_score": final_score,
                        "risk_severity": final_severity
                    }}
                )
                enriched_count += 1
                print(f"Enriched [{ioc_type}] : {indicator} (Risk: {final_score} - {final_severity})")

            elif response.status_code == 404:
                prelim_score = doc.get("preliminary_score", 50)
                prelim_severity = doc.get("preliminary_severity", "Medium")
                collection.update_one(
                    {"_id": doc["_id"]},
                    {"$set": {
                        "vt_enriched": True,
                        "risk_score": prelim_score,
                        "risk_severity": prelim_severity,
                        "vt_note": "Not found in VirusTotal database"
                    }}
                )
                enriched_count += 1
                print(f"VT Not Found (404) - Fallback score used for: {indicator} (Risk: {prelim_score} - {prelim_severity})")

            elif response.status_code == 429:
                print("\n[WARNING] VirusTotal API Rate Limit (429) hit. Gracefully exiting enrichment.")
                break
            else:
                print(f"VT lookup failed ({response.status_code}) : {indicator}")
                skipped_count += 1

            time.sleep(2)
        except Exception as e:
            print(f"Error processing {indicator}: {e}")
            skipped_count += 1

    print("\n========== SUMMARY ==========")
    print(f"Enriched IOCS : {enriched_count}")
    print(f"Skipped IOCS  : {skipped_count}")

if __name__ == "__main__":
    main()