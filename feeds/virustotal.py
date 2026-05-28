import requests
import time
import base64
import html
import re
import os
from urllib.parse import urlparse
from datetime import datetime
from database.mongo_handler import collection
from dotenv import load_dotenv
# =========================================================
# CONFIGURATION
# =========================================================

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")

VT_HEADERS = {
    "x-apikey": VT_API_KEY
}
# =========================================================
# IOC DEDUPLICATION CACHE
# =========================================================

processed_iocs = set()

# =========================================================
# IOC NORMALIZATION
# =========================================================

def normalize_url(url):

    url = html.unescape(url.strip())

    # remove fragments
    url = url.split("#")[0]

    # add protocol
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    if parsed.query:
        clean_url += "?" + parsed.query

    return clean_url.lower()

# =========================================================
# HASH DETECTION
# =========================================================

def detect_hash_type(hash_value):

    if re.fullmatch(r"[A-Fa-f0-9]{32}", hash_value):
        return "FileHash-MD5"

    elif re.fullmatch(r"[A-Fa-f0-9]{40}", hash_value):
        return "FileHash-SHA1"

    elif re.fullmatch(r"[A-Fa-f0-9]{64}", hash_value):
        return "FileHash-SHA256"

    return None

# =========================================================
# IOC TYPE DETECTION
# =========================================================

def detect_ioc_type(ioc):

    hash_type = detect_hash_type(ioc)

    if hash_type:
        return hash_type

    if ioc.startswith(("http://", "https://")):
        return "URL"

    if "/" in ioc:
        return "URL"

    if ":" in ioc:
        return "hostname"

    return "domain"

# =========================================================
# VT URL ENCODING
# =========================================================

def generate_url_id(url):

    encoded = base64.urlsafe_b64encode(
        url.encode()
    ).decode()

    return encoded.strip("=")

# =========================================================
# IOC CATEGORY DETECTION
# =========================================================

def classify_ioc(tags, malicious):

    tags = [t.lower() for t in tags]

    if "phishing" in tags:
        return "phishing"

    elif "trojan" in tags:
        return "trojan"

    elif "ransomware" in tags:
        return "ransomware"

    elif "botnet" in tags or "bot" in tags:
        return "botnet"

    elif "worm" in tags:
        return "worm"

    elif "exploit" in tags:
        return "exploit-kit"

    elif malicious >= 30:
        return "malware"

    return "suspicious"

# =========================================================
# RISK CLASSIFICATION
# =========================================================

def risk_level(score):

    if score <= 20:
        return "LOW"

    elif score <= 50:
        return "MEDIUM"

    elif score <= 80:
        return "HIGH"

    return "CRITICAL"

# =========================================================
# VT LOOKUP
# =========================================================

def query_virustotal(ioc, ioc_type):

    try:

        # -------------------------------------------------
        # FILE HASHES
        # -------------------------------------------------

        if ioc_type.startswith("FileHash"):

            endpoint = f"https://www.virustotal.com/api/v3/files/{ioc}"

        # -------------------------------------------------
        # URLS
        # -------------------------------------------------

        elif ioc_type == "URL":

            normalized_url = normalize_url(ioc)

            url_id = generate_url_id(normalized_url)

            endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        # -------------------------------------------------
        # DOMAINS / HOSTNAMES
        # -------------------------------------------------

        else:

            endpoint = f"https://www.virustotal.com/api/v3/domains/{ioc}"

        response = requests.get(
            endpoint,
            headers=VT_HEADERS
        )

        # =================================================
        # SUCCESS
        # =================================================

        if response.status_code == 200:

            data = response.json()

            attributes = data["data"]["attributes"]

            stats = attributes.get(
                "last_analysis_stats", {}
            )

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)

            reputation = attributes.get(
                "reputation", 0
            )

            tags = attributes.get("tags", [])

            first_seen = attributes.get(
                "first_submission_date"
            )

            # ------------------------------------------------
            # TOTAL ENGINES
            # ------------------------------------------------

            total_engines = (
                malicious +
                suspicious +
                harmless +
                undetected
            )

            # ------------------------------------------------
            # BETTER RISK FORMULA
            # ------------------------------------------------

            risk_score = min(
                (malicious * 10) +
                (suspicious * 5),
                100
            )

            category = classify_ioc(
                tags,
                malicious
            )

            return {
                "status": "success",
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "total_engines": total_engines,
                "reputation": reputation,
                "risk_score": risk_score,
                "risk_level": risk_level(risk_score),
                "tags": tags,
                "category": category,
                "first_seen": first_seen,
                "raw_data": data
            }

        # =================================================
        # UNKNOWN IOC
        # =================================================

        elif response.status_code == 404:

            return {
                "status": "unknown"
            }

        # =================================================
        # RATE LIMIT
        # =================================================

        elif response.status_code == 429:

            return {
                "status": "rate_limited"
            }

        # =================================================
        # AUTH FAILURE
        # =================================================

        elif response.status_code == 401:

            return {
                "status": "auth_failed"
            }

        else:

            return {
                "status": "failed",
                "message": f"HTTP {response.status_code}"
            }

    except Exception as e:

        return {
            "status": "error",
            "message": str(e)
        }

# =========================================================
# ENRICHMENT LOOP
# =========================================================

def enrich_iocs():

    print("\n========== VIRUSTOTAL ENRICHMENT ==========\n")

    enriched = 0
    unknown = 0
    skipped = 0
    failed = 0

    iocs = collection.find()

    for item in iocs:

        ioc = item.get("ioc") or item.get("indicator")

        if not ioc:
            skipped += 1
            continue

        # -------------------------------------------------
        # DEDUPLICATION
        # -------------------------------------------------

        if ioc in processed_iocs:
            print(f"[SKIPPED] Duplicate IOC: {ioc}")
            skipped += 1
            continue

        processed_iocs.add(ioc)

        ioc_type = (
    item.get("ioc_type")
    or detect_ioc_type(ioc)
)

        result = query_virustotal(
            ioc,
            ioc_type
        )

        # =================================================
        # SUCCESS
        # =================================================

        if result["status"] == "success":

            first_seen = result["first_seen"]

            if first_seen:
                first_seen = datetime.utcfromtimestamp(
                    first_seen
                ).strftime("%Y-%m-%d %H:%M:%S UTC")

            collection.update_one(
                {"_id": item["_id"]},
                {
                    "$set": {
                        "virustotal": {
                            "risk_score": result["risk_score"],
                            "risk_level": result["risk_level"],
                            "category": result["category"],
                            "malicious_engines": result["malicious"],
                            "suspicious_engines": result["suspicious"],
                            "total_engines": result["total_engines"],
                            "reputation": result["reputation"],
                            "tags": result["tags"],
                            "first_seen": first_seen,
                            "enriched_at": time.time()
                        }
                    }
                }
            )

            print(f"[ENRICHED] [{ioc_type}] {ioc}")

            print(
                f"  Detected By : "
                f"{result['malicious']}/"
                f"{result['total_engines']} "
                f"Antivirus Engines"
            )

            print(
                f"  Malicious Engines : "
                f"{result['malicious']}"
            )

            print(
                f"  Suspicious Engines : "
                f"{result['suspicious']}"
            )

            print(
                f"  Reputation : "
                f"{result['reputation']}"
            )

            print(
                f"  Risk Score : "
                f"{result['risk_score']}"
            )

            print(
                f"  Severity : "
                f"{result['risk_level']}"
            )

            print(
                f"  Category : "
                f"{result['category']}"
            )

            print(
                f"  Tags : "
                f"{result['tags']}"
            )

            print(
                f"  First Seen : "
                f"{first_seen}"
            )

            print("-----------------------------------")

            enriched += 1

        # =================================================
        # UNKNOWN IOC
        # =================================================

        elif result["status"] == "unknown":

            print(
                f"[UNKNOWN IOC] "
                f"{ioc}"
            )

            unknown += 1

        # =================================================
        # RATE LIMIT
        # =================================================

        elif result["status"] == "rate_limited":

            print(
                "\n[RATE LIMITED] "
                "Sleeping 60 seconds...\n"
            )

            time.sleep(60)

        # =================================================
        # AUTH FAILED
        # =================================================

        elif result["status"] == "auth_failed":

            print(
                "\n[ERROR] Invalid API key\n"
            )

            break

        # =================================================
        # FAILED
        # =================================================

        else:

            print(
                f"[FAILED] {ioc} "
                f"→ {result.get('message')}"
            )

            failed += 1

        # Free API rate limit safety
        time.sleep(2)

    # =====================================================
    # SUMMARY
    # =====================================================

    print("\n========== SUMMARY ==========\n")

    print(f"Enriched IOCS : {enriched}")
    print(f"Unknown IOCS  : {unknown}")
    print(f"Skipped IOCS  : {skipped}")
    print(f"Failed IOCS   : {failed}")

    print("\nVirusTotal enrichment completed!\n")

# =========================================================
# ENTRY POINT
# =========================================================

if __name__ == "__main__":
    enrich_iocs()