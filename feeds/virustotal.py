import sys
import os
import requests
import base64
import time

from dotenv import load_dotenv

# Add project root to Python path
sys.path.insert(
    0,
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)

from database.mongo_connection import collection

# Load environment variables
load_dotenv()

# VirusTotal API Key
VT_API_KEY = os.getenv("VT_API_KEY")

# Validate API key
if not VT_API_KEY:

    print("VirusTotal API key not found in .env")
    exit()

# Request headers
headers = {
    "x-apikey": VT_API_KEY
}

# Max IOCS to enrich per run
MAX_IOCS = 50

# -----------------------------------
# FETCH IOCS FROM DATABASE
# -----------------------------------

# FUTURE VERSION:
# collection.find({"risk_score": {"$gte": 70}})

documents = collection.find().limit(MAX_IOCS)

# Counters
enriched_count = 0
skipped_count = 0
failed_count = 0

print("\n========== VIRUSTOTAL ENRICHMENT ==========\n")

# -----------------------------------
# PROCESS EACH IOC
# -----------------------------------

for doc in documents:

    indicator = doc.get("indicator")
    ioc_type = doc.get("ioc_type")

    # Skip invalid documents
    if not indicator or not ioc_type:

        skipped_count += 1
        continue

    try:

        # -----------------------------------
        # DOMAIN / HOSTNAME
        # -----------------------------------

        if ioc_type.lower() in [
            "domain",
            "hostname"
        ]:

            vt_url = (
                f"https://www.virustotal.com/"
                f"api/v3/domains/{indicator}"
            )

        # -----------------------------------
        # IPv4
        # -----------------------------------

        elif ioc_type.lower() in [
            "ipv4",
            "ip",
            "ip_address"
        ]:

            vt_url = (
                f"https://www.virustotal.com/"
                f"api/v3/ip_addresses/{indicator}"
            )

        # -----------------------------------
        # URL
        # -----------------------------------

        elif ioc_type.lower() == "url":

            encoded_url = base64.urlsafe_b64encode(
                indicator.encode()
            ).decode().strip("=")

            vt_url = (
                f"https://www.virustotal.com/"
                f"api/v3/urls/{encoded_url}"
            )

        # -----------------------------------
        # HASHES
        # -----------------------------------

        elif ioc_type.lower() in [
            "filehash-md5",
            "filehash-sha256",
            "md5",
            "sha256"
        ]:

            vt_url = (
                f"https://www.virustotal.com/"
                f"api/v3/files/{indicator}"
            )

        # -----------------------------------
        # UNSUPPORTED IOC
        # -----------------------------------

        else:

            print(
                f"[SKIPPED] Unsupported IOC type: "
                f"{ioc_type}"
            )

            skipped_count += 1
            continue

        # -----------------------------------
        # VT API REQUEST
        # -----------------------------------

        response = requests.get(
            vt_url,
            headers=headers,
            timeout=15
        )

        # -----------------------------------
        # SUCCESS
        # -----------------------------------

        if response.status_code == 200:

            data = response.json()

            attributes = data.get(
                "data",
                {}
            ).get(
                "attributes",
                {}
            )

            stats = attributes.get(
                "last_analysis_stats",
                {}
            )

            reputation = attributes.get(
                "reputation",
                0
            )

            tags = attributes.get(
                "tags",
                []
            )

            # -----------------------------------
            # RISK SCORE LOGIC
            # -----------------------------------

            malicious = stats.get(
                "malicious",
                0
            )

            suspicious = stats.get(
                "suspicious",
                0
            )

            risk_score = (
                malicious * 10
            ) + (
                suspicious * 5
            )

            # Cap score at 100
            if risk_score > 100:

                risk_score = 100

            # -----------------------------------
            # UPDATE MONGODB
            # -----------------------------------

            collection.update_one(

                {"_id": doc["_id"]},

                {
                    "$set": {

                        "vt_malicious": malicious,

                        "vt_suspicious": suspicious,

                        "vt_harmless": stats.get(
                            "harmless",
                            0
                        ),

                        "vt_undetected": stats.get(
                            "undetected",
                            0
                        ),

                        "vt_reputation": reputation,

                        "vt_tags": tags,

                        "risk_score": risk_score,

                        "vt_enriched": True,

                        "vt_last_updated": time.time()
                    }
                }
            )

            enriched_count += 1

            print(
                f"[ENRICHED] "
                f"[{ioc_type}] "
                f"{indicator} "
                f"→ Risk Score: {risk_score}"
            )

        # -----------------------------------
        # RATE LIMIT
        # -----------------------------------

        elif response.status_code == 429:

            print(
                "[ERROR] VirusTotal API rate limit reached."
            )

            print(
                "Sleeping for 60 seconds..."
            )

            time.sleep(60)

            failed_count += 1

        # -----------------------------------
        # OTHER FAILURES
        # -----------------------------------

        else:

            print(
                f"[FAILED] "
                f"({response.status_code}) : "
                f"{indicator}"
            )

            failed_count += 1

        # IMPORTANT:
        # Free API rate limiting
        time.sleep(2)

    except Exception as e:

        print(
            f"[ERROR] "
            f"{indicator} : {e}"
        )

        failed_count += 1

# -----------------------------------
# SUMMARY
# -----------------------------------

print("\n========== SUMMARY ==========\n")

print(f"Enriched IOCS : {enriched_count}")

print(f"Skipped IOCS  : {skipped_count}")

print(f"Failed IOCS   : {failed_count}")

print("\nVirusTotal enrichment completed!\n")