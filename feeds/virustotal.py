import sys, os, requests, base64, time
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database.mongo_handler import collection

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
headers = {"x-apikey": VT_API_KEY}

MAX_IOCS = 50

def get_vt_url(ioc_type, indicator):

    ioc_type = ioc_type.lower()

    if ioc_type in ["domain", "hostname"]:
        return f"https://www.virustotal.com/api/v3/domains/{indicator}"

    elif ioc_type in ["ipv4", "ip"]:
        return f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"

    elif ioc_type == "url":
        encoded = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
        return f"https://www.virustotal.com/api/v3/urls/{encoded}"

    elif ioc_type in ["md5", "sha256", "filehash-md5", "filehash-sha256"]:
        return f"https://www.virustotal.com/api/v3/files/{indicator}"

    return None


def calculate_vt_score(stats, prelim_score):

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)

    total = malicious + suspicious

    if malicious >= 20 or total >= 25:
        return 100

    elif malicious >= 10 or total >= 15:
        return 90

    elif malicious >= 5 or total >= 8:
        return 80

    elif suspicious >= 5:
        return 70

    elif suspicious >= 1:
        return 60

    elif malicious >= 1:
        return 50

    elif harmless >= 5:
        return 20

    return prelim_score


def get_severity_label(score):

    if score >= 90:
        return "Critical"

    elif score >= 70:
        return "High"

    elif score >= 40:
        return "Medium"

    return "Low"


def main():

    print("\n========== VIRUSTOTAL ENRICHMENT ==========\n")

    ip_docs = list(
        collection.find({
            "vt_enriched": {"$ne": True},
            "ioc_type": {"$in": ["IPv4", "IP"]}
        }).sort("preliminary_score", -1).limit(MAX_IOCS)
    )

    remaining = MAX_IOCS - len(ip_docs)

    non_ip_docs = []

    if remaining > 0:

        non_ip_docs = list(
            collection.find({
                "vt_enriched": {"$ne": True},
                "ioc_type": {"$nin": ["IPv4", "IP"]}
            }).sort("preliminary_score", -1).limit(remaining)
        )

    documents = ip_docs + non_ip_docs

    enriched = 0
    skipped = 0

    print(f"Targeting {len(documents)} indicators...")

    for doc in documents:

        indicator = doc.get("indicator")
        ioc_type = doc.get("ioc_type")

        if not indicator or not ioc_type:
            skipped += 1
            continue

        try:

            vt_url = get_vt_url(ioc_type, indicator)

            if not vt_url:
                skipped += 1
                continue

            response = requests.get(vt_url, headers=headers, timeout=15)

            if response.status_code == 200:

                attributes = response.json()["data"]["attributes"]
                stats = attributes.get("last_analysis_stats", {})

                prelim_score = doc.get("preliminary_score", 50)

                vt_score = calculate_vt_score(stats, prelim_score)

                weighted_score = int(round(
                    (prelim_score * 0.4) + (vt_score * 0.6)
                ))

                final_score = max(vt_score, weighted_score) if vt_score >= 80 else weighted_score

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

                enriched += 1

                print(f"Enriched [{ioc_type}] : {indicator} -> {final_score}")

            elif response.status_code == 404:

                collection.update_one(
                    {"_id": doc["_id"]},
                    {"$set": {
                        "vt_enriched": True,
                        "risk_score": doc.get("preliminary_score", 50),
                        "risk_severity": doc.get("preliminary_severity", "Medium"),
                        "vt_note": "Not found in VT"
                    }}
                )

                enriched += 1

            elif response.status_code == 429:

                print("\n[WARNING] VT Rate Limit Hit.")
                break

            else:
                skipped += 1

            time.sleep(2)

        except Exception as e:

            print(f"Error processing {indicator}: {e}")
            skipped += 1

    remaining_docs = list(
        collection.find({"vt_enriched": {"$ne": True}})
    )

    fallback = 0

    if remaining_docs:

        print(f"\nFallback scoring {len(remaining_docs)} IOCS...")

        for doc in remaining_docs:

            collection.update_one(
                {"_id": doc["_id"]},
                {"$set": {
                    "vt_enriched": True,
                    "risk_score": doc.get("preliminary_score", 50),
                    "risk_severity": doc.get("preliminary_severity", "Medium"),
                    "vt_note": "Preliminary fallback"
                }}
            )

            fallback += 1

    print("\n========== SUMMARY ==========")
    print(f"VT Enriched : {enriched}")
    print(f"Fallback : {fallback}")
    print(f"Skipped : {skipped}")


if __name__ == "__main__":
    main()