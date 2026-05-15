import requests
import os

from dotenv import load_dotenv
from database.mongo_connection import collection

load_dotenv()

API_KEY = os.getenv("VT_API_KEY")

headers = {
    "x-apikey": API_KEY
}

# Sample malicious/suspicious domains
sample_indicators = [
    "malware-test.com",
    "phishing-test.com",
    "example.com"
]

for domain in sample_indicators:

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"

    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        print(f"Failed for {domain}: {response.status_code}")
        continue

    data = response.json()

    attributes = data.get("data", {}).get("attributes", {})

    stats = attributes.get("last_analysis_stats", {})

    malicious_count = stats.get("malicious", 0)

    document = {
        "indicator": domain,
        "ioc_type": "domain",
        "source": "VirusTotal",
        "threat_type": "malicious_domain",
        "confidence": "medium",
        "status": "active",
        "malicious_votes": malicious_count
    }

    existing = collection.find_one({
        "indicator": domain
    })

    if not existing:
        collection.insert_one(document)
        print("Inserted:", domain)

print("VirusTotal ingestion completed!")