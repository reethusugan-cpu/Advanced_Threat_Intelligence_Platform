import sys
import os

# Add project root to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
from dotenv import load_dotenv
from database.mongo_handler import collection

# Load environment variables
load_dotenv()

# Get API Key
API_KEY = os.getenv("OTX_API_KEY")

# Headers
headers = {
    "X-OTX-API-KEY": API_KEY
}

# OTX Endpoint
base_url = "https://otx.alienvault.com/api/v1/pulses/subscribed"

# Pagination Settings
page = 1
MAX_PAGES = 5

# Counters
inserted_count = 0
duplicate_count = 0

# Fetch Multiple Pages
while page <= MAX_PAGES:

    print(f"\n========== Fetching Page {page} ==========")

    try:

        # API Request
        response = requests.get(
            base_url,
            headers=headers,
            params={"page": page},
            timeout=10
        )

    except requests.exceptions.RequestException as e:

        print(f"Request failed: {e}")
        break

    # Check Response
    if response.status_code != 200:

        print(f"Failed to fetch data. Status Code: {response.status_code}")
        break

    # Convert Response to JSON
    data = response.json()

    # Get Pulse Results
    results = data.get("results", [])

    # Stop if no more pages
    if not results:

        print("No more pulses found.")
        break

    # Loop Through Pulses
    for pulse in results:

        pulse_name = pulse.get("name")
        pulse_id = pulse.get("id")
        author = pulse.get("author_name")
        created = pulse.get("created")

        indicators = pulse.get("indicators", [])

        print(f"\nPulse: {pulse_name}")
        print(f"Indicators Found: {len(indicators)}")

        # Loop Through Indicators
        for item in indicators:

            indicator = item.get("indicator")
            ioc_type = item.get("type")

            # Skip empty indicators
            if not indicator:
                continue

            # MongoDB Document
            document = {

                "indicator": indicator,

                "ioc_type": ioc_type,

                "source": "AlienVault OTX",

                "threat_type": pulse_name,

                "pulse_id": pulse_id,

                "author": author,

                "created": created,

                "confidence": "medium",

                "status": "active"
            }

            # Deduplication Check
            existing = collection.find_one({
                "indicator": indicator
            })

            # Insert if not exists
            if not existing:

                collection.insert_one(document)

                inserted_count += 1

                print(f"Inserted [{ioc_type}] : {indicator}")

            else:

                duplicate_count += 1

                print(f"Duplicate skipped : {indicator}")

    # Next Page
    page += 1

# Final Summary
print("\n========== INGESTION SUMMARY ==========")

print(f"Pages Processed        : {page - 1}")

print(f"New Indicators Inserted: {inserted_count}")

print(f"Duplicates Skipped     : {duplicate_count}")
