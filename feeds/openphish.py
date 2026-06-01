import sys
import os
import requests

# Add project root to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.mongo_handler import collection

# OpenPhish Feed
url = "https://openphish.com/feed.txt"

# Limit entries
MAX_ENTRIES = 300

print("\nFetching OpenPhish feed...")

try:

    response = requests.get(
        url,
        timeout=20,
        headers={
            "User-Agent": "TIP-Project"
        }
    )

except requests.exceptions.RequestException as e:

    print(f"Request failed: {e}")
    exit()

# Status check
if response.status_code != 200:

    print(f"Failed to fetch feed: {response.status_code}")
    exit()

print("Feed downloaded successfully.")

# Split URLs line-by-line
urls = response.text.splitlines()

print(f"Total phishing URLs found: {len(urls)}")

inserted_count = 0
duplicate_count = 0

# Process URLs
for indicator in urls:

    indicator = indicator.strip()

    if not indicator:
        continue

    # MongoDB document
    document = {

        "indicator": indicator,

        "ioc_type": "url",

        "source": "OpenPhish",

        "threat_type": "phishing",

        "confidence": "high",

        "status": "active"
    }

    # Deduplication
    existing = collection.find_one({
        "indicator": indicator
    })

    if not existing:

        collection.insert_one(document)

        inserted_count += 1

        print(f"Inserted phishing URL: {indicator}")

    else:

        duplicate_count += 1

    # Limit processing
    if inserted_count >= MAX_ENTRIES:
        break

# Summary
print("\n========== OPENPHISH SUMMARY ==========")

print(f"Inserted : {inserted_count}")

print(f"Duplicates skipped : {duplicate_count}")