import requests
from dotenv import load_dotenv
import os

from database.mongo_handler import collection

# Load environment variables
load_dotenv()

# Get API Key
API_KEY = os.getenv("OTX_API_KEY")

# Headers
headers = {
    "X-OTX-API-KEY": API_KEY
}

# OTX Pulse Endpoint
url = "https://otx.alienvault.com/api/v1/pulses/subscribed"

# Request
response = requests.get(url, headers=headers)

# Success Check
if response.status_code == 200:

    data = response.json()

    count = 0

    # Loop through pulses
    for pulse in data.get("results", []):

        pulse_name = pulse.get("name")

        indicators = pulse.get("indicators", [])

        # Loop through indicators
        for item in indicators:

            indicator = item.get("indicator")

            ioc_type = item.get("type")

            if indicator:

                document = {
                    "indicator": indicator,
                    "ioc_type": ioc_type,
                    "source": "AlienVault OTX",
                    "threat_type": pulse_name,
                    "confidence": "medium",
                    "status": "active"
                }

                # Deduplication
                existing = collection.find_one({
                    "indicator": indicator
                })

                if not existing:

                    collection.insert_one(document)

                    print(f"Inserted [{ioc_type}]: {indicator}")
                else:
                    print(f"Duplicate skipped: {indicator}")

                count += 1

                # Limit for testing
                if count == 20:
                    break

        if count == 20:
            break

else:
    print("Failed to fetch OTX feed")
    print(response.status_code)