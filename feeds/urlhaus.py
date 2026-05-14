import sys
import os

# Add project root to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
import zipfile
import io
import json

from database.mongo_handler import collection

# URLHaus Feed URL
url = "https://urlhaus.abuse.ch/downloads/json/"

# Processing Limit
MAX_ENTRIES = 200

# Counters
inserted_count = 0
duplicate_count = 0
processed_count = 0

try:
	# Send Request
	response = requests.get(url, timeout=10)
except requests.exceptions.RequestException as e:
	print(f"Request failed: {e}")
	exit()

# Check Request Success
if response.status_code == 200:
	print("\nDownloading URLHaus feed...\n")

	# Read ZIP file from memory
	zip_file = zipfile.ZipFile(io.BytesIO(response.content))

	# Get JSON filename inside ZIP
	filename = zip_file.namelist()[0]

	# Open JSON file inside ZIP
	with zip_file.open(filename) as file:
		# Load JSON data
		data = json.load(file)

	# Loop through feed data
	for key, value in data.items():
		# Stop after limit reached
		if processed_count >= MAX_ENTRIES:
			print("\nReached processing limit.")
			break

		# Each value contains list
		entry = value[0]

		# Extract malicious URL
		indicator = entry.get("url")

		# Skip empty indicators
		if not indicator:
			continue

		# Extract tags
		tags = entry.get("tags") or []

		# Malware Family Extraction
		malware_family = "unknown"

		ignore_tags = [
			"32-bit",
			"64-bit",
			"elf",
			"exe",
			"mips",
			"x86",
			"arm"
		]

		for tag in tags:
			if tag.lower() not in ignore_tags:
				malware_family = tag
				break

		# MongoDB Document
		document = {
			"indicator": indicator,
			"ioc_type": "url",
			"source": "URLHaus",
			"threat_type": entry.get("threat"),
			"malware_family": malware_family,
			"first_seen": entry.get("dateadded"),
			"confidence": "high",
			"status": entry.get("url_status"),
			"tags": tags
		}

		# Deduplication Check
		existing = collection.find_one({
			"indicator": indicator
		})

		# Insert if not exists
		if not existing:
			collection.insert_one(document)
			inserted_count += 1
			print(f"Inserted [{malware_family}] : {indicator}")
		else:
			duplicate_count += 1
			print(f"Duplicate skipped : {indicator}")

		# Increase processed count
		processed_count += 1

	# Final Summary
	print("\n========== URLHAUS SUMMARY ==========")
	print(f"Processed Entries : {processed_count}")
	print(f"New Indicators Inserted: {inserted_count}")
	print(f"Duplicates Skipped : {duplicate_count}")

else:
	print(f"Failed to fetch feed. Status Code: {response.status_code}")

# Create outputs folder if not exists
os.makedirs("outputs", exist_ok=True)

# Fetch latest URLHaus indicators
results = collection.find(
	{"source": "URLHaus"},
	{
		"_id": 0,
		"indicator": 1,
		"ioc_type": 1,
		"source": 1,
		"threat_type": 1,
		"malware_family": 1,
		"status": 1
	}
).limit(200)

# Convert cursor to list
results_list = list(results)

# Output file path
output_file = "outputs/latest_urlhaus.json"

# Write JSON file
with open(output_file, "w") as file:
	json.dump(results_list, file, indent=4)

print(f"\nExported latest data to: {output_file}")
