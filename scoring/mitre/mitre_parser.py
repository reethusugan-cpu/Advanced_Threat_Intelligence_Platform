import json
import os

# MITRE JSON Path
MITRE_JSON_PATH = os.path.join(
    os.path.dirname(__file__),
    "enterprise-attack.json"
)

# Load MITRE ATT&CK Data
def load_mitre_data():

    with open(MITRE_JSON_PATH, "r") as file:

        data = json.load(file)

    return data

# Extract ATT&CK Techniques
def extract_techniques():

    data = load_mitre_data()

    techniques = []

    for obj in data.get("objects", []):

        # Only attack-pattern objects
        if obj.get("type") == "attack-pattern":

            technique = {

                "id": obj.get("external_references", [{}])[0].get("external_id"),

                "name": obj.get("name"),

                "description": obj.get("description", "")
            }

            techniques.append(technique)

    return techniques

# Test
if __name__ == "__main__":

    techniques = extract_techniques()

    print(f"Total Techniques Loaded: {len(techniques)}")

    # Print first 5
    for tech in techniques[:5]:

        print(tech)