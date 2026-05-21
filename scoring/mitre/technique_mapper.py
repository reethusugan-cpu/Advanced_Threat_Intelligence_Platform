import json
import os
import re

class MITRETechniqueMapper:
    _instance = None
    
    # Pre-compiled regex patterns for performance
    KEYWORD_MAPPINGS = [
        (re.compile(r"phish", re.I), "T1566", "Phishing"),
        (re.compile(r"credential|brute", re.I), "T1110", "Brute Force"),
        (re.compile(r"stealer|spyware|infostealer", re.I), "T1005", "Data from Local System"),
        (re.compile(r"ransomware|encrypt", re.I), "T1486", "Data Encrypted for Impact"),
        (re.compile(r"c2|command and control|cobalt strike|beacon", re.I), "T1071.001", "Application Layer Protocol: Web Protocols"),
        (re.compile(r"download|loader|dropper", re.I), "T1105", "Ingress Tool Transfer"),
        (re.compile(r"exploit|vulnerability|cve-", re.I), "T1203", "Exploitation for Client Execution"),
        (re.compile(r"keylogger", re.I), "T1056.001", "Input Capture: Keylogging")
    ]

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(MITRETechniqueMapper, cls).__new__(cls, *args, **kwargs)
            cls._instance._initialized = False #prevent reloading database again and again
        return cls._instance

    def __init__(self, json_path=None):
        if getattr(self, "_initialized", False):
            return
        
        self.json_path = json_path or os.path.join(os.path.dirname(os.path.abspath(__file__)), "enterprise-attack.json")
        self.malware_index = {}      # alias (lower) -> list of malware STIX IDs
        self.technique_index = {}    # STIX ID -> technique dict {id, name, description}
        self.relationship_index = {} # STIX ID (source) -> list of target technique IDs
        
        self._load_and_index()
        self._initialized = True

    def _load_and_index(self):
        if not os.path.exists(self.json_path):
            print(f"Warning: MITRE ATT&CK JSON not found at {self.json_path}")
            return

        print(f"Loading MITRE ATT&CK data from {self.json_path}...")
        try:
            with open(self.json_path, "r", encoding="utf-8") as f:
                objects = json.load(f).get("objects", [])
        except Exception as e:
            print(f"Error loading MITRE ATT&CK JSON: {e}")
            return

        for obj in objects:
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue

            obj_type = obj.get("type")
            stix_id = obj.get("id")

            if obj_type == "attack-pattern":
                tech_id = next((ref.get("external_id") for ref in obj.get("external_references", []) 
                              if ref.get("source_name") == "mitre-attack"), None)
                if tech_id and stix_id:
                    self.technique_index[stix_id] = {
                        "id": tech_id,
                        "name": obj.get("name", ""),
                        "description": obj.get("description", "")
                    }

            elif obj_type in ["malware", "tool"] and stix_id:
                aliases = {obj.get("name", "").lower()}
                aliases.update(a.lower() for a in obj.get("x_mitre_aliases", []))
                aliases.update(a.lower() for a in obj.get("aliases", []))
                
                for alias in filter(None, aliases):
                    self.malware_index.setdefault(alias, []).append(stix_id)

            elif obj_type == "relationship" and obj.get("relationship_type") == "uses":
                source_ref = obj.get("source_ref", "")
                target_ref = obj.get("target_ref", "")
                
                if (source_ref.startswith("malware--") or source_ref.startswith("tool--")) and target_ref.startswith("attack-pattern--"):
                    self.relationship_index.setdefault(source_ref, []).append(target_ref)

        print(f"MITRE indexing complete. Indexed {len(self.technique_index)} techniques, {len(self.malware_index)} aliases.")

    def map_malware_to_techniques(self, malware_name):
        if not malware_name or malware_name.lower() == "unknown":
            return []

        search_name = malware_name.lower().strip()
        matched_stix_ids = self.malware_index.get(search_name, [])

        if not matched_stix_ids:
            for alias, ids in self.malware_index.items():
                if search_name in alias or alias in search_name:
                    matched_stix_ids = ids
                    break

        techniques = {}
        for stix_id in matched_stix_ids:
            for ref in self.relationship_index.get(stix_id, []):
                tech_info = self.technique_index.get(ref)
                if tech_info:
                    techniques[tech_info["id"]] = {"id": tech_info["id"], "name": tech_info["name"]}

        return list(techniques.values())

    def map_text_to_techniques(self, text):
        if not text:
            return []

        matched = {}
        for pattern, tech_id, name in self.KEYWORD_MAPPINGS:
            if pattern.search(text):
                matched[tech_id] = {"id": tech_id, "name": name}

        return list(matched.values())

mapper = MITRETechniqueMapper()
