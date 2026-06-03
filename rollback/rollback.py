import sys
import os
import subprocess
import re  # Added for IP validation
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database.mongo_handler import collection

# Simple IPv4 Regex Validator
IP_REGEX = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"

def rollback(ip):
    # Step 0: Input Validation
    if not re.match(IP_REGEX, ip):
        print(f"\n[-] Error: '{ip}' is not a valid IPv4 address.\n")
        return

    # Step 1: Check if IP exists in DB as a blocked entry
    docs = list(collection.find({"resolved_ip": ip, "blocked": True}))

    if not docs:
        print(f"\n[-] IP {ip} not found in blocked records. Nothing to rollback.\n")
        return

    # Step 2: Show what was found
    print(f"\n[+] IP {ip} found! {len(docs)} blocked record(s):\n")

    for doc in docs:
        indicator = doc.get("indicator", "N/A")
        ioc_type = doc.get("ioc_type", "N/A")
        score = doc.get("risk_score", "N/A")

        if ioc_type.lower() in ["url", "domain", "hostname"]:
            print(f"    -> {indicator} ({ioc_type}) | Score: {score}")
        else:
            print(f"    -> {indicator} (Direct IP) | Score: {score}")

    # Step 3: Unblock from iptables
    # -C checks if the rule exists safely without throwing an iptables error
    check = subprocess.run(
        ["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True
    )

    if check.returncode == 0:
        # Execute deletion
        delete_action = subprocess.run(
            ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True
        )
        
        if delete_action.returncode == 0:
            print(f"\n[+] Firewall: {ip} unblocked successfully from iptables.")
        else:
            print(f"\n[-] Firewall Error: Failed to delete iptables rule. Reason: {delete_action.stderr.decode().strip()}")
            return # Stop execution if system firewall didn't actually release the IP
    else:
        print(f"\n[*] Firewall: {ip} was not in iptables (already clean).")

    # Step 4: Update MongoDB
    rollback_time = datetime.now(timezone.utc)
    result = collection.update_many(
        {"resolved_ip": ip, "blocked": True},
        {"$set": {
            "blocked": False,
            "processed": False,
            "rollback": True,
            "rollback_time": rollback_time
        }}
    )

    print(f"[+] Database: {result.modified_count} document(s) updated in MongoDB.")
    
    # Step 5: Sync with SIEM (Elasticsearch Alerting Note)
    from database.elasticsearch_handler import update_elasticsearch_docs
    doc_ids = [str(doc["_id"]) for doc in docs]
    es_fields = {
        "blocked": False,
        "processed": False,
        "rollback": True,
        "rollback_time": rollback_time.isoformat()
    }
    update_elasticsearch_docs(doc_ids, es_fields)
    print(f"[+] SIEM Sync: Broadcasted rollback state for {ip} to tracking pipeline.")
    
    print(f"\n[✓] Rollback complete for {ip}.\n")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 rollback/rollback.py <ip_address>")
        sys.exit(1)

    rollback(sys.argv[1])