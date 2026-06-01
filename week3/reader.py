import sys
import os

sys.path.insert(
    0,
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)

from database.mongo_handler import collection
from week3.utils import extract_ip_from_ioc
from week3.tracker import mark_processed, mark_blocked
from week3.config import RISK_THRESHOLD
from firewall.firewall_enforcer import block_ip


def get_high_risk_iocs():

    query = {

        "risk_score": {"$gte": RISK_THRESHOLD},

        "processed": {"$ne": True}

    }

    docs = list(collection.find(query))

    print(f"\nTotal High Risk IOCS : {len(docs)}")

    ip_count = 0
    resolve_count = 0

    for d in docs:

        ioc_type = d.get("ioc_type", "").lower()

        if ioc_type in ["ipv4", "ip"]:

            ip_count += 1

        elif ioc_type in ["url", "domain", "hostname"]:

            resolve_count += 1

    print(f"Direct IP IOCS : {ip_count}")
    print(f"URL/Domain IOCS To Resolve : {resolve_count}\n")

    actionable_ips = []

    for index, doc in enumerate(docs):

        indicator = doc.get("indicator")
        ioc_type = doc.get("ioc_type")

        print(
            f"[{index+1}/{len(docs)}] "
            f"Processing : {indicator}"
        )

        ip = extract_ip_from_ioc(indicator, ioc_type)

        if not ip:
            print("Could not resolve\n")
            # FIX: Mark it true for processed so it gets excluded next time!
            mark_processed(doc["_id"], ip=None) 
            continue

        print(f"Resolved IP : {ip}\n")

        actionable_ips.append({

            "doc_id": doc["_id"],
            "indicator": indicator,
            "ioc_type": ioc_type,
            "resolved_ip": ip

        })

        mark_processed(doc["_id"], ip)
        block_ip(ip)
        mark_blocked(doc["_id"])
        
    return actionable_ips


def main():

    ips = get_high_risk_iocs()

    print("\n========== ACTIONABLE IPS ==========\n")

    for entry in ips:

        print(

            f"[{entry['ioc_type']}] "
            f"{entry['indicator']} "
            f"-> {entry['resolved_ip']}"

        )

    print(f"\nTotal Actionable IPs : {len(ips)}")


if __name__ == "__main__":
    main()