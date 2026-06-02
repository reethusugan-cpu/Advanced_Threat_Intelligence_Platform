import os
import requests
from dotenv import load_dotenv

load_dotenv()

ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")

def update_elasticsearch_docs(doc_ids, update_fields):
    """
    Directly update Elasticsearch documents using _update_by_query.
    Used to keep ES in sync when documents are updated in MongoDB.
    """
    if not doc_ids:
        return True

    url = ELASTICSEARCH_URL.rstrip('/') + '/threat-intel-indicators-*/_update_by_query'
    
    str_ids = [str(d_id) for d_id in doc_ids]
    
    script_parts = []
    for field in update_fields.keys():
        script_parts.append(f"ctx._source.{field} = params.{field}")
    
    script_source = '; '.join(script_parts)
    
    payload = {
        "script": {
            "source": script_source,
            "lang": "painless",
            "params": update_fields
        },
        "query": {
            "ids": {
                "values": str_ids
            }
        }
    }
    
    try:
        response = requests.post(
            url,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        if response.status_code == 200:
            res_json = response.json()
            updated = res_json.get('updated', 0)
            print(f"[+] Elasticsearch Sync: Updated {updated} document(s) in ES.")
            return True
        else:
            print(f"[-] Elasticsearch Sync Warning: Status {response.status_code}, Response: {response.text}")
            return False
    except Exception as e:
        print(f"[-] Elasticsearch Sync Connection Error: Could not connect to Elasticsearch at {ELASTICSEARCH_URL}. Error: {e}")
        return False
