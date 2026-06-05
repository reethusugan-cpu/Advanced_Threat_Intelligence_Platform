from database.mongo_handler import collection
from database.elasticsearch_handler import update_elasticsearch_docs
from datetime import datetime


def mark_processed(doc_id, ip):
    processed_time = datetime.utcnow()
    collection.update_one(
        {"_id": doc_id},
        {"$set": {
            "processed": True,
            "resolved_ip": ip,
            "processed_time": processed_time
        }}
    )
    update_elasticsearch_docs([doc_id], {
        "processed": True,
        "resolved_ip": ip,
        "processed_time": processed_time.isoformat()
    })


def mark_blocked(doc_id):
    collection.update_one(
        {"_id": doc_id},
        {"$set": {
            "blocked": True
        }}
    )
    update_elasticsearch_docs([doc_id], {
        "blocked": True
    })
