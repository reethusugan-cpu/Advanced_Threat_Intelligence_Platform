from database.mongo_handler import collection
from datetime import datetime


def mark_processed(doc_id, ip):

    collection.update_one(

        {"_id": doc_id},

        {"$set": {

            "processed": True,
            "resolved_ip": ip,
            "processed_time": datetime.utcnow()

        }}
    )


def mark_blocked(doc_id):

    collection.update_one(

        {"_id": doc_id},

        {"$set": {

            "blocked": True

        }}
    )