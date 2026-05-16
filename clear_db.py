from database.mongo_handler import collection

# Delete all documents
result = collection.delete_many({})

print(f"Deleted {result.deleted_count} documents")
