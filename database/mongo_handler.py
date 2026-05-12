from pymongo import MongoClient

# MongoDB Connection
client = MongoClient("mongodb://localhost:27017/")

# Database
db = client["threat_intel"]

# Collection
collection = db["indicators"]