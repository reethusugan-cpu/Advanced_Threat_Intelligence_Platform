import os
# pyrefly: ignore [missing-import]
from pymongo import MongoClient
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env'))

# MongoDB Credentials
MONGO_USERNAME = os.getenv("MONGO_USERNAME", "")
MONGO_PASSWORD = os.getenv("MONGO_PASSWORD", "")
MONGO_HOST = os.getenv("MONGO_HOST", "localhost")
MONGO_PORT = os.getenv("MONGO_PORT", "27017")
MONGO_AUTH_DB = os.getenv("MONGO_AUTH_DB", "admin")

# MongoDB Connection (with authentication)
if MONGO_USERNAME and MONGO_PASSWORD:
    uri = f"mongodb://{MONGO_USERNAME}:{MONGO_PASSWORD}@{MONGO_HOST}:{MONGO_PORT}/?authSource={MONGO_AUTH_DB}"
else:
    uri = f"mongodb://{MONGO_HOST}:{MONGO_PORT}/"

client = MongoClient(uri)

# Database
db = client["threat_intel"]

# Collection
collection = db["indicators"]