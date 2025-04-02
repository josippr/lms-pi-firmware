from pymongo import MongoClient
from dotenv import load_dotenv
import os
from datetime import datetime
import random
import time

# Load environment variables
load_dotenv()

# Access environment variables
MONGO_URI = os.getenv("MONGO_URI")
DATABASE_NAME = os.getenv("DATABASE_NAME")
COLLECTION_NAME = os.getenv("COLLECTION_NAME")

# Function to generate fake network traffic data
def generate_fake_traffic():
    source_ip = f"192.168.1.{random.randint(1, 254)}"
    destination_ip = f"10.0.0.{random.randint(1, 254)}"
    protocols = ["TCP", "UDP", "ICMP"]
    protocol = random.choice(protocols)
    payload_size = random.randint(64, 1500)
    timestamp = datetime.utcnow()

    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol,
        "payload_size": payload_size,
    }

# Function to insert fake traffic data into MongoDB
def insert_fake_traffic():
    try:
        client = MongoClient(MONGO_URI)
        db = client[DATABASE_NAME]

        if COLLECTION_NAME not in db.list_collection_names():
            db.create_collection(
                COLLECTION_NAME,
                timeseries={
                    "timeField": "timestamp",
                    "metaField": "metadata",
                    "granularity": "seconds",
                },
            )
            print(f"Created time series collection: {COLLECTION_NAME}")

        collection = db[COLLECTION_NAME]

        while True:
            fake_traffic = generate_fake_traffic()
            collection.insert_one(fake_traffic)
            print(f"Inserted fake traffic: {fake_traffic}")
            time.sleep(random.randint(1, 5))

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        client.close()

# Run the script
if __name__ == "__main__":
    insert_fake_traffic()