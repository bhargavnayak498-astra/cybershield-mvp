from __future__ import annotations

from typing import Any

from pymongo import MongoClient
from pymongo.collection import Collection

from app.config import settings


client = MongoClient(settings.mongo_uri, serverSelectionTimeoutMS=3000)
db = client[settings.mongo_db]


def get_collection() -> Collection[Any]:
    return db["scans"]


def ensure_indexes() -> None:
    scans = get_collection()
    scans.create_index([("created_at", -1)])
    scans.create_index([("hash", 1)])
    scans.create_index([("score", -1)])
