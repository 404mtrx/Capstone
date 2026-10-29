import hashlib
import json
from functools import lru_cache

from opensearchpy import OpenSearch, helpers

from app.config import settings

MAPPINGS = {
    "properties": {
        "timestamp": {"type": "date"},
        "source": {"type": "keyword"},
        "event_type": {"type": "keyword"},
        "username": {"type": "keyword"},
        "source_ip": {"type": "ip"},
        "destination_ip": {"type": "ip"},
        "action": {"type": "keyword"},
        "severity": {"type": "keyword"},
        "message": {"type": "text"},
        "hostname": {"type": "keyword"},
        "protocol": {"type": "keyword"},
        "process_name": {"type": "keyword"},
    }
}


def doc_id(event: dict) -> str:
    """Same event -> same id, so re-sending a log file never creates duplicates."""
    return hashlib.sha256(json.dumps(event, sort_keys=True).encode()).hexdigest()


class EventStore:
    def __init__(self, url: str, index: str):
        self.client = OpenSearch(hosts=[url])
        self.index = index

    def ensure_index(self):
        if not self.client.indices.exists(index=self.index):
            self.client.indices.create(index=self.index, body={"mappings": MAPPINGS})

    def index_events(self, events: list[dict]) -> int:
        self.ensure_index()
        actions = [
            {"_index": self.index, "_id": doc_id(e), "_source": e} for e in events
        ]
        indexed, _ = helpers.bulk(self.client, actions, refresh=True)
        return indexed

    def search(self, filters: dict, size: int) -> list[dict]:
        self.ensure_index()
        query = (
            {"bool": {"filter": [{"term": {k: v}} for k, v in filters.items()]}}
            if filters
            else {"match_all": {}}
        )
        body = {"query": query, "size": size, "sort": [{"timestamp": "desc"}]}
        result = self.client.search(index=self.index, body=body)
        return [hit["_source"] for hit in result["hits"]["hits"]]


@lru_cache
def get_event_store() -> EventStore:
    return EventStore(settings.opensearch_url, settings.opensearch_index)
