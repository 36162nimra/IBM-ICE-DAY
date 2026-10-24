"""Inventory operations. The circular import is intentional for the demo."""
from .models import Item
from .repository import fetch_all, persist

def list_items(limit: int) -> list[Item]:
    """Return at most limit items."""
    return fetch_all()[:limit]

def find_item(item_id: int) -> Item:
    """Find an item in the local inventory."""
    return next(item for item in fetch_all() if item.id == item_id)

def save_item(item: Item) -> Item:
    return persist(item)

def normalize_name(name: str) -> str:
    return name.strip()
