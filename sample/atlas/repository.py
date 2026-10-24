"""In-memory repository; imports deliberately demonstrate a cycle."""
from .models import Item
from .service import normalize_name

def fetch_all() -> list[Item]:
    """Return a sample inventory record."""
    return [Item(id=1, name="Field notebook", quantity=12)]

def persist(item: Item) -> Item:
    item.name = normalize_name(item.name)
    return item
