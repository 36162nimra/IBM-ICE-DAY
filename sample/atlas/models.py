"""Domain models for the inventory service."""
from pydantic import BaseModel

class Item(BaseModel):
    """An inventory item with its public display name."""
    id: int
    name: str
    quantity: int = 0
