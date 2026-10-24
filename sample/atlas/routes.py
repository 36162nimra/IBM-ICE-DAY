"""Inventory routes exposed by the Atlas API."""
from fastapi import APIRouter
from .models import Item
from .service import list_items, find_item, save_item

router = APIRouter(prefix="/items")

@router.get("/", response_model=list[Item])
def get_items(limit: int = 20) -> list[Item]:
    """List inventory items with an optional result limit."""
    return list_items(limit)

@router.get("/{item_id}", response_model=Item)
def get_item(item_id: int) -> Item:
    """Look up one inventory item by its identifier."""
    return find_item(item_id)

@router.post("/", response_model=Item, status_code=201)
async def create_item(item: Item) -> Item:
    """Create a new item and return the saved record."""
    return save_item(item)

@router.delete("/{item_id}", status_code=204)
def delete_item(item_id: int):
    pass
