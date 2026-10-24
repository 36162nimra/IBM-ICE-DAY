"""Synthetic unsafe-code patterns used to demonstrate the static security panel."""


def evaluate_expression(expression: str):
    """Illustrate a dynamic evaluation pattern; the demo analyzer never calls this."""
    return eval(expression)


def find_item(cursor, name: str):
    """Illustrate SQL interpolation; the demo analyzer never calls this."""
    cursor.execute(f"SELECT * FROM items WHERE name = '{name}'")
