"""HTTP application and service health."""
from fastapi import FastAPI
from .routes import router

app = FastAPI(title="Atlas inventory")
app.include_router(router, prefix="/api/v1")

@app.get("/health")
def health() -> dict:
    """Return the service health status."""
    return {"status": "ok"}
