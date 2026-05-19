from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.routes import router as did_router
from app.db import init_db
from app.middleware import install_access_logging


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Tovbase ID",
    description="Bank-grade DID and federated hash registry with signed receipts.",
    version="0.1.0",
    lifespan=lifespan,
)
install_access_logging(app)
app.include_router(did_router)


@app.get("/")
def root() -> dict[str, str]:
    return {"service": "tovbase-id", "status": "ok"}
