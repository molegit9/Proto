import sys
import asyncio
from contextlib import asynccontextmanager

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    
    try:
        import uvicorn.loops.asyncio
        uvicorn.loops.asyncio.asyncio_setup = lambda: None
    except Exception:
        pass

# ChromaDB 백그라운드 스레드(Telemetry)로 인한 Uvicorn 종료 무한 대기 버그 방지
import os
os.environ["ANONYMIZED_TELEMETRY"] = "False"
os.environ["CHROMA_TELEMETRY_ANONYMIZED"] = "False"

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.services.rag_service import init_vector_db
from app.services.database import init_db
from app.services.browser_analyzer import shutdown_browser_pool
from app.services.http_client import close_http_client

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Startup: Vector DB 및 SQLite DB 초기화를 시작합니다.")
    init_vector_db()
    init_db()
    yield
    print("Shutdown: Playwright 브라우저 풀 및 HTTP 클라이언트를 종료합니다.")
    await shutdown_browser_pool()
    await close_http_client()

from app.api.routes import router

app = FastAPI(title="Phishing Security Assistant API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ],
    allow_origin_regex=r"chrome-extension://.*|https?://.*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)

@app.get("/")
def read_root():
    return {"status": "ok", "message": "Phishing Security Assistant API is running"}
