from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os

# 프로젝트 루트의 .env 로드 (NVIDIA_API_KEY 등). 공용 PC에서 키를 파일로만 관리.
# override=True: reload 감시 프로세스가 상속시킨 옛 값을 덮어써 .env 수정이 즉시 반영되게 함.
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"), override=True)

app = FastAPI(title="SecAPITester", version="1.0.0")


# 개발/테스트 도구: 정적 파일 캐시로 인한 "변경 미반영" 방지 (항상 최신 서빙)
@app.middleware("http")
async def _no_cache(request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    return response

# 라우터 등록
from routers.api import router as api_router
app.include_router(api_router)

# 정적 파일
STATIC_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend", "static")
TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend", "templates")

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/")
def index():
    return FileResponse(os.path.join(TEMPLATE_DIR, "index.html"))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
