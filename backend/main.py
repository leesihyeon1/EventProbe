from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os

app = FastAPI(title="SecAPITester", version="1.0.0")

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
