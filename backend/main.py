from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
import hmac
import os

# 프로젝트 루트의 .env 로드 (NVIDIA_API_KEY 등). 공용 PC에서 키를 파일로만 관리.
# override=True: reload 감시 프로세스가 상속시킨 옛 값을 덮어써 .env 수정이 즉시 반영되게 함.
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"), override=True)

app = FastAPI(title="SecAPITester", version="1.0.0")


def _access_token() -> str:
    return os.getenv("EVENTPROBE_TOKEN", "").strip()


# ─────────────────────────────────────────────────────────────────────────────
# 접근 토큰 가드 (선택)
#
# 이 도구는 임의 대상에 공격 페이로드를 보내는 프록시이므로, 네트워크에 노출되면
# 누구나 조종할 수 있는 무인 공격 서버가 된다. 기본 바인딩은 127.0.0.1(루프백)이라
# 로컬에서만 접근되지만, 다른 PC에서 접속해야 해서 HOST=0.0.0.0 등으로 여는 경우엔
# EVENTPROBE_TOKEN 을 설정해 접근을 제한한다.
#
#   - EVENTPROBE_TOKEN 이 비어 있으면 가드 비활성(루프백 전용 기본값이라 안전).
#   - 설정 시: 쿠키(ep_token) 또는 헤더(X-Access-Token)로 토큰을 검증.
#     최초 1회 http://HOST:PORT/?token=<토큰> 으로 접속하면 쿠키가 심기고, 토큰이
#     URL/브라우저 히스토리에 남지 않도록 즉시 쿼리 없는 주소로 리다이렉트한다.
# ─────────────────────────────────────────────────────────────────────────────
@app.middleware("http")
async def _access_guard(request: Request, call_next):
    token = _access_token()
    if not token:
        return await call_next(request)

    def _valid(candidate: str) -> bool:
        # 상수 시간 비교로 타이밍 공격 방지
        return bool(candidate) and hmac.compare_digest(candidate, token)

    # 1) ?token= 로 접속 → 쿠키 발급 후 토큰 제거한 주소로 리다이렉트
    q_token = request.query_params.get("token")
    if q_token is not None:
        if _valid(q_token):
            clean_qs = "&".join(
                f"{k}={v}" for k, v in request.query_params.multi_items() if k != "token"
            )
            location = request.url.path + (f"?{clean_qs}" if clean_qs else "")
            resp = RedirectResponse(url=location, status_code=303)
            resp.set_cookie(
                "ep_token", token,
                httponly=True, samesite="lax", max_age=86400, path="/",
            )
            return resp
        return JSONResponse({"detail": "접근 토큰이 올바르지 않습니다."}, status_code=401)

    # 2) 쿠키 또는 헤더 검증
    if _valid(request.cookies.get("ep_token", "")) or _valid(request.headers.get("x-access-token", "")):
        return await call_next(request)

    return JSONResponse(
        {"detail": "접근 토큰이 필요합니다. 주소 끝에 ?token=<EVENTPROBE_TOKEN> 을 붙여 접속하세요."},
        status_code=401,
    )


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
    import argparse
    import uvicorn

    # 기본 바인딩은 루프백(127.0.0.1) — 네트워크 노출 차단. 다른 PC에서 접속해야 하면
    # HOST 환경변수나 --host 로 여는 대신, 반드시 EVENTPROBE_TOKEN 을 함께 설정할 것.
    parser = argparse.ArgumentParser(description="EventProbe / SecAPITester 서버")
    parser.add_argument("--host", default=os.getenv("HOST", "127.0.0.1"),
                        help="바인딩 주소 (기본 127.0.0.1). 네트워크 공개 시 0.0.0.0")
    parser.add_argument("--port", type=int, default=int(os.getenv("PORT", "8000")),
                        help="포트 (기본 8000)")
    args = parser.parse_args()

    host, port = args.host, args.port
    is_loopback = host in ("127.0.0.1", "localhost", "::1")
    if not is_loopback and not _access_token():
        print("\n" + "=" * 70)
        print(f"⚠️  경고: {host} 로 바인딩하면 네트워크의 다른 사용자도 이 도구를")
        print("    조종해 임의 대상에 공격 요청을 보낼 수 있습니다.")
        print("    .env 에 EVENTPROBE_TOKEN 을 설정해 접근을 제한하세요.")
        print("=" * 70 + "\n")

    uvicorn.run("main:app", host=host, port=port, reload=True)
