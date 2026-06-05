import time
import json
import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from core.analyzer import analyze_response, generate_summary

router = APIRouter(prefix="/api")

# ── 요청 모델 ──────────────────────────────────────────────
class SingleRequest(BaseModel):
    method: str
    url: str
    headers: dict = {}
    body: Optional[str] = None
    params: dict = {}
    payload: Optional[str] = None
    payload_id: Optional[str] = None
    category: Optional[str] = None
    timeout: int = 10

class BulkRequest(BaseModel):
    method: str
    url: str
    target_param: str          # 페이로드를 삽입할 파라미터 이름
    inject_in: str = "params"  # params / body / headers
    headers: dict = {}
    body: Optional[str] = None
    params: dict = {}
    payload_ids: list[str]
    category: str
    timeout: int = 10

# ── 페이로드 DB 로드 ────────────────────────────────────────
DATA_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "payloads.json")

def load_payloads():
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def find_payload_by_id(payload_id: str):
    data = load_payloads()
    for cat in data["categories"]:
        for p in cat["payloads"]:
            if p["id"] == payload_id:
                return p, cat
    return None, None


# ── 단일 요청 전송 ──────────────────────────────────────────
@router.post("/request")
async def send_request(req: SingleRequest):
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
            start = time.time()
            response = await client.request(
                method=req.method.upper(),
                url=req.url,
                headers=req.headers,
                params=req.params,
                content=req.body.encode() if req.body else None,
                timeout=req.timeout,
            )
            elapsed = (time.time() - start) * 1000

        body_text = response.text[:50000]  # 최대 50KB
        analysis = analyze_response(
            status_code=response.status_code,
            headers=dict(response.headers),
            body=body_text,
            response_time=elapsed,
            payload=req.payload,
            category=req.category,
        )

        return {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": body_text,
            "response_time": round(elapsed, 2),
            "body_size": len(response.content),
            "analysis": analysis,
        }
    except httpx.TimeoutException:
        return {
            "status_code": 0,
            "headers": {},
            "body": "",
            "response_time": req.timeout * 1000,
            "body_size": 0,
            "analysis": {
                "verdict": "timeout",
                "confidence": 30,
                "waf_detected": None,
                "block_reason": ["요청 타임아웃"],
                "error_leaks": [],
                "sensitive_data": [],
                "response_anomalies": ["응답 시간 초과 — Time-based 공격 가능성"],
                "risk_level": "medium",
                "details": ["요청 타임아웃 발생"],
                "score": 35,
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── 다중 페이로드 일괄 테스트 ───────────────────────────────
@router.post("/bulk-test")
async def bulk_test(req: BulkRequest):
    data = load_payloads()
    # 카테고리에서 선택된 페이로드 추출
    payloads_to_test = []
    for cat in data["categories"]:
        if cat["id"] == req.category:
            if req.payload_ids:
                payloads_to_test = [p for p in cat["payloads"] if p["id"] in req.payload_ids]
            else:
                payloads_to_test = cat["payloads"]
            break

    if not payloads_to_test:
        raise HTTPException(status_code=404, detail="페이로드를 찾을 수 없습니다")

    results = []
    async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
        for p in payloads_to_test:
            # 파라미터 조립
            params = dict(req.params)
            headers = dict(req.headers)
            body = req.body

            if req.inject_in == "params":
                params[req.target_param] = p["payload"]
            elif req.inject_in == "body":
                try:
                    body_dict = json.loads(body) if body else {}
                    body_dict[req.target_param] = p["payload"]
                    body = json.dumps(body_dict)
                    headers.setdefault("Content-Type", "application/json")
                except Exception:
                    body = p["payload"]
            elif req.inject_in == "headers":
                headers[req.target_param] = p["payload"]

            try:
                start = time.time()
                response = await client.request(
                    method=req.method.upper(),
                    url=req.url,
                    headers=headers,
                    params=params,
                    content=body.encode() if body else None,
                    timeout=req.timeout,
                )
                elapsed = (time.time() - start) * 1000
                body_text = response.text[:10000]
                analysis = analyze_response(
                    response.status_code, dict(response.headers),
                    body_text, elapsed, p["payload"], req.category
                )
                results.append({
                    "payload_id": p["id"],
                    "payload_name": p["name"],
                    "payload": p["payload"],
                    "description": p["description"],
                    "risk": p["risk"],
                    "status_code": response.status_code,
                    "response_time": round(elapsed, 2),
                    "analysis": analysis,
                })
            except httpx.TimeoutException:
                results.append({
                    "payload_id": p["id"],
                    "payload_name": p["name"],
                    "payload": p["payload"],
                    "description": p["description"],
                    "risk": p["risk"],
                    "status_code": 0,
                    "response_time": req.timeout * 1000,
                    "analysis": {
                        "verdict": "timeout", "confidence": 30,
                        "waf_detected": None, "block_reason": ["타임아웃"],
                        "error_leaks": [], "sensitive_data": [],
                        "response_anomalies": ["응답 시간 초과"],
                        "risk_level": "medium", "details": ["타임아웃"], "score": 35,
                    },
                })
            except Exception as e:
                results.append({
                    "payload_id": p["id"],
                    "payload_name": p["name"],
                    "payload": p["payload"],
                    "description": p["description"],
                    "risk": p["risk"],
                    "status_code": 0,
                    "response_time": 0,
                    "analysis": {
                        "verdict": "error", "confidence": 0,
                        "waf_detected": None, "block_reason": [str(e)],
                        "error_leaks": [], "sensitive_data": [],
                        "response_anomalies": [],
                        "risk_level": "info", "details": [f"에러: {e}"], "score": 0,
                    },
                })

    summary = generate_summary(results)
    return {"results": results, "summary": summary}


# ── 페이로드 목록 조회 ──────────────────────────────────────
@router.get("/payloads")
def get_payloads():
    return load_payloads()

@router.get("/payloads/{category_id}")
def get_category_payloads(category_id: str):
    data = load_payloads()
    for cat in data["categories"]:
        if cat["id"] == category_id:
            return cat
    raise HTTPException(status_code=404, detail="카테고리를 찾을 수 없습니다")
