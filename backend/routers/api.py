import time
import json
import asyncio
import socket
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
    target_param: str
    inject_in: str = "params"
    headers: dict = {}
    body: Optional[str] = None
    params: dict = {}
    payload_ids: list[str]
    category: str
    timeout: int = 10

# 다중 타겟 일괄 테스트
class MultiTargetRequest(BaseModel):
    method: str
    urls: list[str]            # 복수 대상 URL
    target_param: str
    inject_in: str = "params"
    headers: dict = {}
    body: Optional[str] = None
    params: dict = {}
    payload_ids: list[str]
    category: str
    timeout: int = 10

# 포트 스캔
class PortScanRequest(BaseModel):
    hosts: list[str]           # 단일/다중 호스트 모두 지원
    ports: list[int] = []      # 빈 경우 기본 포트 목록 사용
    timeout: float = 2.0

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


# ── 다중 타겟 일괄 테스트 ───────────────────────────────────
@router.post("/multi-target-test")
async def multi_target_test(req: MultiTargetRequest):
    if not req.urls:
        raise HTTPException(status_code=400, detail="대상 URL이 없습니다")

    data = load_payloads()
    payloads_to_test = []
    for cat in data["categories"]:
        if cat["id"] == req.category:
            payloads_to_test = [p for p in cat["payloads"] if p["id"] in req.payload_ids] if req.payload_ids else cat["payloads"]
            break

    if not payloads_to_test:
        raise HTTPException(status_code=404, detail="페이로드를 찾을 수 없습니다")

    target_results = []

    async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
        for url in req.urls:
            url = url.strip()
            if not url:
                continue
            results = []
            for p in payloads_to_test:
                params  = dict(req.params)
                headers = dict(req.headers)
                body    = req.body

                if req.inject_in == "params":
                    params[req.target_param] = p["payload"]
                elif req.inject_in == "body":
                    try:
                        bd = json.loads(body) if body else {}
                        bd[req.target_param] = p["payload"]
                        body = json.dumps(bd)
                        headers.setdefault("Content-Type", "application/json")
                    except Exception:
                        body = p["payload"]
                elif req.inject_in == "headers":
                    headers[req.target_param] = p["payload"]

                try:
                    start = time.time()
                    resp  = await client.request(
                        method=req.method.upper(), url=url,
                        headers=headers, params=params,
                        content=body.encode() if body else None,
                        timeout=req.timeout,
                    )
                    elapsed = (time.time() - start) * 1000
                    bt = resp.text[:5000]
                    analysis = analyze_response(resp.status_code, dict(resp.headers), bt, elapsed, p["payload"], req.category)
                    results.append({
                        "payload_id": p["id"], "payload_name": p["name"],
                        "payload": p["payload"], "description": p["description"],
                        "risk": p["risk"], "status_code": resp.status_code,
                        "response_time": round(elapsed, 2), "analysis": analysis,
                    })
                except httpx.TimeoutException:
                    results.append({
                        "payload_id": p["id"], "payload_name": p["name"],
                        "payload": p["payload"], "description": p["description"],
                        "risk": p["risk"], "status_code": 0,
                        "response_time": req.timeout * 1000,
                        "analysis": {"verdict": "timeout", "confidence": 30,
                            "waf_detected": None, "block_reason": ["타임아웃"],
                            "error_leaks": [], "sensitive_data": [],
                            "response_anomalies": [], "risk_level": "medium",
                            "details": ["타임아웃"], "score": 35, "alerts": []},
                    })
                except Exception as e:
                    results.append({
                        "payload_id": p["id"], "payload_name": p["name"],
                        "payload": p["payload"], "description": p["description"],
                        "risk": p["risk"], "status_code": 0, "response_time": 0,
                        "analysis": {"verdict": "error", "confidence": 0,
                            "waf_detected": None, "block_reason": [str(e)],
                            "error_leaks": [], "sensitive_data": [],
                            "response_anomalies": [], "risk_level": "info",
                            "details": [f"에러: {e}"], "score": 0, "alerts": []},
                    })

            target_results.append({
                "url": url,
                "results": results,
                "summary": generate_summary(results),
            })

    return {"targets": target_results, "target_count": len(target_results)}


# ── 포트 스캔 ────────────────────────────────────────────────
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
    3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888,
    9200, 27017, 1433, 1521, 2375, 2376, 4444, 4848,
    7001, 8161, 9090, 9300, 11211, 50070,
]

WELL_KNOWN = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "Jupyter",
    9200: "Elasticsearch", 27017: "MongoDB", 1433: "MSSQL", 1521: "Oracle",
    2375: "Docker(비보안)", 2376: "Docker(TLS)", 4444: "Metasploit",
    4848: "GlassFish", 7001: "WebLogic", 8161: "ActiveMQ",
    9090: "Prometheus/Openshift", 9300: "Elasticsearch(클러스터)",
    11211: "Memcached", 50070: "Hadoop NameNode",
}

RISK_PORTS = {21, 23, 445, 3389, 6379, 2375, 4444, 27017, 11211, 50070}

async def _check_port(host: str, port: int, timeout: float) -> dict:
    try:
        start = time.time()
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        elapsed = (time.time() - start) * 1000
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return {
            "port": port,
            "state": "open",
            "service": WELL_KNOWN.get(port, "Unknown"),
            "response_time": round(elapsed, 2),
            "risk": "high" if port in RISK_PORTS else "low",
            "note": _port_note(port),
        }
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return {"port": port, "state": "closed", "service": WELL_KNOWN.get(port, ""), "response_time": None, "risk": "info", "note": ""}

def _port_note(port: int) -> str:
    notes = {
        6379: "⚠️ Redis 인증 없이 노출 여부 확인 필요",
        27017: "⚠️ MongoDB 인증 없이 노출 여부 확인 필요",
        2375: "🔴 Docker 데몬 비보안 노출 — RCE 가능",
        3389: "⚠️ RDP 노출 — 무차별 대입 위험",
        23: "🔴 Telnet 평문 통신 — 사용 지양",
        11211: "⚠️ Memcached 노출 — DDoS 증폭 위험",
        4444: "🔴 Metasploit 기본 포트 — 백도어 의심",
        50070: "⚠️ Hadoop NameNode 관리 인터페이스 노출",
        9200: "⚠️ Elasticsearch 무인증 노출 여부 확인",
        5900: "⚠️ VNC 원격 접속 노출",
    }
    return notes.get(port, "")

@router.post("/port-scan")
async def port_scan(req: PortScanRequest):
    if not req.hosts:
        raise HTTPException(status_code=400, detail="호스트를 입력하세요")

    ports = req.ports if req.ports else DEFAULT_PORTS

    async def scan_one(raw_host: str) -> dict:
        host = raw_host.strip()
        for scheme in ("http://", "https://", "ftp://"):
            if host.startswith(scheme):
                host = host[len(scheme):]
        host = host.split("/")[0].split(":")[0]
        if not host:
            return {"host": raw_host, "error": "유효하지 않은 호스트"}
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            return {"host": host, "ip": None, "error": f"DNS 해석 실패: {host}",
                    "total_scanned": 0, "open_count": 0, "risky_count": 0,
                    "results": [], "open_ports": []}
        tasks   = [_check_port(ip, p, req.timeout) for p in ports]
        raw     = await asyncio.gather(*tasks)
        results = sorted(raw, key=lambda x: x["port"])
        open_ports  = [r for r in results if r["state"] == "open"]
        risky_ports = [r for r in open_ports if r["risk"] == "high"]
        return {
            "host": host, "ip": ip, "error": None,
            "total_scanned": len(ports),
            "open_count": len(open_ports),
            "risky_count": len(risky_ports),
            "results": results,
            "open_ports": open_ports,
        }

    host_results = []
    for h in req.hosts:
        if h.strip():
            host_results.append(await scan_one(h))

    total_open  = sum(r.get("open_count", 0)  for r in host_results)
    total_risky = sum(r.get("risky_count", 0) for r in host_results)

    return {
        "host_count": len(host_results),
        "total_open": total_open,
        "total_risky": total_risky,
        "hosts": host_results,
    }


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
