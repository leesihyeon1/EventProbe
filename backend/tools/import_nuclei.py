#!/usr/bin/env python3
"""Nuclei 템플릿 → payloads.json CVE 뱅크 임포터 (재사용).

신뢰 소스(projectdiscovery/nuclei-templates)의 HTTP CVE 템플릿을 읽어, 이 도구의
CVE 페이로드 스키마로 변환·중복제거 후 backend/data/payloads.json 의 'cve' 카테고리에
병합한다. 손으로 수백 개를 적는 대신 검증된 소스에서 정확한 요청을 가져오기 위함.

사용법:
  # 1) 템플릿 저장소 클론(한 번)
  git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates

  # 2) 미리보기(파일 미변경) — 무엇이 추가될지 요약만
  python backend/tools/import_nuclei.py nuclei-templates --dry-run

  # 3) 실제 병합 (심각도 critical/high 만, 최대 300개 예시)
  python backend/tools/import_nuclei.py nuclei-templates --severity critical,high --limit 300

주의:
  - 자동 변환이므로 병합 후 반드시 git diff 로 검토할 것(보안 도구 = 페이로드 정확성 중요).
  - {{helper}} 인터폴레이션이 남는 경로/본문은 그대로 전송 불가라 건너뛴다.
  - raw HTTP 템플릿, 다단계(멀티 request) 는 best-effort(첫 요청만) 또는 스킵.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys

try:
    import yaml
except ImportError:
    sys.exit("PyYAML 필요: pip install pyyaml")

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PAYLOADS = os.path.join(_ROOT, "data", "payloads.json")

_CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}", re.I)
_INTERP_RE = re.compile(r"\{\{(?!BaseURL\}\})")   # {{BaseURL}} 외의 인터폴레이션이 남았는지
_SEV2RISK = {"critical": "critical", "high": "high", "medium": "medium",
             "low": "low", "info": "info", "unknown": "info"}

# info.tags 의 제품 키워드 → applies_to 지문(서버/파워드바이). 매칭되면 정밀도↑.
_TAG_TO_SERVER = {"nginx": "nginx", "apache": "apache", "tomcat": "tomcat",
                  "iis": "microsoft-iis", "jetty": "jetty", "openresty": "openresty"}
_TAG_TO_POWERED = {
    "wordpress": "wordpress", "wp-plugin": "wordpress", "drupal": "drupal", "joomla": "joomla",
    "gitlab": "gitlab", "jira": "jira", "confluence": "confluence", "jenkins": "jenkins",
    "spring": "spring", "laravel": "laravel", "django": "django", "grafana": "grafana",
    "nextjs": "next.js", "php": "php", "aspnet": "asp.net", "nodejs": "node",
}
# path_contains 후보에서 제외할 흔한 세그먼트
_COMMON_SEG = {"api", "v1", "v2", "v3", "app", "admin", "index.php", "login", "user",
               "static", "public", "assets", "img", "css", "js", "cgi-bin", "", "."}


def _first_http_block(tpl: dict):
    """템플릿에서 첫 HTTP 요청 블록을 반환(신형 'http' / 구형 'requests')."""
    for key in ("http", "requests"):
        blocks = tpl.get(key)
        if isinstance(blocks, list) and blocks:
            return blocks[0]
    return None


def _distinctive_path_contains(path: str) -> list:
    """경로에서 흔치 않은 세그먼트를 골라 path_contains 힌트로 사용."""
    segs = [s for s in re.split(r"[/?&=]", path) if s and _INTERP_RE.search(s) is None]
    picks = [s for s in segs if len(s) >= 4 and s.lower() not in _COMMON_SEG and "{{" not in s]
    # 너무 흔한 확장자성 제거
    picks = [s for s in picks if not s.lower().endswith((".css", ".js", ".png", ".ico"))]
    return picks[:3]


def _applies_to(info: dict, path: str) -> dict:
    tags = info.get("tags") or ""
    tagset = {t.strip().lower() for t in (tags.split(",") if isinstance(tags, str) else tags)}
    ap: dict = {}
    servers = sorted({v for k, v in _TAG_TO_SERVER.items() if k in tagset})
    powered = sorted({v for k, v in _TAG_TO_POWERED.items() if k in tagset})
    if servers:
        ap["server"] = servers
    if powered:
        ap["powered_by"] = powered
    pc = _distinctive_path_contains(path)
    if pc:
        ap["path_contains"] = pc
    if not ap:                      # 지문 힌트가 전혀 없으면 경로만이라도
        ap["path_contains"] = [path[:40]] if path else []
    return ap


def convert(tpl: dict) -> dict | None:
    """Nuclei 템플릿 dict → payloads.json CVE 엔트리. 변환 불가면 None."""
    tid = str(tpl.get("id") or "")
    info = tpl.get("info") or {}
    blk = _first_http_block(tpl)
    if not blk:
        return None
    if blk.get("raw"):              # raw HTTP 는 이 도구 폼에 싣기 어려움 → 스킵
        return None

    method = str(blk.get("method") or "GET").upper()
    paths = blk.get("path") or []
    if isinstance(paths, str):
        paths = [paths]
    if not paths:
        return None
    raw_path = str(paths[0])
    path = raw_path.replace("{{BaseURL}}", "").replace("{{RootURL}}", "")
    if not path.startswith("/"):
        path = "/" + path
    # BaseURL 외의 {{helper}} 가 경로/본문에 남으면 그대로 전송 불가 → 스킵
    body = blk.get("body")
    if _INTERP_RE.search(path) or (body and _INTERP_RE.search(str(body))):
        return None

    cve_m = _CVE_RE.search(tid) or _CVE_RE.search(json.dumps(info.get("classification") or {}))
    cve = cve_m.group(0).upper() if cve_m else ""
    refs = info.get("reference") or []
    ref = (refs[0] if isinstance(refs, list) and refs else
           (refs if isinstance(refs, str) else
            (f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else "")))

    entry = {
        "id": "nuclei_" + tid.replace("-", "_").lower(),
        "name": (f"{cve} " if cve else "") + str(info.get("name") or tid),
        "payload": path,
        "description": "[Nuclei] " + str(info.get("name") or tid),
        "risk": _SEV2RISK.get(str(info.get("severity") or "info").lower(), "info"),
        "cve": cve,
        "location": "path",
        "param": "",
        "reference": str(ref),
        "applies_to": _applies_to(info, path),
    }
    if method != "GET":
        entry["method"] = method
    hdrs = blk.get("headers")
    if isinstance(hdrs, dict) and hdrs:
        entry["headers"] = {str(k): str(v) for k, v in hdrs.items()}
    if body:
        entry["body"] = str(body)
    return entry


def main():
    ap = argparse.ArgumentParser(description="Nuclei 템플릿 → payloads.json CVE 임포터")
    ap.add_argument("templates_dir", help="클론한 nuclei-templates 디렉터리")
    ap.add_argument("--severity", default="critical,high",
                    help="쉼표구분 심각도 필터 (기본 critical,high). 'all' 이면 전체")
    ap.add_argument("--limit", type=int, default=0, help="추가 최대 개수(0=무제한)")
    ap.add_argument("--dry-run", action="store_true", help="파일 미변경, 요약만 출력")
    args = ap.parse_args()

    sev_filter = None if args.severity.lower() == "all" else {
        s.strip().lower() for s in args.severity.split(",") if s.strip()}

    # http/cves 우선, 없으면 http 전체
    roots = [os.path.join(args.templates_dir, "http", "cves"),
             os.path.join(args.templates_dir, "cves"),
             os.path.join(args.templates_dir, "http")]
    files = []
    for r in roots:
        if os.path.isdir(r):
            files = glob.glob(os.path.join(r, "**", "*.yaml"), recursive=True)
            break
    if not files:
        sys.exit(f"템플릿을 찾지 못함. 확인: {roots}")

    data = json.load(open(_PAYLOADS, encoding="utf-8"))
    cve_cat = next((c for c in data["categories"] if c["id"] == "cve"), None)
    if cve_cat is None:
        sys.exit("payloads.json 에 'cve' 카테고리가 없음")
    existing = cve_cat["payloads"]
    have_ids = {p.get("id") for p in existing}
    have_cves = {p.get("cve") for p in existing if p.get("cve")}
    have_keys = {(p.get("location"), (p.get("param") or "").lower(), p.get("payload")) for p in existing}

    added, skipped_dup, skipped_conv, skipped_sev = 0, 0, 0, 0
    new_entries = []
    for fp in files:
        try:
            tpl = yaml.safe_load(open(fp, encoding="utf-8"))
        except Exception:
            skipped_conv += 1
            continue
        if not isinstance(tpl, dict):
            skipped_conv += 1
            continue
        sev = str((tpl.get("info") or {}).get("severity") or "info").lower()
        if sev_filter is not None and sev not in sev_filter:
            skipped_sev += 1
            continue
        e = convert(tpl)
        if not e or not e.get("payload"):
            skipped_conv += 1
            continue
        key = (e["location"], (e["param"] or "").lower(), e["payload"])
        if e["id"] in have_ids or (e["cve"] and e["cve"] in have_cves) or key in have_keys:
            skipped_dup += 1
            continue
        have_ids.add(e["id"])
        if e["cve"]:
            have_cves.add(e["cve"])
        have_keys.add(key)
        new_entries.append(e)
        added += 1
        if args.limit and added >= args.limit:
            break

    print(f"스캔 파일: {len(files)} | 추가: {added} | 중복스킵: {skipped_dup} | "
          f"변환불가: {skipped_conv} | 심각도필터: {skipped_sev}")
    if new_entries[:5]:
        print("예시(최대 5):")
        for e in new_entries[:5]:
            print(f"  + {e['cve'] or '(no-cve)':18} {e.get('method','GET'):4} {e['payload'][:50]}")

    if args.dry_run:
        print("\n[dry-run] 파일 미변경. 실제 병합하려면 --dry-run 을 빼세요.")
        return
    if not new_entries:
        print("추가할 항목 없음.")
        return

    cve_cat["payloads"].extend(new_entries)
    with open(_PAYLOADS, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(f"\n병합 완료 → {_PAYLOADS} (cve 총 {len(cve_cat['payloads'])}). "
          "git diff 로 반드시 검토하세요.")


if __name__ == "__main__":
    main()
