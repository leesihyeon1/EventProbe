#!/usr/bin/env python3
"""sqlmap errors.xml → dbms_error_signatures.json 임포터.

sqlmap 의 DBMS 에러 시그니처(data/xml/errors.xml)를 이 도구의 선언형 에러 룰로 가져온다.
전역(scope=global) 큐레이트 항목은 보존하고, sqlmap 패턴은 scope=sqli 로 추가한다
(전역 적용 시 오탐이 나는 넓은 패턴이 있어, SQLi 문맥에서만 적용되게 하기 위함).

사용법:
  # 1) errors.xml 확보 — 로컬 경로 또는 URL
  #    https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/data/xml/errors.xml
  python backend/tools/import_sqlmap_errors.py errors.xml --dry-run
  python backend/tools/import_sqlmap_errors.py https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/data/xml/errors.xml

주의:
  - scope=global(큐레이트) 항목은 유지, 중복 regex 는 스킵. git diff 로 검토 권장.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import xml.etree.ElementTree as ET

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_JSON = os.path.join(_ROOT, "data", "dbms_error_signatures.json")


def _read(src: str) -> str:
    if src.startswith(("http://", "https://")):
        import urllib.request
        with urllib.request.urlopen(src, timeout=30) as r:   # noqa: S310 (신뢰 소스)
            return r.read().decode("utf-8", "ignore")
    with open(src, encoding="utf-8") as f:
        return f.read()


def parse_errors_xml(xml_text: str) -> list:
    """<root><dbms value="MySQL"><error regexp="..."/></dbms></root> → [{regex,label,dbms,scope}]."""
    root = ET.fromstring(xml_text)
    out = []
    for dbms in root.iter("dbms"):
        name = dbms.get("value") or "SQL"
        for err in dbms.iter("error"):
            rx = err.get("regexp")
            if not rx:
                continue
            try:
                re.compile(rx)
            except re.error:
                continue
            out.append({"regex": rx, "label": f"{name} 에러", "dbms": name, "scope": "sqli"})
    return out


def main():
    ap = argparse.ArgumentParser(description="sqlmap errors.xml → dbms_error_signatures.json")
    ap.add_argument("source", help="errors.xml 로컬 경로 또는 URL")
    ap.add_argument("--dry-run", action="store_true", help="파일 미변경, 요약만")
    args = ap.parse_args()

    try:
        xml_text = _read(args.source)
    except Exception as e:
        sys.exit(f"errors.xml 읽기 실패: {e}")
    imported = parse_errors_xml(xml_text)
    if not imported:
        sys.exit("errors.xml 에서 패턴을 찾지 못함(형식 확인)")

    store = json.load(open(_JSON, encoding="utf-8")) if os.path.isfile(_JSON) else {"error_signatures": []}
    sigs = store.setdefault("error_signatures", [])
    have = {s.get("regex") for s in sigs}

    added = [e for e in imported if e["regex"] not in have]
    print(f"sqlmap 패턴: {len(imported)} | 신규 추가(scope=sqli): {len(added)} | 중복 스킵: {len(imported) - len(added)}")
    print(f"기존 유지: 전역 {sum(1 for s in sigs if s.get('scope') != 'sqli')} · sqli {sum(1 for s in sigs if s.get('scope') == 'sqli')}")
    for e in added[:8]:
        print(f"  + [{e['dbms']}] {e['regex'][:60]}")
    if args.dry_run:
        print("\n[dry-run] 파일 미변경.")
        return
    if not added:
        print("추가할 항목 없음.")
        return
    sigs.extend(added)
    with open(_JSON, "w", encoding="utf-8") as f:
        json.dump(store, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(f"\n병합 완료 → {_JSON} (총 {len(sigs)}). git diff 로 검토하세요.")


if __name__ == "__main__":
    main()
