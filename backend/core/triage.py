"""Stateless SIEM triage. No persistence, AI calls or target requests."""
import csv
import hashlib
import io
import json
import re
from collections import defaultdict
from datetime import datetime
from urllib.parse import urlsplit
from core.classify import classify, is_direct_file_probe
from core.triage_cve import identify as identify_cve
from core.triage_campaigns import summarize_campaigns
from core.triage_summary import refresh_attack_summary, signature_category
from core.triage_statistics import summarize_statistics, device_kind
from core.triage_filter import refresh_screening, status_provenance

MAX_BYTES = 2_000_000
MAX_RECORDS = 10000
POLICY = "triage-3"


class UnsupportedLog(ValueError):
    pass


def fields(text):
    # Quoted values are consumed whole; an unquoted value ends at the next key.
    pattern = r'(?:^|[\s,])([\w.-]+)=("(?:\\.|[^"\\])*"|.*?)(?=(?:[\s,]+[\w.-]+=)|$)'
    out = {}
    for m in re.finditer(pattern, text):
        value = m[2].strip()
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1].replace(r'\"', '"')
        out[m[1]] = value
    return out


def normalize(data, line, raw):
    pick = lambda *keys: next((str(data[k]) for k in keys if data.get(k) not in (None, '', 'N/A', '---')), '')
    inner = {}
    for part in pick('layer_7_data').split(';;;'):
        if '==' in part:
            k, v = part.split('==', 1)
            inner[k.strip()] = v.strip()
    destination = pick('dst', 'dst_ip', 'destination_ip', 'dest_ip', 'destinationAddress')
    host = pick('httpHost', 'dhost', 'dest_host', 'host') or inner.get('HTTP Host', '')
    path = pick('url', 'uri', 'request', 'request_uri') or inner.get('HTTP URI', '')
    method = (pick('requestMethod', 'webMethod', 'method') or inner.get('HTTP Request Method', '')).upper()
    event_name = pick('evtname', 'eventName', 'event_name', 'attack_name', 'evntDesc', 'ruleName', 'signature')
    device = device_kind(data, raw)
    network_only = not path and bool(destination and event_name and device in ('IPS', 'IDS'))
    if not path and not network_only:
        if not data: raise ValueError('로그 필드를 읽을 수 없습니다.')
        raise UnsupportedLog('HTTP 요청 경로가 없는 로그입니다. 감사·인증 로그 등은 요청 검증 대상에서 제외됩니다.')
    conflicts = []
    if path.startswith(('http://', 'https://')):
        u = urlsplit(path)
        if host and host.lower() != u.netloc.lower(): conflicts.append('HOST_CONFLICT')
        host = host or u.netloc
        path = u.path + ('?' + u.query if u.query else '')
    host_candidates = re.findall(r'(?:^|[\r\n,])\s*Host:\s*([^,\r\n]+)', pick('Header-Value'), re.I)
    if host_candidates and any(h.strip().lower() != host.lower() for h in host_candidates):
        conflicts.append('HOST_CONFLICT')
    if not host and not destination: conflicts.append('HOST_MISSING')
    if data.get('pcap'): conflicts.append('PCAP_NOT_INSPECTED')
    query = pick('webQuery', 'query', 'uri_query')
    if query and '?' not in path: path += '?' + query.lstrip('?')
    action_raw = pick('disposition', 'act', 'action')
    action = {'permit':'allowed','allow':'allowed','allowed':'allowed','block':'blocked','blocked':'blocked','deny':'blocked','drop':'blocked','reset':'blocked'}.get(action_raw.lower(), 'unknown')
    code = pick('resultCode', 'status', 'status_code', 'http_status')
    status = int(code) if code.isdigit() and 100 <= int(code) <= 599 else None
    headers = data.get('request_headers') or data.get('headers') or pick('Header-Value') or inner.get('HTTP Header', '')
    if not isinstance(headers, dict):
        headers = dict(line.split(':', 1) for line in str(headers).splitlines() if ':' in line)
    req_body = pick('request_body', 'body', 'http_body') or inner.get('HTTP Request Body', '')
    attack = classify(url=path, headers=headers, req_body=req_body) if path else classify()
    signature = pick('attack_name', 'evntDesc', 'ruleName', 'signature')
    category = attack.primary or signature_category(signature)
    # CVE/제품군 인식 — 요청/분석 엔진의 요청 전용 지문을 재사용(로컬, 무반출, 시도 식별이며 성공 판정 아님)
    cve_info = identify_cve(url=path, req_body=req_body, req_headers=headers, signature=signature)
    evidence = [f'{hit.where}: {hit.subtype or hit.attack_type} · {hit.evidence}' for hit in attack.candidates]
    if signature: evidence.append(f'장비 탐지명: {signature}')
    reasons = []
    bucket = 'information'
    if action == 'blocked': bucket = 'low'; reasons.append('DEVICE_BLOCKED')
    elif status in (404,410) and method in ('GET','HEAD') and '?' not in path and not category:
        bucket = 'low'; reasons.append('SIMPLE_NOT_FOUND')
    elif category or network_only or (status and 200 <= status < 300 and is_direct_file_probe(path)):
        bucket = 'review'; reasons.append('ATTACK_REVIEW')
    else: reasons.append('INSUFFICIENT_EVIDENCE')
    if conflicts: reasons.extend(conflicts)
    count = pick('occurrences','cnt','attack_count')
    count = int(count) if count.isdigit() else None
    timestamp = pick('_time','timestamp','attack_time','eventCreateTime')
    if not timestamp:
        m = re.search(r'\d{4}-\d{2}-\d{2}T[\d:.]+(?:Z|[+-]\d{2}:\d{2})',raw)
        timestamp = m[0] if m else ''
    window = 'unknown'
    try:
        dt = datetime.fromisoformat(timestamp.replace('Z','+00:00'))
        if dt.tzinfo: window = str(int(dt.timestamp()) // 900)
    except ValueError: pass
    response_origin = status_provenance(pick('response_source', 'status_origin', 'http_status_source'))
    return dict(id=hashlib.sha256(f'{line}:{raw}'.encode()).hexdigest()[:20], line=line,
                host=host, destination=destination, path=path, method=method or '불명', action=action,
                action_raw=action_raw, status=status, status_source=response_origin,
                device=device, event_name=event_name, response_result=pick('result_status', 'response_status'),
                occurrences=count, severity=pick('alertSev','attack_severity','severity'),
                signature=signature, attack_evidence=evidence,
                source=pick('src','src_ip','source_ip'), timestamp=timestamp, window=window,
                category=category, priority=bucket, reasons=reasons,
                cve=cve_info['cves'], products=cve_info['products'], cve_source=cve_info['source'],
                readiness='manual_confirmation_required', fields=data)


def is_csv_export(text):
    """Recognize a header by field names, independently of column order."""
    try:
        header=next(csv.reader(io.StringIO(text,newline='')))
    except (csv.Error,StopIteration):
        return False
    known={'_raw','_time','httpHost','dhost','url','uri','request_uri','requestMethod','webMethod'}
    return len(header)>1 and bool(set(header)&known)


def analyze(text):
    if len(text.encode('utf-8')) > MAX_BYTES: raise ValueError('입력은 2MB 이하로 제한됩니다.')
    text = text.lstrip("\ufeff")
    stripped = text.strip()
    if not stripped: raise ValueError('분석할 로그를 입력하세요.')
    records = []
    if stripped.startswith('['):
        data = json.loads(stripped)
        if not isinstance(data, list): raise ValueError('JSON 배열이 필요합니다.')
        records = [(i+1, x, json.dumps(x, ensure_ascii=False)) for i,x in enumerate(data)]
    elif is_csv_export(text):
        try:
            reader=csv.DictReader(io.StringIO(text,newline=''),strict=True)
            for row in reader:
                if None in row: raise ValueError('CSV 열 수가 헤더와 일치하지 않습니다.')
                records.append((reader.line_num,row,json.dumps(row,ensure_ascii=False)))
        except csv.Error as exc:
            raise ValueError(f'CSV 형식을 확인하세요: {exc}') from exc
    else:
        records = [(i+1,None,x) for i,x in enumerate(text.splitlines()) if x.strip()]
    if len(records)>MAX_RECORDS: raise ValueError('최대 10,000개 레코드를 분석할 수 있습니다.')
    events, errors, unsupported = [], [], []
    for line, data, raw in records:
        try:
            if len(raw)>100000: raise ValueError('단일 레코드는 100KB 이하이어야 합니다.')
            if data is None: data = json.loads(raw) if raw.lstrip().startswith('{') else fields(raw)
            if not isinstance(data, dict): raise ValueError('로그 객체가 필요합니다.')
            if data.get('_raw'):
                source=str(data['_raw'])
                embedded=json.loads(source) if source.lstrip().startswith('{') else fields(source)
                if not isinstance(embedded,dict): raise ValueError('원문 로그 객체가 필요합니다.')
                # Exported fields fill gaps; original device values remain authoritative.
                data={**{k:v for k,v in data.items() if k!='_raw' and v not in (None,'')},
                      **{k:v for k,v in embedded.items() if v not in (None,'')}}
            events.append(normalize(data,line,raw))
        except UnsupportedLog as e:
            unsupported.append(dict(line=line, reason=str(e)))
        except (ValueError,TypeError) as e:
            errors.append(dict(line=line, reason=str(e)[:200]))
    groups = defaultdict(list)
    for e in events: groups[(e['host'] or e.get('destination') or '(대상 불명)', e['window'] if e['window'] != 'unknown' else 'unknown:' + e['id'])].append(e)
    result = []
    for (host,window), items in groups.items():
        mixed = {x['action'] for x in items} >= {'allowed','blocked'}
        if mixed:
            for e in items:
                e['priority']='review'; e['reasons'].append('MIXED_ALLOWED_BLOCKED')
        result.append(dict(host=host, window=window, count=len(items), events=[e['id'] for e in items], mixed=mixed))
    output=refresh_attack_summary(dict(scan_analysis=summarize_campaigns(events),policy=POLICY, events=events, errors=errors, unsupported=unsupported, groups=result,
                summary=dict(records=len(records), parsed=len(events), errors=len(errors), unsupported=len(unsupported), groups=len(result),
                review=sum(e['priority']=='review' for e in events), information=sum(e['priority']=='information' for e in events), low=sum(e['priority']=='low' for e in events)),
                target_requests=0, persisted=False))
    output['statistics']=summarize_statistics(events)
    return refresh_screening(output)
