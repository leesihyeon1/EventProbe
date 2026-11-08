"""Stateless SIEM triage. No persistence, AI calls or target requests."""
import base64
import csv
import hashlib
import io
import json
import os
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

# 입력 한도는 환경변수로 조절한다(코드 수정 없이 배포 단위로 상향 가능). 기본 20MB/10만건.
MAX_BYTES = int(os.getenv('TRIAGE_MAX_BYTES') or 20_000_000)
MAX_RECORDS = int(os.getenv('TRIAGE_MAX_RECORDS') or 100_000)
MAX_MB = MAX_BYTES // 1_000_000
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


_IP_EMPTY = {'', 'N/A', '---', 'UNKNOWN', '0.0.0.0', '::', '0:0:0:0:0:0:0:0'}


def _ip_token(value):
    """Return a bare IP from one token (strips :port, brackets, zone), else ''.

    Device-neutral: used to pull the real client out of X-Forwarded-For chains
    and to drop placeholders like N/A / 0.0.0.0 that otherwise split one source
    into many distinct values.
    """
    value = str(value).strip().strip('"').strip().strip('[]')
    if value.upper() in _IP_EMPTY:
        return ''
    m = re.match(r'(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?(?:\b|$)', value)
    if m and all(int(o) < 256 for o in m[1].split('.')):
        return m[1] if m[1] not in _IP_EMPTY else ''
    v = value.split('%')[0]  # IPv6 zone id
    if v.count(':') >= 2 and re.fullmatch(r'[0-9A-Fa-f:]+', v):
        return '' if v in _IP_EMPTY else v
    return ''


def _xff_left(text):
    """Leftmost valid IP of an X-Forwarded-For value (the originating client)."""
    for token in str(text).split(','):
        ip = _ip_token(token)
        if ip:
            return ip
    return ''


def _xff_from_headers(text):
    """Pull the X-Forwarded-For client out of a raw HTTP header/request blob."""
    m = re.search(r'x[-_ ]?forwarded[-_ ]?for\s*[:=]\s*([^\r\n"]+)', str(text), re.I)
    return _xff_left(m[1]) if m else ''


def _b64_decode(value):
    """Best-effort base64 decode of a packet-data blob (url-safe/padding tolerant)."""
    v = re.sub(r'[^A-Za-z0-9+/=_-]', '', str(value))
    if not 24 <= len(v) <= 200000:
        return ''
    v = v.replace('-', '+').replace('_', '/').rstrip('=')
    try:
        return base64.b64decode(v + '=' * (-len(v) % 4)).decode('latin1')
    except ValueError:  # binascii.Error subclasses ValueError
        return ''


def client_source(pick):
    """Originating client IP across mixed device formats.

    Proxy/LB-fronted sensors (e.g. CEF behind envoy/GCP) record the connection
    `src` as the proxy/load-balancer and carry the true client in X-Forwarded-For.
    When XFF is present — as a field, in the raw request headers, or inside the
    base64 packet capture — its leftmost entry is the origin client and wins over
    the connection `src`. Otherwise fall back to the connection source, keeping a
    hostname source verbatim when it is not an IP.
    """
    # Device-resolved real client (pre-NAT / CIM client) — authoritative, not spoofable.
    for key in ('true-client-ip', 'true_client_ip', 'x-real-ip', 'x_real_ip',
                'sourceTranslatedAddress', 'source_translated_address', 'client_ip'):
        ip = _ip_token(pick(key))
        if ip:
            return ip
    ip = _xff_left(pick('xff', 'x_forwarded_for', 'x-forwarded-for'))
    if ip:
        return ip
    for key in ('Header_Value', 'Header-Value', 'http_header', 'headers_raw', 'request_headers', 'headers'):
        ip = _xff_from_headers(pick(key))
        if ip:
            return ip
    for key in ('TrendMicroDsPacketData', 'Packet_Trace', 'pcapdata'):
        ip = _xff_from_headers(_b64_decode(pick(key)))
        if ip:
            return ip
    for key in ('src', 'src_ip', 'source_ip'):
        raw = pick(key)
        if not raw:
            continue
        ip = _ip_token(raw)
        if ip:
            return ip
        if not re.search(r'\d{1,3}(?:\.\d{1,3}){3}', raw):  # hostname source, keep as-is
            return raw.strip().strip('"')
    return ''


def _norm_host(host):
    """Drop the implied HTTP/HTTPS default port so one asset is not split by :80/:443.

    Non-default ports (e.g. :8080) and bare IPv6 literals are left untouched.
    """
    host = str(host).strip().strip('"')
    m = re.fullmatch(r'(\[[0-9A-Fa-f:]+\]|[^:]+):(80|443)', host)
    return m[1] if m else host


def normalize(data, line, raw):
    pick = lambda *keys: next((str(data[k]) for k in keys if data.get(k) not in (None, '', 'N/A', '---')), '')
    inner = {}
    for part in pick('layer_7_data').split(';;;'):
        if '==' in part:
            k, v = part.split('==', 1)
            inner[k.strip().strip('"')] = v.strip().strip('"')
    destination = pick('dst', 'dst_ip', 'destination_ip', 'dest_ip', 'destinationAddress')
    device = device_kind(data, raw)
    # SIEM host is commonly the collector/sensor, not the HTTP destination.
    host = pick('httpHost', 'http_hostname', 'dhost', 'dest_host') or inner.get('HTTP Host', '')
    if not host and device not in ('IDS', 'IPS'):
        host = pick('host')
    path = pick('url', 'uri', 'request', 'request_uri') or inner.get('HTTP URI', '')
    method = (pick('requestMethod', 'webMethod', 'method') or inner.get('HTTP Request Method', '')).upper()
    event_name = pick('evtname', 'eventName', 'event_name', 'attack_name', 'evntDesc', 'ruleName', 'signature')
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
    status = None
    for code in [pick(k) for k in ('resultCode', 'status', 'status_code', 'http_status', 'response_code', 'http_response_code')] + [inner.get('HTTP Return Code', ''), inner.get('HTTP Response Code', '')]:
        match = re.fullmatch(r'(?:HTTP/\d(?:\.\d)?\s+)?([1-5]\d{2})(?:\s+[^\r\n]*)?', code.strip())
        if match:
            status = int(match[1])
            break
    headers = data.get('request_headers') or data.get('headers') or pick('Header-Value') or inner.get('HTTP Header', '')
    if not isinstance(headers, dict):
        headers = dict(line.split(':', 1) for line in str(headers).splitlines() if ':' in line)
    req_body = pick('request_body', 'body', 'http_body') or inner.get('HTTP Request Body', '')
    attack = classify(url=path, headers=headers, req_body=req_body) if path else classify()
    signature = pick('attack_name', 'evntDesc', 'ruleName', 'signature')
    category = attack.primary or signature_category(signature)
    # CVE/제품군 인식 — 요청/분석 엔진의 요청 전용 지문을 재사용(로컬, 무반출, 시도 식별이며 성공 판정 아님)
    cve_info = identify_cve(url=path, req_body=req_body, req_headers=headers, signature=' '.join(dict.fromkeys(filter(None, [event_name, signature]))))
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
                host=_norm_host(host), destination=destination, path=path, method=method or '불명', action=action,
                action_raw=action_raw, status=status, status_source=response_origin,
                device=device, event_name=event_name, response_result=pick('result_status', 'response_status'),
                occurrences=count, severity=pick('alertSev','attack_severity','severity'),
                signature=signature, attack_evidence=evidence,
                source=client_source(pick), timestamp=timestamp, window=window,
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
    if len(text.encode('utf-8')) > MAX_BYTES: raise ValueError(f'입력은 {MAX_MB}MB 이하로 제한됩니다.')
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
    if len(records)>MAX_RECORDS: raise ValueError(f'최대 {MAX_RECORDS:,}개 레코드를 분석할 수 있습니다.')
    events, errors, unsupported = [], [], []
    excluded_detection_count = 0
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
            # Operator exclusion: UDS_*_Block detection names never enter
            # statistics, search/detail lists or verification handoff.
            detection = next((str(data[k]).strip() for k in
                              ('evtname', 'eventName', 'event_name', 'attack_name', 'evntDesc', 'ruleName', 'signature')
                              if data.get(k) not in (None, '', 'N/A', '---')), '')
            if re.fullmatch(r'UDS_.*_Block', detection, re.I):
                excluded_detection_count += 1
                continue
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
                summary=dict(records=len(records), excluded_detections=excluded_detection_count, parsed=len(events), errors=len(errors), unsupported=len(unsupported), groups=len(result),
                review=sum(e['priority']=='review' for e in events), information=sum(e['priority']=='information' for e in events), low=sum(e['priority']=='low' for e in events)),
                target_requests=0, persisted=False))
    output['statistics']=summarize_statistics(events)
    return refresh_screening(output)
