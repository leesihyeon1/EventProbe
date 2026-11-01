"""Bounded, local statistics over observed event records."""
import re
from collections import Counter, defaultdict
from core.classify import is_direct_file_probe


DEVICE_MARKERS = (
    ('WAF', r'\bwaf\b|imperva|incapsula|modsecurity|awswaf|cloudflare'),
    ('IPS', r'\bips\b|tippingpoint|intrusion.prevention'),
    ('IDS', r'\bids\b|snort|suricata|intrusion.detection'),
)


def device_kind(data, raw=''):
    explicit = ' '.join(str(data.get(k) or '') for k in (
        'device_type', 'deviceType', 'devtype', 'sensor_type', 'product',
        'deviceProduct', 'vendor', 'deviceVendor', 'log_source', 'sourcetype'))
    cef = raw.split('CEF:', 1)[1].split('|', 5)[:4] if 'CEF:' in raw else []
    probe = explicit + ' ' + ' '.join(cef)
    return next((kind for kind, pattern in DEVICE_MARKERS if re.search(pattern, probe, re.I)), '미확인')


def event_family(event):
    name = event.get('event_name', '') or ''
    path = event.get('path', '') or ''
    category = event.get('category', '') or ''
    has_vuln = bool(event.get('cve') or event.get('products'))
    if is_direct_file_probe(path) or re.search(
            r'file.access|file.probe|\.env|\.git|directory.(scan|list|brows)|path.scan|recon|'
            r'information.disclosure|정보.?수집|파일.*(스캔|탐색|노출)', name, re.I):
        return '정보 수집성'
    # 뚜렷한 네트워크/볼류메트릭 공격 먼저(이름 기준) — 이후 이름/CVE 로 앱·웹 분류.
    if re.search(r'port.?scan|network.?scan|syn.?scan|\bdos\b|ddos|flood|amplification|'
                 r'brute.?force|network.?attack|네트워크|포트.*스캔|무차별', name, re.I):
        return '네트워크 공격'
    if category in ('sqli', 'xss', 'lfi', 'ssrf', 'nosql', 'xxe', 'redirect') or re.search(
            r'sql.?injection|\bxss\b|cross.?site|\bssrf\b|\blfi\b|\brfi\b|file.?inclusion|'
            r'traversal|directory.?climb|\bxxe\b|open.?redirect|path.?confusion|web.?attack|웹.*공격', name, re.I):
        return '웹 공격'
    if category in ('cmdi', 'ssti', 'authbypass', 'deserial', 'upload') or re.search(
            r'\brce\b|code.?execution|command.?(execution|injection)|remote.?code|arbitrary.?(file|command|code)|'
            r'deserial|\bjndi\b|\bognl\b|\bspel\b|log4j|log4shell|shellshock|proxylogon|proxyshell|'
            r'buffer.?overflow|overflow|\bexploit\b|injection|application.?attack|앱.*공격|코드.?실행|원격.?실행', name, re.I):
        return '애플리케이션 공격'
    # 이름으로는 못 가렸지만 특정 CVE·제품 익스플로잇이면 앱 공격으로 분류해 '미분류'를 줄인다.
    if has_vuln:
        return '애플리케이션 공격'
    if not path and event.get('device') in ('IPS', 'IDS'):
        return '네트워크 공격'
    return '기타/미분류'


def display_name(name):
    """장비가 집계한 비식별 탐지명(예: Imperva 'Multiple signatures from <IP>')을 읽기 쉬운
    한국어로 정규화한다. 그 외는 원본 유지."""
    name = (name or '').strip()
    m = re.match(r'(?i)^multiple\s+signatures\s+from\s+(\S+)', name)
    if m:
        return f'다수 시그니처(장비 집계) · 출발지 {m.group(1)}'
    return name or '탐지명 없음'


def top_items(counter, limit=8):
    ranked = sorted(counter.items(), key=lambda pair: (-pair[1], pair[0]))
    shown = [dict(label=key, count=count) for key, count in ranked[:limit]]
    if len(ranked) > limit:
        shown.append(dict(label='기타', count=sum(count for _, count in ranked[limit:])))
    return shown


def summarize_statistics(events):
    names = Counter()
    families = Counter()
    targets = Counter()
    cve_detail = defaultdict(lambda: dict(count=0, actions=Counter(), targets=set()))
    products = defaultdict(lambda: dict(records=0, actions=Counter(), cves=set(), targets=set()))
    cve_records = 0
    cve_open_records = 0   # CVE/제품 식별 이벤트 중 차단되지 않은(허용·불명) 건 — 우선 조사 대상
    devices = defaultdict(lambda: dict(actions=Counter(), statuses=Counter(), results=Counter(), records=0, status_eligible=0))
    source_targets = defaultdict(set)
    target_sources = defaultdict(set)
    source_families = defaultdict(set)
    for event in events:
        names[display_name(event.get('event_name'))] += 1
        family = event_family(event)
        event['family'] = family
        families[family] += 1
        target = event.get('host') or event.get('destination') or '대상 불명'
        targets[target] += 1
        event_cves = event.get('cve') or []
        event_products = event.get('products') or []
        act = event.get('action') or 'unknown'
        if event_cves or event_products:
            cve_records += 1
            if act != 'blocked':
                cve_open_records += 1
        for cve in event_cves:
            c = cve_detail[cve]
            c['count'] += 1
            c['actions'][act] += 1
            c['targets'].add(target)
        for product in event_products:
            p = products[product]
            p['records'] += 1
            p['actions'][act] += 1
            p['cves'].update(event_cves)
            p['targets'].add(target)
        kind = event.get('device') or '미확인'
        d = devices[kind]
        d['records'] += 1
        d['actions'][event.get('action') or 'unknown'] += 1
        if kind in ('WAF', 'IDS'):
            d['status_eligible'] += 1
            d['statuses'][str(event['status']) if event.get('status') is not None else 'HTTP 응답 미기록'] += 1
            if event.get('response_result'):
                d['results'][str(event['response_result'])] += 1
        source = event.get('source')
        if source:
            source_targets[source].add(target)
            target_sources[target].add(source)
            source_families[source].add(family)
    device_rows = []
    for kind in ('IPS', 'WAF', 'IDS', '미확인'):
        if kind not in devices: continue
        d = devices[kind]
        device_rows.append(dict(name=kind, records=d['records'], actions=dict(d['actions']),
                                http_status=top_items(d['statuses'], 6), response_result=top_items(d['results'], 6),
                                status_eligible=d['status_eligible']))
    signals = []
    for source, target_set in source_targets.items():
        if len(target_set) >= 3:
            signals.append(dict(type='multi_target_source', label=f'한 출발지가 {len(target_set)}개 대상을 관측', source=source, count=len(target_set)))
    for target, source_set in target_sources.items():
        if len(source_set) >= 3:
            signals.append(dict(type='multi_source_target', label=f'한 대상에 {len(source_set)}개 출발지 관측', target=target, count=len(source_set)))
    for source, family_set in source_families.items():
        meaningful = family_set - {'기타/미분류'}
        if len(meaningful) >= 3:
            signals.append(dict(type='multi_family_source', label=f'한 출발지에서 {len(meaningful)}개 이벤트 계열 관측', source=source, count=len(meaningful)))
    signals.sort(key=lambda signal: (-signal['count'], signal['type'], signal.get('source', signal.get('target', ''))))
    def _open(actions):   # 차단되지 않은(허용+불명) = 우선 조사 대상
        return actions.get('allowed', 0) + actions.get('unknown', 0)
    product_rows = []
    for name, d in sorted(products.items(), key=lambda kv: (-_open(kv[1]['actions']), -kv[1]['records'], kv[0]))[:10]:
        product_rows.append(dict(name=name, records=d['records'], actions=dict(d['actions']), open=_open(d['actions']),
                                 cves=sorted(d['cves'])[:8], targets=len(d['targets'])))
    # CVE별: 빈도가 아니라 '미차단(허용·불명)' 우선으로 정렬해 통과한 시도를 먼저 보인다.
    cve_ranked = sorted(cve_detail.items(), key=lambda kv: (-_open(kv[1]['actions']), -kv[1]['count'], kv[0]))
    cve_rows = [dict(label=k, count=v['count'], blocked=v['actions'].get('blocked', 0),
                     open=_open(v['actions']), targets=len(v['targets'])) for k, v in cve_ranked[:10]]
    if len(cve_ranked) > 10:
        rest = [v for _, v in cve_ranked[10:]]
        cve_rows.append(dict(label='기타', count=sum(v['count'] for v in rest),
                             blocked=sum(v['actions'].get('blocked', 0) for v in rest),
                             open=sum(_open(v['actions']) for v in rest),
                             targets=len({t for v in rest for t in v['targets']})))
    return dict(total=len(events), event_names=top_items(names, 10), families=top_items(families, 5),
                devices=device_rows, targets=top_items(targets, 10), correlations=signals[:5],
                cves=cve_rows, products=product_rows, cve_records=cve_records, cve_open_records=cve_open_records,
                note='각 수치는 파싱된 로그 레코드 수입니다. 장비별 중복 관측과 발생 횟수 필드는 별도이며, HTTP 응답은 장비 기록값입니다. 미확인 장비를 추정해 IPS/WAF/IDS에 넣지 않습니다.')
