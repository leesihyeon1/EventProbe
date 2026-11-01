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
    name = event.get('event_name', '')
    path = event.get('path', '')
    category = event.get('category', '')
    if is_direct_file_probe(path) or re.search(r'file.access|file.probe|\.env|\.git|directory.scan|path.scan|파일.*(스캔|탐색)', name, re.I):
        return '정보 수집성'
    if not path and event.get('device') in ('IPS', 'IDS'):
        return '네트워크 공격'
    if re.search(r'port.scan|network.scan|syn.scan|dos|ddos|flood|network.attack|네트워크|포트.*스캔', name, re.I):
        return '네트워크 공격'
    if category in ('cmdi', 'ssti', 'authbypass', 'deserial', 'upload') or re.search(r'\brce\b|code.execution|application.attack|앱.*공격', name, re.I):
        return '애플리케이션 공격'
    if category in ('sqli', 'xss', 'lfi', 'ssrf', 'nosql', 'xxe', 'redirect', 'authbypass') or re.search(r'sql.injection|\bxss\b|web.attack|웹.*공격', name, re.I):
        return '웹 공격'
    return '기타/미분류'


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
    devices = defaultdict(lambda: dict(actions=Counter(), statuses=Counter(), results=Counter(), records=0, status_eligible=0))
    source_targets = defaultdict(set)
    target_sources = defaultdict(set)
    source_families = defaultdict(set)
    for event in events:
        names[event.get('event_name') or '탐지명 없음'] += 1
        family = event_family(event)
        event['family'] = family
        families[family] += 1
        target = event.get('host') or event.get('destination') or '대상 불명'
        targets[target] += 1
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
    return dict(total=len(events), event_names=top_items(names, 10), families=top_items(families, 5),
                devices=device_rows, targets=top_items(targets, 10), correlations=signals[:5],
                note='각 수치는 파싱된 로그 레코드 수입니다. 장비별 중복 관측과 발생 횟수 필드는 별도이며, HTTP 응답은 장비 기록값입니다. 미확인 장비를 추정해 IPS/WAF/IDS에 넣지 않습니다.')
